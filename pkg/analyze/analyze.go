// Package analyze provides a Hashcracky-style "analyzer" mode for the
// Password Transformation Tool (ptt).
package analyze

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/hashcracky/ptt/pkg/format"
	"github.com/hashcracky/ptt/pkg/mask"
	"github.com/hashcracky/ptt/pkg/rule"
	"github.com/hashcracky/ptt/pkg/utils"
)

// analyzeSummary bundles everything returned by the analyzer.
type analyzeSummary struct {
	TopTokens       []string
	CategoryCounts  map[string]int
	CharComposition map[string]int
	FullMasks       []string
	PartialMasks    []string
	Rules           []string
}

// Analyze performs a analysis of the provided plaintext lines.
//
// Args:
//
//	lines: []string - One plaintext entry per line.
//
// Returns:
//
//	analyzeSummary - Computed information.
func Analyze(lines []string) analyzeSummary {
	var (
		categories   map[string]int
		comp         map[string]int
		fullMasks    []string
		partialMasks []string
		rules        []string
		topNonBlock  []string
	)

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		categories = classifyTokens(lines)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		comp = characterComposition(lines)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		fullMasks = generateFullMasks(lines)
	}()

	tokens := boundarySplitTokens(lines, "ultdb")
	freq := countFrequency(tokens)

	topNonBlock = getTopN(freq, 5000)
	topTokens := getTopN(freq, 2000)

	ngramFreq := generateNGramFrequency(tokens, 1, 3)
	topNgrams := getTopN(ngramFreq, 2000)

	joined := append(
		append(make([]string, 0, len(topTokens)+len(topNgrams)), topTokens...),
		topNgrams...,
	)

	wg.Add(1)
	go func() {
		defer wg.Done()
		rules = generateRulesFromTokens(joined)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		partialMasks = generatePartialMasks(lines, topNonBlock)
	}()

	wg.Wait()

	return analyzeSummary{
		TopTokens:       topNonBlock,
		CategoryCounts:  categories,
		CharComposition: comp,
		FullMasks:       fullMasks,
		PartialMasks:    partialMasks,
		Rules:           rules,
	}
}

// countFrequency tallies occurrences of every token.
//
// Args:
//
//	tokens: []string - Input tokens.
//
// Returns:
//
//	map[string]int - Frequency table.
func countFrequency(tokens []string) map[string]int {
	m := make(map[string]int, len(tokens))
	for _, t := range tokens {
		m[t]++
	}
	return m
}

// isNumericOnly reports whether s consists solely of decimal digits.
//
// Args:
//
//	s: string - Candidate.
//
// Returns:
//
//	bool - True if only digits are present.
func isNumericOnly(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !utilsIsDigit(r) {
			return false
		}
	}
	return true
}

// getTopN returns up to n most-frequent tokens, skipping numeric-only tokens.
//
// Args:
//
//	freq: map[string]int - Token counts.
//	n:   int             - Maximum length of result slice.
//
// Returns:
//
//	[]string - Top tokens ordered strictly by descending frequency.
func getTopN(freq map[string]int, n int) []string {
	type kv struct {
		k string
		v int
	}

	var list []kv
	for k, v := range freq {
		list = append(list, kv{k, v})
	}

	sort.SliceStable(list, func(i, j int) bool { return list[i].v > list[j].v })

	out := make([]string, 0, n)

	for _, e := range list {
		if isNumericOnly(e.k) {
			continue
		}

		out = append(out, e.k)
		if len(out) == n {
			break
		}
	}
	return out
}

// classifyTokens puts each token into property buckets.
//
// Args:
//
//	tokens: []string - Input tokens.
//
// Returns:
//
//	map[string]int - Counts per bucket.
func classifyTokens(tokens []string) map[string]int {
	counts := map[string]int{}
	for _, t := range tokens {
		for _, c := range format.StatClassifyToken(t) {
			counts[c]++
		}
	}
	return counts
}

// characterComposition counts rune classes across the token set.
//
// Args:
//
//	tokens: []string - Input tokens.
//
// Returns:
//
//	map[string]int - Composition counts.
func characterComposition(tokens []string) map[string]int {
	var lower, upper, digit, special, multibyte int
	for _, t := range tokens {
		for _, r := range t {
			switch {
			case r >= '0' && r <= '9':
				digit++
			case r >= 'a' && r <= 'z':
				lower++
			case r >= 'A' && r <= 'Z':
				upper++
			case r > 127:
				multibyte++
			case !utilsIsSpace(r):
				special++
			}
		}
	}
	return map[string]int{
		"lower":     lower,
		"upper":     upper,
		"digits":    digit,
		"special":   special,
		"multibyte": multibyte,
	}
}

// generateFullMasks creates fully masked versions of input lines with
// deduplication, frequency sorted.
//
// Args:
//
//	lines: []string - Input plaintext lines.
//
// Returns:
//
//	[]string - Deduplicated full masks, frequency sorted.
func generateFullMasks(lines []string) []string {
	replacements := mask.ConstructReplacements("uldbs")
	replacer := strings.NewReplacer(replacements...)

	freq := make(map[string]int)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		masked := replacer.Replace(line)
		if !utilsCheckASCIIString(masked) {
			masked = mask.ConvertMultiByteMask(masked)
		}

		freq[masked]++
	}

	return sortByFrequency(freq)
}

// generatePartialMasks creates masks that retain top tokens but mask everything
// else. Only passes the tokens actually present in each line to the masking
// function, avoiding a full scan of the token set.
//
// Args:
//
//	lines:     []string - Input plaintext lines.
//	topTokens: []string - Tokens to retain (not mask).
//
// Returns:
//
//	[]string - Deduplicated partial masks, frequency sorted.
func generatePartialMasks(lines []string, topTokens []string) []string {
	replacements := mask.ConstructReplacements("uldbs")
	replacer := strings.NewReplacer(replacements...)

	tokenSet := make(map[string]struct{}, len(topTokens))
	for _, t := range topTokens {
		tokenSet[strings.ToLower(strings.TrimSpace(t))] = struct{}{}
	}

	freq := make(map[string]int)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		lineTokens := boundarySplitTokens([]string{line}, "ultdb")

		lineMatched := make(map[string]struct{})
		for _, lt := range lineTokens {
			if _, ok := tokenSet[lt]; ok {
				lineMatched[lt] = struct{}{}
			}
		}

		if len(lineMatched) == 0 {
			continue
		}

		masked := maskLineRetainingTokens(line, lineMatched, replacer)
		if masked != "" && !isFullMask(masked) {
			freq[masked]++
		}
	}

	return sortByFrequency(freq)
}

// maskLineRetainingTokens masks a line but preserves tokens from tokenSet.
//
// Args:
//
//	line:     string - Input line to mask.
//	tokenSet: map[string]struct{} - Set of lowercase tokens to preserve.
//	replacer: *strings.Replacer - Mask replacer for non-token characters.
//
// Returns:
//
//	string - Partially masked line.
func maskLineRetainingTokens(line string, tokenSet map[string]struct{}, replacer *strings.Replacer) string {
	type match struct {
		token string
		start int
		end   int
	}

	var matches []match
	lineLower := strings.ToLower(line)

	for token := range tokenSet {
		idx := 0
		for {
			pos := strings.Index(lineLower[idx:], token)
			if pos == -1 {
				break
			}

			actualPos := idx + pos
			matches = append(matches, match{
				token: line[actualPos : actualPos+len(token)],
				start: actualPos,
				end:   actualPos + len(token),
			})

			idx = actualPos + len(token)
		}
	}

	if len(matches) == 0 {
		return ""
	}

	sort.Slice(matches, func(i, j int) bool {
		return matches[i].start < matches[j].start
	})

	var filtered []match
	for _, m := range matches {
		overlap := false
		for _, f := range filtered {
			if (m.start >= f.start && m.start < f.end) ||
				(m.end > f.start && m.end <= f.end) ||
				(m.start <= f.start && m.end >= f.end) {
				overlap = true
				break
			}
		}
		if !overlap {
			filtered = append(filtered, m)
		}
	}

	var result strings.Builder
	lastEnd := 0

	for _, m := range filtered {
		if m.start > lastEnd {
			before := line[lastEnd:m.start]
			masked := replacer.Replace(before)
			if !utilsCheckASCIIString(masked) {
				masked = mask.ConvertMultiByteMask(masked)
			}
			result.WriteString(masked)
		}

		result.WriteString(m.token)
		lastEnd = m.end
	}

	if lastEnd < len(line) {
		remaining := line[lastEnd:]
		masked := replacer.Replace(remaining)
		if !utilsCheckASCIIString(masked) {
			masked = mask.ConvertMultiByteMask(masked)
		}
		result.WriteString(masked)
	}

	return result.String()
}

// sortByFrequency converts a frequency map to a sorted slice (descending).
//
// Args:
//
//	freq: map[string]int - Frequency table.
//
// Returns:
//
//	[]string - Keys sorted by descending frequency.
func sortByFrequency(freq map[string]int) []string {
	type kv struct {
		k string
		v int
	}

	var items []kv
	for k, v := range freq {
		items = append(items, kv{k, v})
	}

	sort.SliceStable(items, func(i, j int) bool {
		return items[i].v > items[j].v
	})

	result := make([]string, len(items))
	for i, item := range items {
		result[i] = item.k
	}

	return result
}

// isFullMask reports whether s consists entirely of Hashcat mask placeholders
// (e.g. ?l, ?u, ?d, ?s, ?b) with no retained literal text. Such entries are
// redundant in partial mask output because they duplicate the full mask file.
//
// Args:
//
//	s: string - Candidate masked string.
//
// Returns:
//
//	bool - True if s contains only mask placeholders and no plaintext.
func isFullMask(s string) bool {
	if s == "" {
		return true
	}
	i := 0
	for i < len(s) {
		if s[i] == '?' && i+1 < len(s) {
			switch s[i+1] {
			case 'l', 'u', 'd', 's', 'b', 'a', 'h', 'H':
				i += 2
				continue
			}
		}
		return false
	}
	return true
}

// generateRulesFromTokens builds a curated set of Hashcat rules from a set of
// input strings (tokens/n-grams).
//
// Args:
//
//	items: []string - Arbitrary strings (tokens/n-grams).
//
// Returns:
//
//	[]string - Unique, sorted Hashcat rules.
func generateRulesFromTokens(items []string) []string {
	freq := map[string]int{}
	for _, m := range items {
		freq[m] = 1
	}

	ruleMap := map[string]int{}
	mergeRule(ruleMap, rule.AppendRules(freq, "rule-append", false, false))
	mergeRule(ruleMap, rule.PrependRules(freq, "rule-prepend", false, false))
	mergeRule(ruleMap, rule.InsertRules(freq, "1", "2", false, false))
	mergeRule(ruleMap, rule.OverwriteRules(freq, "0", "2", false, false))
	mergeRule(ruleMap, rule.PrependRules(freq, "rule-prepend-remove", false, false))
	mergeRule(ruleMap, rule.PrependRules(freq, "rule-prepend-toggle", false, false))
	mergeRule(ruleMap, rule.ToggleRules(freq, "0", "0", false, false))

	var out []string
	for k := range ruleMap {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// merge adds values from src into dst.
//
// Args:
//
//	dst: map[string]int - Destination map.
//	src: map[string]int - Source map.
//
// Returns:
//
//	(none) - dst is modified in-place.
func mergeRule(dst map[string]int, src map[string]int) {
	for k, v := range src {
		dst[k] += v
	}
}

// boundarySplitTokens splits each input line into lowercase token boundaries
// using the provided character mask. Tokens shorter than three characters are
// discarded.
//
// Args:
//
//	lines: []string - Input lines.
//	mask:  string   - Character classes to keep ('u', 'l', 'd', 't', 'b').
//
// Returns:
//
//	[]string - Lowercased tokens of length >= 3.
func boundarySplitTokens(lines []string, maskStr string) []string {
	var tokens []string
	keep := func(rt rune) bool { return strings.ContainsRune(maskStr, rt) }

	for _, line := range lines {
		var last rune
		var b strings.Builder

		for _, r := range line {
			var rt rune
			switch {
			case r >= 'a' && r <= 'z':
				rt = 'l'
			case r >= 'A' && r <= 'Z':
				rt = 'u'
			case r >= '0' && r <= '9':
				rt = 'd'
			case isSpecial(r):
				rt = 's'
			default:
				rt = 'b'
			}

			cont := last == 0 || rt == last ||
				(last == 'u' && rt == 'l' && strings.ContainsRune(maskStr, 't'))

			if !cont && b.Len() > 0 {
				if t := strings.ToLower(b.String()); len(t) >= 3 {
					tokens = append(tokens, t)
				}
				b.Reset()
			}

			if keep(rt) {
				b.WriteRune(r)
				last = rt
			} else {
				last = 0
			}
		}

		if b.Len() > 0 {
			if t := strings.ToLower(b.String()); len(t) >= 3 {
				tokens = append(tokens, t)
			}
		}
	}

	return tokens
}

// generateNGramFrequency builds n-gram frequencies from the given tokens.
//
// Args:
//
//	input:          []string - Source strings (tokens).
//	wordRangeStart: int      - Minimum n-gram size.
//	wordRangeEnd:   int      - Maximum n-gram size.
//
// Returns:
//
//	map[string]int - Frequency map of qualifying n-grams.
func generateNGramFrequency(input []string, wordRangeStart, wordRangeEnd int) map[string]int {
	freq := make(map[string]int)

	for _, s := range input {
		for n := wordRangeStart; n <= wordRangeEnd; n++ {
			for _, g := range utils.GenerateNGrams(s, n) {
				g = strings.TrimSpace(strings.Trim(g, ","))
				if g != "" {
					freq[g]++
				}
			}
		}
	}

	return freq
}

// isSpecial reports whether the rune is a non-alphanumeric, non-space character
//
// Args:
//
//	r: rune - Character to test.
//
// Returns:
//
//	bool - True if the character is a special character.
func isSpecial(r rune) bool {
	return !utilsIsLetter(r) && !utilsIsDigit(r) && !utilsIsSpace(r)
}

// utilsIsLetter reports whether r is an ASCII letter.
func utilsIsLetter(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

// utilsIsDigit reports whether r is an ASCII digit.
func utilsIsDigit(r rune) bool {
	return r >= '0' && r <= '9'
}

// utilsIsSpace reports whether r is an ASCII whitespace character.
func utilsIsSpace(r rune) bool {
	return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\v' || r == '\f'
}

// utilsCheckASCIIString reports whether s contains only ASCII characters.
func utilsCheckASCIIString(s string) bool {
	for _, r := range s {
		if r > 127 {
			return false
		}
	}
	return true
}

// PrintSummary renders the analyzer summary to standard output. When verbose is
// true a fuller human-readable report (categories, composition and a sample of
// the generated artifacts) is printed; otherwise only the top tokens and a
// short artifact inventory are emitted.
//
// Args:
//
//	s       analyzeSummary - The analysis results.
//	linesIn  int           - Number of input lines analyzed.
//	verbose  bool          - Whether to emit the fuller report.
//
// Returns:
//
//	(none)
func PrintSummary(s analyzeSummary, linesIn int, verbose bool) {
	fmt.Fprintf(os.Stderr, "[*] Analysis of %d input line(s). [%d unique tokens, %d full masks, %d partial masks, %d rules]\n",
		linesIn, len(s.TopTokens), len(s.FullMasks), len(s.PartialMasks), len(s.Rules))

	if verbose {
		fmt.Println()
		fmt.Println("=== Token Category Counts ===")
		keys := make([]string, 0, len(s.CategoryCounts))
		for k := range s.CategoryCounts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("  %-30s %d\n", k, s.CategoryCounts[k])
		}

		fmt.Println()
		fmt.Println("=== Character Composition ===")
		compKeys := []string{"lower", "upper", "digits", "special", "multibyte"}
		for _, k := range compKeys {
			fmt.Printf("  %-10s %d\n", k, s.CharComposition[k])
		}

		fmt.Println()
		fmt.Printf("=== Top Tokens (first 25 of %d) ===\n", len(s.TopTokens))
		for i, t := range s.TopTokens {
			if i >= 25 {
				break
			}
			fmt.Printf("  %s\n", t)
		}

		fmt.Println()
		fmt.Printf("=== Full Masks (first 25 of %d) ===\n", len(s.FullMasks))
		for i, m := range s.FullMasks {
			if i >= 25 {
				break
			}
			fmt.Printf("  %s\n", m)
		}

		fmt.Println()
		fmt.Printf("=== Partial Masks (first 25 of %d) ===\n", len(s.PartialMasks))
		for i, m := range s.PartialMasks {
			if i >= 25 {
				break
			}
			fmt.Printf("  %s\n", m)
		}

		fmt.Println()
		fmt.Printf("=== Rules (first 25 of %d) ===\n", len(s.Rules))
		for i, r := range s.Rules {
			if i >= 25 {
				break
			}
			fmt.Printf("  %s\n", r)
		}
		return
	}

	// Concise output.
	fmt.Println("=== Top Tokens ===")
	for _, t := range s.TopTokens {
		fmt.Printf("  %s\n", t)
	}
	fmt.Println()
	fmt.Println("=== Categories ===")
	ck := make([]string, 0, len(s.CategoryCounts))
	for k := range s.CategoryCounts {
		ck = append(ck, k)
	}
	sort.Strings(ck)
	for _, k := range ck {
		fmt.Printf("  %s: %d\n", k, s.CategoryCounts[k])
	}
	fmt.Println()
	fmt.Println("=== Composition ===")
	for _, k := range []string{"lower", "upper", "digits", "special", "multibyte"} {
		fmt.Printf("  %s: %d\n", k, s.CharComposition[k])
	}
	fmt.Println()
	fmt.Printf("=== Artifacts: %d full masks, %d partial masks, %d rules ===\n",
		len(s.FullMasks), len(s.PartialMasks), len(s.Rules))
}

// writeArtifactLines joins the provided lines with newlines, adds a trailing
// newline, and writes them to the given file path. It also creates the file's
// parent directory if it does not already exist.
//
// Args:
//
//	dir    string  - The output directory the file will be written to.
//	name   string  - The base file name (without extension) to write.
//	lines  []string - The lines to persist.
//
// Returns:
//
//	error - Non-nil on I/O failure.
func writeArtifactLines(dir, name string, lines []string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create output directory %q: %s", dir, err)
	}

	var body strings.Builder
	for _, line := range lines {
		body.WriteString(line)
		body.WriteString("\n")
	}

	filePath := filepath.Join(dir, name)
	if err := os.WriteFile(filePath, []byte(body.String()), 0o644); err != nil {
		return fmt.Errorf("failed to write %q: %s", filePath, err)
	}
	return nil
}

// WriteArtifacts persists the full masks, partial masks, and rules to files in
// the provided output directory so the generated artifacts are accessible
// outside the tool (for example, to load directly into Hashcat). Files that are
// empty are not written. On success it returns the absolute paths of the files
// that were created.
//
// Args:
//
//	s     analyzeSummary - The analysis results.
//	dir  string          - The output directory to write the artifacts to.
//
// Returns:
//
//	[]string - Paths of the artifacts that were written.
//	error    - Non-nil on I/O failure.
func WriteArtifacts(s analyzeSummary, dir string) ([]string, error) {
	var written []string

	if err := writeArtifactLines(dir, "full_masks.txt", s.FullMasks); err != nil {
		return written, err
	}
	written = append(written, filepath.Join(dir, "full_masks.txt"))

	if err := writeArtifactLines(dir, "partial_masks.txt", s.PartialMasks); err != nil {
		return written, err
	}
	written = append(written, filepath.Join(dir, "partial_masks.txt"))

	if err := writeArtifactLines(dir, "rules.txt", s.Rules); err != nil {
		return written, err
	}
	written = append(written, filepath.Join(dir, "rules.txt"))

	return written, nil
}
