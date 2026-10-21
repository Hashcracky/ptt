// Package brainstorm contains the brainstorm transformation mode for PTT.
//
// This package adapts the logic from the brainstorm application (github.com/hashcracky/brainstorm)
// into PTT's map-based transformation pipeline.
package brainstorm

import (
	"bufio"
	"strings"
	"unicode"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// TransformLine applies the core brainstorm transformation to a single input line.
//
// Args:
// cfg: *Config - Application configuration.
// line: string - Raw input line (without trailing newline).
//
// Returns:
// string - Transformed line (without trailing newline).
func TransformLine(cfg *Config, line string) string {
	line = removeTrailingNonLettersDigitsStr(line)
	line = removeLeadingNonLettersDigitsStr(line)
	line = filterLinesStr(cfg, line)

	if len(line) == 0 {
		return ""
	}

	processedChunk := generateNGramSliceStr(line, cfg.NGramMin, cfg.NGramMax)
	processedChunk = strings.Join(prepareStringForTransformationsStr(processedChunk), "\n")

	processedChunk = strings.Join(applyPostFiltersStr(processedChunk), "\n")

	return enforceLengthRangeStr(processedChunk, cfg.OutMinLength, cfg.OutMaxLength)
}

// generateNGramSliceStr takes a string and generates a new string
// using the generateNGrams function and combines the results.
//
// Args:
// input (string): The original string to generate n-grams from
// wordRangeStart (int): The starting number of words to use for n-grams
// wordRangeEnd (int): The ending iteration number of words to use for n-grams
//
// Returns:
// string: A new string with the n-grams generated.
func generateNGramSliceStr(input string, wordRangeStart int, wordRangeEnd int) string {
	lines := strings.Split(input, "\n")
	var newList []string

	for _, line := range lines {
		nGrams := generateNGrams(line, wordRangeStart, wordRangeEnd)
		newList = append(newList, nGrams...)
	}

	return strings.Join(newList, "\n")
}

// generateNGrams generates n-grams from a string of text and returns a slice of n-grams.
//
// Args:
// text (string): The text to generate n-grams from.
// wordRangeStart (int): The starting number of words to use for n-grams.
// wordRangeEnd (int): The ending iteration number of words to use for n-grams.
//
// Returns:
// []string: A slice of n-grams.
func generateNGrams(text string, wordRangeStart int, wordRangeEnd int) []string {
	words := strings.Fields(text)
	var nGrams []string

	for i := wordRangeStart; i <= wordRangeEnd; i++ {
		if i <= 0 || i > len(words) {
			continue
		}

		for j := 0; j <= len(words)-i; j++ {
			nGram := strings.Join(words[j:j+i], " ")
			nGram = strings.TrimSpace(nGram)
			nGram = strings.TrimLeft(nGram, " ")
			nGram = strings.ReplaceAll(nGram, ".", "")
			nGram = strings.ReplaceAll(nGram, ",", "")
			nGram = strings.ReplaceAll(nGram, ";", "")
			nGrams = append(nGrams, nGram)
		}
	}

	return nGrams
}

// prepareStringForTransformationsStr processes each line in the input string,
// removes unwanted characters, normalizes each line, and generates various
// transformed versions for each line.
//
// Args:
// data (string): The string containing lines to process.
//
// Returns:
// []string: A flattened slice of all prepared string variants for all lines.
func prepareStringForTransformationsStr(data string) []string {
	input := data
	scanner := bufio.NewScanner(strings.NewReader(input))

	var results []string

	for scanner.Scan() {
		line := scanner.Text()

		clean := strings.ReplaceAll(line, "\x00", "")
		clean = strings.ReplaceAll(clean, "\n", "")
		clean = strings.ReplaceAll(clean, "\t", "")
		clean = strings.ReplaceAll(clean, "\r", "")
		clean = strings.ReplaceAll(clean, "\f", "")
		clean = strings.ReplaceAll(clean, "\v", "")

		if strings.TrimSpace(clean) == "" {
			continue
		}

		if strings.Contains(clean, " ") {
			results = append(
				results,
				strings.ReplaceAll(
					cases.Title(language.Und, cases.NoLower).String(clean),
					" ",
					"",
				),
			)
		} else {
			results = append(results, strings.ReplaceAll(clean, " ", ""))
		}
	}

	return results
}

// applyPostFiltersStr applies post-processing filters on the transformed output
// lines, including removing unbalanced leading-quote or leading-bracket
// variants and adding apostrophe-stripped variants.
//
// Args:
// data (string): The string containing transformed lines.
//
// Returns:
// []string: A slice of filtered and augmented lines.
func applyPostFiltersStr(data string) []string {
	input := data
	scanner := bufio.NewScanner(strings.NewReader(input))

	var filtered []string

	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			continue
		}

		if hasUnbalancedLeadingDelimiter(line) {
			continue
		}

		if hasUnbalancedDelimitersAnywhere(line) {
			continue
		}

		// If middle-quote noise is present, emit apostrophe-free variants so there is still output.
		if containsMiddleQuoteNoise(line) {
			apostropheFreeVariants := generateApostropheFreeVariants(line)
			filtered = append(filtered, apostropheFreeVariants...)
			continue
		}

		filtered = append(filtered, line)

		apostropheFreeVariants := generateApostropheFreeVariants(line)
		filtered = append(filtered, apostropheFreeVariants...)
	}

	return filtered
}

// hasUnbalancedLeadingDelimiter checks whether a string starts with an opening
// quote or bracket and lacks the corresponding closing quote or bracket later
// in the token.
//
// Args:
// s (string): The string to inspect.
//
// Returns:
// bool: True if the string has an unbalanced leading delimiter.
func hasUnbalancedLeadingDelimiter(s string) bool {
	if s == "" {
		return false
	}

	runes := []rune(s)

	openToClose := map[rune][]rune{
		'(': {')'},
		'[': {']'},
		'{': {'}'},
		'<': {'>'},
		'"': {'"', '”'},
		'“': {'”', '"'},
		'‘': {'’', '\''},
	}

	first := runes[0]

	allowedClosers, isOpening := openToClose[first]
	if !isOpening {
		return false
	}

	for _, r := range runes[1:] {
		for _, c := range allowedClosers {
			if r == c {
				return false
			}
		}
	}

	return true
}

// generateApostropheFreeVariants returns variants of the input string where
// apostrophes are removed. The original string is not included in the
// returned slice.
//
// Args:
// s (string): The string to generate variants from.
//
// Returns:
// []string: A slice of apostrophe-free variants, or an empty slice if no
// apostrophes are present.
func generateApostropheFreeVariants(s string) []string {
	if !strings.ContainsAny(s, "'’") {
		return nil
	}

	variant := strings.Map(
		func(r rune) rune {
			if r == '\'' || r == '’' {
				return -1
			}

			return r
		},
		s,
	)

	if variant == "" || variant == s {
		return nil
	}

	return []string{variant}
}

// filterLinesStr checks each line and skips those that consist only of digits or
// special characters and those that are unlikely to contain words. In unicode
// mode (cfg.IncludeNonLatin), lines containing any non-Latin letters are accepted
// without Latin vowel heuristics.
//
// Args:
// cfg (*Config): Configuration.
// data (string): The string containing the data to be processed.
//
// Returns:
// string: The processed string with filtered lines.
func filterLinesStr(cfg *Config, data string) string {
	scanner := bufio.NewScanner(strings.NewReader(data))
	var result strings.Builder

	for scanner.Scan() {
		line := scanner.Text()

		if strings.TrimSpace(line) == "" {
			continue
		}

		if isAllDigitsOrSpecialChars(line) {
			continue
		}

		if cfg.IncludeNonLatin {
			if containsNonLatinLetter(line) {
				result.WriteString(line + "\n")
				continue
			}
			if !likelyContainsWords(line) {
				continue
			}
			result.WriteString(line + "\n")
			continue
		}

		if !likelyContainsWords(line) {
			continue
		}

		result.WriteString(line + "\n")
	}

	return result.String()
}

// containsNonLatinLetter returns true if the string contains at least one
// Unicode letter that is not part of the Latin script.
//
// Args:
// s (string): Input string.
//
// Returns:
// bool: True if a non-Latin letter is present.
func containsNonLatinLetter(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) && !unicode.Is(unicode.Latin, r) {
			return true
		}
	}
	return false
}

// isAllDigitsOrSpecialChars checks if a string contains only digits or special
// characters.
//
// Args:
// s (string): The string to check.
//
// Returns:
// bool: True if the string contains only digits or special characters, false
// otherwise.
func isAllDigitsOrSpecialChars(s string) bool {
	hasLetter := false

	for _, char := range s {
		if unicode.IsLetter(char) {
			hasLetter = true
			break
		}
	}

	return !hasLetter
}

// likelyContainsWords checks a string to see if there are atleast 5 characters
// in a row that are not digits or special characters and ensures that there is
// atleast one vowel in the string.
//
// Args:
// s (string): The string to check.
//
// Returns:
// bool: True if the string likely contains words, false otherwise.
func likelyContainsWords(s string) bool {
	if len(s) < 2 {
		return false
	}

	if len(s) < 5 {
		return looksLikeWordPattern(s)
	}

	if !looksLikeWordPattern(s) {
		return false
	}

	vowelCount := 0

	for i := 0; i < len(s)-4; i++ {
		if isWordLike(s[i : i+5]) {
			vowelCount++
		}
	}

	return vowelCount > 0
}

// isWordLike checks if a substring contains at least one vowel and no more
// than one digit or special character.
//
// Args:
// s (string): The substring to check.
//
// Returns:
// bool: True if the substring is likely a word, false otherwise.
func isWordLike(s string) bool {
	vowels := "aeiouAEIOU"
	digitOrSpecialCount := 0
	hasVowel := false

	for _, char := range s {
		if strings.ContainsRune(vowels, char) {
			hasVowel = true
		} else if !unicode.IsLetter(char) {
			digitOrSpecialCount++
		}
	}

	return hasVowel && digitOrSpecialCount <= 1
}

// removeTrailingNonLettersDigitsStr removes trailing characters from each line
// that are not letters.
//
// Args:
// data (string): The string containing the data to be processed.
//
// Returns:
// string: The processed string with trailing non-letter characters removed.
func removeTrailingNonLettersDigitsStr(data string) string {
	scanner := bufio.NewScanner(strings.NewReader(data))
	var result strings.Builder

	for scanner.Scan() {
		line := scanner.Text()

		processedLine := strings.TrimRightFunc(line, func(r rune) bool {
			return !unicode.IsLetter(r)
		})

		result.WriteString(processedLine + "\n")
	}

	return result.String()
}

// removeLeadingNonLettersDigitsStr removes leading characters from each line
// that are not letters.
//
// Args:
// data (string): The string containing the data to be processed.
//
// Returns:
// string: The processed string with leading non-letter characters removed.
func removeLeadingNonLettersDigitsStr(data string) string {
	scanner := bufio.NewScanner(strings.NewReader(data))
	var result strings.Builder

	for scanner.Scan() {
		line := scanner.Text()

		processedLine := strings.TrimLeftFunc(line, func(r rune) bool {
			return !unicode.IsLetter(r)
		})

		result.WriteString(processedLine + "\n")
	}

	return result.String()
}

// enforceLengthRangeStr filters the input string to only include strings
// between minLength and maxLength characters inclusive.
//
// Args:
// input (string): The input string to filter.
// minLength (int): The minimum length of strings to include.
// maxLength (int): The maximum length of strings to include.
//
// Returns:
// string: A new string with strings within the specified length range.
func enforceLengthRangeStr(input string, minLength int, maxLength int) string {
	lines := strings.Split(input, "\n")
	var filtered []string

	for _, line := range lines {
		if len(line) >= minLength && len(line) <= maxLength {
			filtered = append(filtered, line)
		}
	}

	return strings.Join(filtered, "\n")
}

// isVowel returns whether a rune is a vowel.
//
// Args:
// r: rune - Character to test.
//
// Returns:
// bool - True if the rune is a vowel, false otherwise.
func isVowel(r rune) bool {
	vowels := "aeiouAEIOU"

	return strings.ContainsRune(vowels, r)
}

// isLetterLike returns whether a rune should be treated as a word letter.
//
// Args:
// r: rune - Character to test.
//
// Returns:
// bool - True if the rune is letter-like, false otherwise.
func isLetterLike(r rune) bool {
	return unicode.IsLetter(r) || r == '\''
}

// looksLikeWordPattern applies heuristic checks for vowel density and
// consonant run length to decide whether a string looks like a word.
//
// Args:
// s: string - Input string.
//
// Returns:
// bool - True if the string passes heuristic word checks, false otherwise.
func looksLikeWordPattern(s string) bool {
	if len(s) == 0 {
		return false
	}

	if hasSuspiciousAlphaNumericRuns(s) {
		return false
	}

	if hasHighNonLetterDensity(s) {
		return false
	}

	if containsTooManyUncommonClusters(s) {
		return false
	}

	syllables := countSyllableLikeSegments(s)

	if syllables == 0 {
		return false
	}

	if len(s) >= 8 && syllables < 2 {
		return false
	}

	var (
		vowelCount          int
		letterCount         int
		maxConsonantRun     int
		currentConsonantRun int
		maxVowelRun         int
		currentVowelRun     int
	)

	for _, r := range s {
		if !isLetterLike(r) {
			continue
		}

		letterCount++

		if isVowel(r) {
			vowelCount++
			currentVowelRun++
			if currentVowelRun > maxVowelRun {
				maxVowelRun = currentVowelRun
			}
			currentConsonantRun = 0
		} else {
			currentConsonantRun++
			if currentConsonantRun > maxConsonantRun {
				maxConsonantRun = currentConsonantRun
			}
			currentVowelRun = 0
		}
	}

	if letterCount == 0 {
		return false
	}

	vowelRatio := float64(vowelCount) / float64(letterCount)

	if vowelRatio < 0.25 {
		return false
	}

	if vowelRatio > 0.8 {
		return false
	}

	if maxConsonantRun > 4 {
		return false
	}

	if maxVowelRun > 3 {
		return false
	}

	return true
}

// containsTooManyUncommonClusters checks for a high ratio of uncommon
// letter clusters that are unlikely in natural language.
//
// Args:
// s: string - Input string.
//
// Returns:
// bool - True if the string contains too many uncommon clusters.
func containsTooManyUncommonClusters(s string) bool {
	uncommonBigrams := map[string]struct{}{
		"qx": {}, "xq": {}, "qj": {}, "jq": {}, "vk": {}, "kj": {}, "zx": {}, "xk": {},
		"vv": {}, "ww": {}, "zz": {}, "qq": {}, "xx": {}, "kk": {}, "jj": {},
		"gf": {}, "fg": {}, "vd": {}, "dv": {}, "qz": {}, "zq": {}, "hj": {}, "jh": {},
	}

	lower := strings.ToLower(s)

	var (
		totalBigrams      int
		uncommonBigramCnt int
		noVowelWindowCnt  int
	)

	for i := 0; i < len(lower)-1; i++ {
		a := lower[i]
		b := lower[i+1]

		if !unicode.IsLetter(rune(a)) || !unicode.IsLetter(rune(b)) {
			continue
		}

		totalBigrams++

		key := string([]byte{a, b})

		if _, exists := uncommonBigrams[key]; exists {
			uncommonBigramCnt++
		}

		if i+4 < len(lower) {
			window := lower[i : i+5]

			if !windowHasVowel(window) {
				noVowelWindowCnt++
			}
		}
	}

	if totalBigrams == 0 {
		return false
	}

	uncommonRatio := float64(uncommonBigramCnt) / float64(totalBigrams)
	noVowelRatio := float64(noVowelWindowCnt) / float64(totalBigrams)

	if uncommonRatio > 0.2 {
		return true
	}

	if noVowelRatio > 0.35 {
		return true
	}

	return false
}

// windowHasVowel checks whether a byte window contains at least one vowel.
//
// Args:
// window: string - Input window.
//
// Returns:
// bool - True if a vowel is present, false otherwise.
func windowHasVowel(window string) bool {
	for _, r := range window {
		if isVowel(r) {
			return true
		}
	}

	return false
}

// countSyllableLikeSegments approximates syllable count by scanning for
// consonant-plus-vowel patterns.
//
// Args:
// s: string - Input string.
//
// Returns:
// int - Approximated number of syllable-like segments.
func countSyllableLikeSegments(s string) int {
	lower := strings.ToLower(s)
	var (
		syllables int
		i         int
		n         = len(lower)
	)

	for i < n {
		for i < n && !isLetterLike(rune(lower[i])) {
			i++
		}

		for i < n && isLetterLike(rune(lower[i])) && !isVowel(rune(lower[i])) {
			i++
		}

		if i < n && isVowel(rune(lower[i])) {
			syllables++

			for i < n && isVowel(rune(lower[i])) {
				i++
			}
		}
	}

	return syllables
}

// hasHighNonLetterDensity checks whether a string contains a high ratio
// of digits and special characters compared to letters.
//
// Args:
// s: string - Input string.
//
// Returns:
// bool - True if non-letter density is too high, false otherwise.
func hasHighNonLetterDensity(s string) bool {
	var letterCount int
	var nonLetterCount int

	for _, r := range s {
		if unicode.IsLetter(r) {
			letterCount++
		} else if unicode.IsDigit(r) || unicode.IsSymbol(r) || unicode.IsPunct(r) {
			nonLetterCount++
		}
	}

	if letterCount == 0 {
		return true
	}

	total := letterCount + nonLetterCount

	if total == 0 {
		return false
	}

	nonLetterRatio := float64(nonLetterCount) / float64(total)

	if nonLetterRatio > 0.3 {
		return true
	}

	return false
}

// hasSuspiciousAlphaNumericRuns checks for long sequences where digits
// are embedded inside otherwise alphabetic chunks.
//
// Args:
// s: string - Input string.
//
// Returns:
// bool - True if suspicious alphanumeric runs are present.
func hasSuspiciousAlphaNumericRuns(s string) bool {
	var (
		currentRunLen int
		hasLetter     bool
		hasDigit      bool
	)

	reset := func() {
		currentRunLen = 0
		hasLetter = false
		hasDigit = false
	}

	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			currentRunLen++

			if unicode.IsLetter(r) {
				hasLetter = true
			}

			if unicode.IsDigit(r) {
				hasDigit = true
			}

			if currentRunLen >= 6 && hasLetter && hasDigit {
				return true
			}
		} else {
			reset()
		}
	}

	return false
}

// hasUnbalancedDelimitersAnywhere reports whether parentheses/brackets/braces
// are unbalanced or misordered anywhere in the string.
//
// Args:
// s: string - Input token.
//
// Returns:
// bool - True if any (), [], {}, or <> are unbalanced or misordered.
func hasUnbalancedDelimitersAnywhere(s string) bool {
	type pair struct{ open, close rune }
	pairs := []pair{
		{'(', ')'},
		{'[', ']'},
		{'{', '}'},
		{'<', '>'},
	}

	for _, p := range pairs {
		var depth int

		for _, r := range s {
			if r == p.open {
				depth++
			} else if r == p.close {
				if depth == 0 {
					return true
				}
				depth--
			}
		}

		if depth != 0 {
			return true
		}
	}

	return false
}

// containsMiddleQuoteNoise reports whether the string contains quote or backtick
// characters in the middle of the token, which commonly indicate parsing artifacts.
//
// Args:
// s: string - Input token.
//
// Returns:
// bool - True if '"', '\' or '`' appears at a non-edge position, or if repeated
// sequences like ” or “ occur inside the token.
func containsMiddleQuoteNoise(s string) bool {
	if len(s) < 3 {
		return false
	}

	runes := []rune(s)
	n := len(runes)

	for i, r := range runes {
		if r == '"' || r == '\'' || r == '`' {
			if i > 0 && i < n-1 {
				return true
			}
			if i+1 < n && (runes[i+1] == r) && i+1 < n-1 {
				return true
			}
		}
	}

	return false
}
