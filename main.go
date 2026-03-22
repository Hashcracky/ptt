package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"sort"
	"sync"

	"github.com/hashcracky/ptt/pkg/format"
	"github.com/hashcracky/ptt/pkg/models"
	"github.com/hashcracky/ptt/pkg/transform"
	"github.com/hashcracky/ptt/pkg/utils"
)

var version = "1.1.1"
var wg sync.WaitGroup
var mutex = &sync.Mutex{}
var retain models.FileArgumentFlag
var remove models.FileArgumentFlag
var readFiles models.FileArgumentFlag
var transformationFiles models.FileArgumentFlag
var intRange models.IntRange
var lenRange models.IntRange
var wordRange models.IntRange
var primaryMap map[string]int
var err error

// getModeHelp returns a detailed help string for each transformation mode.
// The returned text mirrors the USAGE.md guide so users can get mode-specific
// guidance directly from the CLI without opening the docs.
//
// Args:
//
//	mode string - The transformation mode name (or alias).
//
// Returns:
//
//	string - Detailed help text for the mode, or empty string if unknown.
func getModeHelp(mode string) string {
	help := map[string]string{
		"rule-append": `Mode: rule-append (alias: append)
Transforms input by creating Hashcat append rules.

Syntax:
  ptt -f <input_file> -t rule-append

Description:
  Creates append rules ($) for each character in the input strings. The rules
  append characters to the end of a candidate password during cracking.

Example:
  $ echo 'hello' | ptt -t rule-append
  $h $e $l $l $o`,

		"rule-append-remove": `Mode: rule-append-remove (alias: append-remove)
Transforms input by creating append-remove rules.

Syntax:
  ptt -f <input_file> -t rule-append-remove

Description:
  Removes characters from the end of the password before creating append rules.
  Combines the ] (remove last) and $ (append) operations.

Example:
  $ echo 'hello' | ptt -t rule-append-remove
  ] $h ] $e ] $l ] $l ] $o`,

		"rule-prepend": `Mode: rule-prepend (alias: prepend)
Transforms input by creating Hashcat prepend rules.

Syntax:
  ptt -f <input_file> -t rule-prepend

Description:
  Creates prepend rules (^) for each character in the input strings. The rules
  prepend characters to the beginning of a candidate password during cracking.

Example:
  $ echo 'hello' | ptt -t rule-prepend
  ^o ^l ^l ^e ^h`,

		"rule-prepend-remove": `Mode: rule-prepend-remove (alias: prepend-remove)
Transforms input by creating prepend-remove rules.

Syntax:
  ptt -f <input_file> -t rule-prepend-remove

Description:
  Removes characters from the beginning of the password before creating prepend
  rules. Combines the [ (remove first) and ^ (prepend) operations.

Example:
  $ echo 'hello' | ptt -t rule-prepend-remove
  [ ^o [ ^l [ ^l [ ^e [ ^h`,

		"rule-prepend-toggle": `Mode: rule-prepend-toggle (alias: prepend-toggle)
Transforms input by creating prepend-toggle rules.

Syntax:
  ptt -f <input_file> -t rule-prepend-toggle

Description:
  Creates rules that toggle the case of the password where a string is
  prepended. Useful for generating camel and pascal case passwords.

Example:
  $ echo 'Test' | ptt -t rule-prepend-toggle
  ^t ^s ^e ^T T4
  ^T ^s ^e ^t T0`,

		"rule-toggle": `Mode: rule-toggle (alias: toggle)
Transforms input by creating Hashcat toggle rules.

Syntax:
  ptt -f <input_file> -t rule-toggle -i <index>

Flags:
  -i <index>    Starting index of the toggle pattern (default: 0).
                Accepts ranges separated by '-' (e.g. 0-5).

Description:
  Creates toggle rules (T) for each position in the input strings, starting
  at the given index. If no index is provided, toggling begins at position 0.

Example:
  $ echo 'hello' | ptt -t rule-toggle
  T0
  T1
  T2
  T3
  T4

  $ echo 'hello' | ptt -t rule-toggle -i 2
  T2
  T3
  T4`,

		"rule-insert": `Mode: rule-insert (alias: insert)
Transforms input by creating Hashcat insert rules.

Syntax:
  ptt -f <input_file> -t rule-insert -i <index>

Flags:
  -i <index>    Position where the string will be inserted (default: 0).
                Accepts ranges separated by '-' (e.g. 1-5).

Description:
  Creates insert rules (i) for each character at the specified position in
  the password. The index can also accept range values in the format of
  start-end.

Example:
  $ echo 'hello' | ptt -t rule-insert -i 0
  i0h i1e i2l i3l i4o

  $ echo 'hello' | ptt -t rule-insert -i 1-3
  i1h i2e i3l i4l i5o
  i2h i3e i4l i5l i6o
  i3h i4e i5l i6l i7o`,

		"rule-overwrite": `Mode: rule-overwrite (alias: overwrite)
Transforms input by creating Hashcat overwrite rules.

Syntax:
  ptt -f <input_file> -t rule-overwrite -i <index>

Flags:
  -i <index>    Position where the string will be overwritten (default: 0).
                Accepts ranges separated by '-' (e.g. 1-5).

Description:
  Creates overwrite rules (o) for each character at the specified position.
  The index can also accept range values in the format of start-end.

Example:
  $ echo 'hello' | ptt -t rule-overwrite -i 0
  o0h o1e o2l o3l o4o

  $ echo 'hello' | ptt -t rule-overwrite -i 1-3
  o1h o2e o3l o4l o5o
  o2h o3e o4l o5l o6o
  o3h o4e o5l o6l o7o`,

		"encode": `Mode: encode
Transforms input by HTML and Unicode escape encoding.

Syntax:
  ptt -f <input_file> -t encode

Description:
  Encodes input strings using HTML entity encoding and Unicode escape
  sequences. Useful for generating encoded candidates.

Example:
  $ echo '<html>' | ptt -t encode
  &lt;html&gt;

  $ echo 'Hello' | ptt -t encode
  Hello\u0048\u0065\u006c\u006c\u006f`,

		"decode": `Mode: decode
Transforms input by HTML and Unicode escape decoding.

Syntax:
  ptt -f <input_file> -t decode

Description:
  Decodes input strings from HTML entity encoding and Unicode escape
  sequences back into their original form.

Example:
  $ echo '&lt;html&gt;' | ptt -t decode
  <html>`,

		"hex": `Mode: hex
Transforms input by encoding strings into $HEX[...] format.

Syntax:
  ptt -f <input_file> -t hex

Description:
  Encodes each input string into the $HEX[...] format used by Hashcat
  for representing non-printable or special characters.

Example:
  $ echo 'Hello' | ptt -t hex
  $HEX[48656c6c6f]`,

		"dehex": `Mode: dehex
Transforms input by decoding $HEX[...] formatted strings.

Syntax:
  ptt -f <input_file> -t dehex

Description:
  Decodes $HEX[...] formatted strings back into their plaintext form.

Example:
  $ echo '$HEX[48656c6c6f]' | ptt -t dehex
  Hello`,

		"mask": `Mode: mask
Transforms input by masking characters with the provided mask.

Syntax:
  ptt -f <input_file> -t mask -rm <mask_characters> -v

Flags:
  -rm <uldsb>   Characters to mask (u=upper, l=lower, d=digit, s=special,
                b=byte). Default: uldsb (all characters).
  -v            Show additional metadata: length, complexity, and mask keyspace
                appended as :length:complexity:keyspace.

Description:
  Replaces characters in input strings with Hashcat mask tokens (?u, ?l, ?d,
  ?s, ?b). Only the character classes specified in -rm are masked.

Example:
  $ echo 'Password1!' | ptt -t mask
  ?u?l?l?l?l?l?l?l?d?s

  $ echo 'Password1!' | ptt -t mask -rm ds
  Password?d?s

  $ echo 'Password1!' | ptt -t mask -rm ds -v
  1 Password?d?s:10:4:360`,

		"mask-remove": `Mode: mask-remove (alias: remove)
Transforms input by removing characters with the provided mask.

Syntax:
  ptt -f <input_file> -t mask-remove -rm <mask_characters>

Flags:
  -rm <uldsb>   Characters to remove (u=upper, l=lower, d=digit, s=special,
                b=byte). Default: uldsb (all characters).

Description:
  Masks the input and then removes the masked character tokens, leaving
  only the unmasked portions of the string.

Example:
  $ echo 'Password1!' | ptt -t mask-remove -rm ds
  Password`,

		"mask-retain": `Mode: mask-retain (alias: retain)
Transforms input by creating masks that retain specified keywords.

Syntax:
  ptt -f <input_file> -t mask-retain -rm <mask_characters> -tf <keep_file> -v

Flags:
  -rm <uldsb>   Mask characters to use for non-retained portions (default: all).
  -tf <file>    File containing keywords to retain. Required. Can be used
                multiple times.
  -v            Show additional metadata: length, complexity, and mask keyspace.

Description:
  Creates partial masks where specified keywords from the -tf file are kept
  in plaintext while all other characters are replaced with mask tokens.
  Each keyword match produces a separate output line.

Example:
  $ cat keep.txt
  sp-
  1337

  $ echo 'sp-test1337' | ptt -t mask-retain -tf keep.txt
  sp-?l?l?l?l?d?d?d?d
  ?l?l?s?l?l?l?l1337

  $ echo 'sp-test1337' | ptt -t mask-retain -tf keep.txt -rm l
  sp-?l?l?l?l1337
  ?l?l-?l?l?l?l1337`,

		"mask-match": `Mode: mask-match (alias: match)
Transforms input by keeping only strings that match masks from a file.

Syntax:
  ptt -f <input_file> -t mask-match -tf <mask_file>

Flags:
  -tf <file>    File containing masks to match against. Required. Can be
                used multiple times.

Description:
  Masks each input string and compares the result against the masks in the
  -tf file. Only input strings whose masks appear in the file are kept.

Example:
  $ cat masks.txt
  ?u?l?l?l?l?l?l?l?d?s

  $ echo 'Password1!' | ptt -t mask-match -tf masks.txt
  Password1!`,

		"mask-pop": `Mode: mask-pop (alias: pop)
Transforms input by 'popping' tokens from character boundaries.

Syntax:
  ptt -f <input_file> -t mask-pop -rm <mask_characters>

Flags:
  -rm <uldsbt>  Characters boundaries to pop on (u=upper, l=lower, d=digit,
                s=special, b=byte, t=title-case words requiring u and l).
                Default: uldsbt (all boundaries).

Description:
  Splits input strings at character-class boundaries defined by the mask
  and aggregates the resulting tokens. Useful for extracting meaningful
  substrings from passwords (e.g. words, numbers, specials).

Example:
  $ echo 'Password1!' | ptt -t mask-pop
  Password
  1
  !

  $ ptt -f rockyou.txt -t pop -l 4-5
  1234
  2007
  2006
  love
  ...`,

		"mask-swap": `Mode: mask-swap
Transforms input by swapping tokens using partial masks and a replacement file.

Syntax:
  ptt -f <mask_input> -t mask-swap -tf <replacement_file>

Flags:
  -tf <file>    File containing replacement tokens. Required. Can be used
                multiple times.

Description:
  Takes partial/retain masks as input (not raw passwords) and swaps the
  masked portions with tokens from the -tf replacement file. This is a
  two-step process: first create retain masks, then swap on them.

Example:
  Step 1 - Create retain masks:
  $ cat pass.lst
  love@123
  @123love

  $ cat retain.txt
  love

  $ ptt -f pass.lst -tf retain.txt -t mask-retain | tee retained.mask
  ?s?d?d?dlove
  love?s?d?d?d

  Step 2 - Swap tokens:
  $ cat swap.lst
  $333
  #888
  #123

  $ ptt -f retained.mask -tf swap.lst -t mask-swap
  #123love
  $333love
  love$333
  love#888
  love#123
  #888love`,

		"passphrase": `Mode: passphrase
Transforms input by generating passphrases from sentences.

Syntax:
  ptt -f <input_file> -t passphrase -w <word_count>

Flags:
  -w <count>    Number of words per passphrase. Required. Accepts ranges
                separated by '-' (e.g. 2-4).

Description:
  Reformats space-separated input sentences into new passphrases using the
  specified number of words. Input should contain space-separated content.

Example:
  $ echo 'the quick brown fox jumps' | ptt -t passphrase -w 3
  thequickbrown
  quickbrownfox
  brownfoxjumps

  $ echo 'the quick brown fox jumps' | ptt -t passphrase -w 2-3
  thequick
  quickbrown
  brownfox
  foxjumps
  thequickbrown
  quickbrownfox
  brownfoxjumps`,

		"regram": `Mode: regram
Transforms input by 'regramming' sentences into new n-grams.

Syntax:
  ptt -f <input_file> -t regram -w <word_count>

Flags:
  -w <count>    Number of words per n-gram. Required. Accepts ranges
                separated by '-' (e.g. 2-4).

Description:
  Generates new n-grams from space-separated input by combining words.
  Input should contain space-separated content.

Example:
  $ echo 'the quick brown fox' | ptt -t regram -w 2
  the quick
  quick brown
  brown fox

  $ echo 'the quick brown fox' | ptt -t regram -w 3
  the quick brown
  quick brown fox`,
	}

	aliases := map[string]string{
		"append":         "rule-append",
		"append-remove":  "rule-append-remove",
		"prepend":        "rule-prepend",
		"prepend-remove": "rule-prepend-remove",
		"prepend-toggle": "rule-prepend-toggle",
		"insert":         "rule-insert",
		"overwrite":      "rule-overwrite",
		"toggle":         "rule-toggle",
		"remove":         "mask-remove",
		"retain":         "mask-retain",
		"match":          "mask-match",
		"pop":            "mask-pop",
	}

	if canonical, ok := aliases[mode]; ok {
		mode = canonical
	}

	if text, ok := help[mode]; ok {
		return text
	}
	return ""
}

// peekTransformationArg scans os.Args for a -t flag value before flag.Parse
// runs so that the custom flag.Usage function can show mode-specific help
// when both -t and -h are supplied together.
//
// Returns:
//
//	string - The value of the -t flag if found, or empty string.
func peekTransformationArg() string {
	for i, arg := range os.Args {
		if arg == "-t" && i+1 < len(os.Args) {
			return os.Args[i+1]
		}
	}
	return ""
}

func main() {
	peekedMode := peekTransformationArg()

	flag.Usage = func() {
		if peekedMode != "" {
			helpText := getModeHelp(peekedMode)
			if helpText != "" {
				fmt.Fprintf(os.Stderr, "Password Transformation Tool (ptt) version (%s)\n", version)
				fmt.Fprintf(os.Stderr, "-------------------------------------------------------------------------------------------------------------\n")
				fmt.Fprintf(os.Stderr, "%s\n", helpText)
				fmt.Fprintf(os.Stderr, "-------------------------------------------------------------------------------------------------------------\n")
				fmt.Fprintf(os.Stderr, "For full documentation see: https://github.com/hashcracky/ptt/tree/main/docs/USAGE.md\n")
				return
			}
		}

		fmt.Fprintf(os.Stderr, "Usage of Password Transformation Tool (ptt) version (%s):\n\n", version)
		fmt.Fprintf(os.Stderr, "ptt [options] [...]\nAccepts standard input and/or additonal arguments.\n\n")
		fmt.Fprintf(os.Stderr, "The -f, -k, -r, and -tf flags can be used multiple times, together, and with files or directories.\n")
		fmt.Fprintf(os.Stderr, "-------------------------------------------------------------------------------------------------------------\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "These modify or filter the transformation mode.\n\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "-------------------------------------------------------------------------------------------------------------\n")
		fmt.Fprintf(os.Stderr, "Transformation Modes:\n")
		fmt.Fprintf(os.Stderr, "These create or alter based on the selected mode.\n\n")
		modes := map[string]string{
			"rule-append":                           "Transforms input by creating append rules. (alias: append)",
			"rule-append-remove":                    "Transforms input by creating append-remove rules. (alias: append-remove)",
			"rule-prepend":                          "Transforms input by creating prepend rules. (alias: prepend)",
			"rule-prepend-remove":                   "Transforms input by creating prepend-remove rules. (alias: prepend-remove)",
			"rule-prepend-toggle":                   "Transforms input by creating prepend-toggle rules. (alias: prepend-toggle)",
			"rule-insert -i [index]":                "Transforms input by creating insert rules starting at index. (alias: insert)",
			"rule-overwrite -i [index]":             "Transforms input by creating overwrite rules starting at index. (alias: overwrite)",
			"rule-toggle -i [index]":                "Transforms input by creating toggle rules starting at index. (alias: toggle)",
			"encode":                                "Transforms input by HTML and Unicode escape encoding.",
			"decode":                                "Transforms input by HTML and Unicode escape decoding.",
			"hex":                                   "Transforms input by encoding strings into $HEX[...] format.",
			"dehex":                                 "Transforms input by decoding $HEX[...] formatted strings.",
			"mask -rm [uldsb] -v":                   "Transforms input by masking characters with provided mask.",
			"mask-remove -rm [uldsb]":               "Transforms input by removing characters with provided mask. (alias: remove)",
			"mask-retain -rm [uldsb] -tf [file] -v": "Transforms input by creating masks that still retain strings from file. (alias: retain)",
			"mask-pop -rm [uldsbt]":                 "Transforms input by 'popping' tokens from character boundaries using the provided mask. (alias: pop)",
			"mask-match -tf [file]":                 "Transforms input by keeping only strings with matching masks from a mask file. (alias: match)",
			"mask-swap -tf [file]":                  "Transforms input by swapping tokens from a mask/partial mask input and a transformation file of tokens.",
			"passphrase -w [words]":                 "Transforms input by generating passphrases from sentences with a given number of words.",
			"regram -w [words]":                     "Transforms input by 'regramming' sentences into new n-grams with a given number of words.",
		}

		keys := make([]string, 0, len(modes))
		for k := range modes {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, k := range keys {
			fmt.Fprintf(os.Stderr, "  -t %s\n\t%s\n", k, modes[k])
		}
		fmt.Fprintf(os.Stderr, "-------------------------------------------------------------------------------------------------------------\n")
		fmt.Fprintf(os.Stderr, "Tip: Use -t <mode> -h for detailed help and examples on a specific mode.\n")
	}

	verbose := flag.Bool("v", false, "Show verbose output when possible. (Can show additional metadata in some modes.)")
	verbose2 := flag.Bool("vv", false, "Show statistics output when possible.")
	verbose3 := flag.Bool("vvv", false, "Show verbose statistics output when possible.")
	minimum := flag.Int("m", 0, "Minimum numerical frequency to include in output.")
	minComplexity := flag.Int("mc", 0, "Minimum complexity score to include before processing (lowercase, uppercase, digits, specials, bytes) [1-5].")
	outputVerboseMax := flag.Int("n", 0, "Maximum number of items to return in output.")
	transformation := flag.String("t", "", "Transformation to apply to input.")
	replacementMask := flag.String("rm", "uldsbt", "Replacement mask for transformations if applicable.")
	jsonOutput := flag.String("o", "", "Output to JSON file in addition to stdout. Accepts file names and paths.")
	bypassMap := flag.Bool("b", false, "Bypass map creation and use stdout as primary output. Disables some options.")
	debugMode := flag.Int("d", 0, "Enable debug mode with verbosity levels [0-2].")
	ignoreCase := flag.Bool("ic", false, "Ignore case when processing output and converts all output to lowercase.")
	flag.Var(&retain, "k", "Only keep items in a file.")
	flag.Var(&remove, "r", "Only keep items not in a file.")
	flag.Var(&readFiles, "f", "Read additional files for input.")
	flag.Var(&transformationFiles, "tf", "Read additional files for transformations if applicable.")
	flag.Var(&intRange, "i", "Starting index for transformations if applicable. Accepts ranges separated by '-'.")
	flag.Var(&lenRange, "l", "Only output items of a certain length (does not adjust for rules). Accepts ranges separated by '-'.")
	flag.Var(&wordRange, "w", "Number of words for transformations if applicable. Accepts ranges separated by '-'.")
	flag.Parse()

	if *bypassMap {
		fmt.Fprintf(os.Stderr, "[*] Bypassing map creation and using standard output as primary output. Options are disabled. This does not bypass the initial input memory usage.\n")
	}

	if *debugMode > 0 {
		fmt.Fprintf(os.Stderr, "[*] Debug mode enabled with verbosity level %d.\n", *debugMode)
	}

	fs := &models.RealFileSystem{}
	var retainMap map[string]int
	var removeMap map[string]int
	var readFilesMap map[string]int
	var transformationFilesMap map[string]int
	doneLoad := make(chan bool)
	go utils.TrackLoadTime(doneLoad, "Load")

	if retain != nil || remove != nil || readFiles != nil || transformationFiles != nil {
		fmt.Fprintf(os.Stderr, "[*] Reading files for input.\n")
	}

	if retain != nil {
		retainMap = utils.ReadFilesToMap(fs, retain)
	}
	if remove != nil {
		removeMap = utils.ReadFilesToMap(fs, remove)
	}
	if readFiles != nil {
		readFilesMap = utils.ReadFilesToMap(fs, readFiles)
	}
	if transformationFiles != nil {
		transformationFilesMap = utils.ReadFilesToMap(fs, transformationFiles)
	}

	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		primaryMap, err = utils.LoadStdinToMap(bufio.NewScanner(os.Stdin))
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error reading from standard input: %s.\n", err)
			return
		}
	}

	if len(primaryMap) == 0 && len(readFilesMap) == 0 {
		fmt.Fprintf(os.Stderr, "[!] No input provided. Exiting.\n")
		return
	} else if len(primaryMap) == 0 {
		primaryMap = readFilesMap
	} else if len(readFilesMap) > 0 {
		primaryMap = utils.CombineMaps(primaryMap, readFilesMap)
	}

	doneLoad <- true
	close(doneLoad)
	fmt.Fprintf(os.Stderr, "[*] All input loaded.\n")
	fmt.Fprintf(os.Stderr, "[*] Starting Processing.\n")

	if *minComplexity > 0 {
		fmt.Fprintf(os.Stderr, "[*] Filtering input items with complexity less than %d.\n", *minComplexity)
		primaryMap = format.FilterByComplexity(primaryMap, *minComplexity)
		if len(primaryMap) == 0 {
			fmt.Fprintf(os.Stderr, "[!] No items remaining after complexity filter. Exiting.\n")
			return
		}
	}

	doneProcess := make(chan bool)
	go utils.TrackLoadTime(doneProcess, "Processing")

	if *transformation != "" {
		primaryMap = transform.TransformationController(primaryMap, *transformation, intRange.Start, intRange.End, *verbose, *replacementMask, transformationFilesMap, *bypassMap, *debugMode, wordRange.Start, wordRange.End)
	}

	doneProcess <- true
	close(doneProcess)

	if *ignoreCase {
		fmt.Fprintf(os.Stderr, "[*] Ignoring case when processing output.\n")
	}

	if *ignoreCase {
		primaryMap = format.CreateIgnoreCaseMap(primaryMap)
	}

	if *minimum > 0 {
		fmt.Fprintf(os.Stderr, "[*] Removing items with frequency less than %d.\n", *minimum)
	}

	if *minimum > 0 {
		primaryMap = format.RemoveMinimumFrequency(primaryMap, *minimum)
	}

	if lenRange.Start > 0 || lenRange.End > 0 {
		fmt.Fprintf(os.Stderr, "[*] Only outputting items between %d and %d characters.\n", lenRange.Start, lenRange.End)
	}

	if lenRange.Start > 0 || lenRange.End > 0 {
		primaryMap = format.RemoveLengthRange(primaryMap, lenRange.Start, lenRange.End)
	}

	if len(retainMap) > 0 || len(removeMap) > 0 {
		fmt.Fprintf(os.Stderr, "[*] Retain/remove flags provided. Retaining %d and removing %d items.\n", len(retainMap), len(removeMap))
	}

	if len(retainMap) > 0 || len(removeMap) > 0 {
		primaryMap, err = format.RetainRemove(primaryMap, retainMap, removeMap, *debugMode)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error processing retain and remove flags: %s.\n", err)
			return
		}
	}

	if *outputVerboseMax > 0 {
		primaryMap = format.FilterTopN(primaryMap, *outputVerboseMax)
	}

	fmt.Fprintf(os.Stderr, "[*] Task complete with %d unique results.\n", len(primaryMap))

	if *verbose3 {
		format.PrintStatsToSTDOUT(primaryMap, *verbose3, *outputVerboseMax)
	} else if *verbose2 {
		format.PrintStatsToSTDOUT(primaryMap, *verbose3, *outputVerboseMax)
	} else {
		format.PrintArrayToSTDOUT(primaryMap, *verbose)
	}

	if *jsonOutput != "" {
		fmt.Fprintf(os.Stderr, "[*] Saving output to JSON file: %s.\n", *jsonOutput)
	}

	if *jsonOutput != "" {
		err = format.SaveArrayToJSON(*jsonOutput, primaryMap)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error saving output to JSON: %s.\n", err)
			return
		}
	}
}
