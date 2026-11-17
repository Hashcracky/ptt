package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/hashcracky/ptt/pkg/analyze"
	"github.com/hashcracky/ptt/pkg/bypass"
	"github.com/hashcracky/ptt/pkg/format"
	"github.com/hashcracky/ptt/pkg/models"
	"github.com/hashcracky/ptt/pkg/transform"
	"github.com/hashcracky/ptt/pkg/utils"
)

var version = "1.3.1"
var retain models.FileArgumentFlag
var remove models.FileArgumentFlag
var readFiles models.FileArgumentFlag
var transformationFiles models.FileArgumentFlag
var intRange models.IntRange
var lenRange models.IntRange
var wordRange models.IntRange
var primaryMap map[string]int
var err error
var analyzeMode bool
var inputLines []string

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
		"rule-append": `Mode: rule-append
Alias: append
Make Hashcat append rules from the input.

Syntax:
  ptt -f <input_file> -t rule-append

Description:
  The mode makes an append rule ($) for each character in the input string.
  In Hashcat, an append rule adds a character to the end of a candidate
  password.

Example:
  $ echo 'hello' | ptt -t rule-append
  $h $e $l $l $o`,

		"rule-append-remove": `Mode: rule-append-remove
Alias: append-remove
Make append-remove rules from the input.

Syntax:
  ptt -f <input_file> -t rule-append-remove

Description:
  Each rule removes the last character of the password. Then it adds a
  character to the end. The rule uses the ] (remove last) and $ (append)
  operations.

Example:
  $ echo 'hello' | ptt -t rule-append-remove
  ] $h ] $e ] $l ] $l ] $o`,

		"rule-prepend": `Mode: rule-prepend
Alias: prepend
Make Hashcat prepend rules from the input.

Syntax:
  ptt -f <input_file> -t rule-prepend

Description:
  The mode makes a prepend rule (^) for each character in the input string.
  In Hashcat, a prepend rule adds a character to the start of a candidate
  password.

Example:
  $ echo 'hello' | ptt -t rule-prepend
  ^o ^l ^l ^e ^h`,

		"rule-prepend-remove": `Mode: rule-prepend-remove
Alias: prepend-remove
Make prepend-remove rules from the input.

Syntax:
  ptt -f <input_file> -t rule-prepend-remove

Description:
  Each rule removes the first character of the password. Then it adds a
  character to the start. The rule uses the [ (remove first) and ^ (prepend)
  operations.

Example:
  $ echo 'hello' | ptt -t rule-prepend-remove
  [ ^o [ ^l [ ^l [ ^e [ ^h`,

		"rule-prepend-toggle": `Mode: rule-prepend-toggle
Alias: prepend-toggle
Make prepend-toggle rules from the input.

Syntax:
  ptt -f <input_file> -t rule-prepend-toggle

Description:
  The mode makes rules that add a string to the start of a password and
  toggle the case. Use these rules to make camel case and pascal case
  passwords.

Example:
  $ echo 'Test' | ptt -t rule-prepend-toggle
  ^t ^s ^e ^T T4
  ^T ^s ^e ^t T0`,

		"rule-toggle": `Mode: rule-toggle
Alias: toggle
Make Hashcat toggle rules from the input.

Syntax:
  ptt -f <input_file> -t rule-toggle -i <index>

Flags:
  -i <index>    The start index of the toggle pattern. The default is 0.
                The value can be a range, for example 0-5.

Description:
  The mode makes a toggle rule (T) for each position in the input string.
  It starts at the index that you give. If you do not give an index, it
  starts at position 0.

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

		"rule-insert": `Mode: rule-insert
Alias: insert
Make Hashcat insert rules from the input.

Syntax:
  ptt -f <input_file> -t rule-insert -i <index>

Flags:
  -i <index>    The position where the rule inserts the string. The default
                is 0. The value can be a range, for example 1-5.

Description:
  The mode makes an insert rule (i) for each character at the position that
  you give in the password. The index can also be a range in the format
  start-end.

Example:
  $ echo 'hello' | ptt -t rule-insert -i 0
  i0h i1e i2l i3l i4o

  $ echo 'hello' | ptt -t rule-insert -i 1-3
  i1h i2e i3l i4l i5o
  i2h i3e i4l i5l i6o
  i3h i4e i5l i6l i7o`,

		"rule-overwrite": `Mode: rule-overwrite
Alias: overwrite
Make Hashcat overwrite rules from the input.

Syntax:
  ptt -f <input_file> -t rule-overwrite -i <index>

Flags:
  -i <index>    The position where the rule overwrites the string. The
                default is 0. The value can be a range, for example 1-5.

Description:
  The mode makes an overwrite rule (o) for each character at the position
  that you give. The index can also be a range in the format start-end.

Example:
  $ echo 'hello' | ptt -t rule-overwrite -i 0
  o0h o1e o2l o3l o4o

  $ echo 'hello' | ptt -t rule-overwrite -i 1-3
  o1h o2e o3l o4l o5o
  o2h o3e o4l o5l o6o
  o3h o4e o5l o6l o7o`,

		"encode": `Mode: encode
Encode the input as HTML entities and Unicode escape sequences.

Syntax:
  ptt -f <input_file> -t encode

Description:
  The mode encodes each input string with HTML entities and with Unicode
  escape sequences. Use it to make encoded candidates.

Example:
  $ echo '<html>' | ptt -t encode
  &lt;html&gt;

  $ echo 'Hello' | ptt -t encode
  Hello\u0048\u0065\u006c\u006c\u006f`,

		"decode": `Mode: decode
Decode HTML entities and Unicode escape sequences in the input.

Syntax:
  ptt -f <input_file> -t decode

Description:
  The mode decodes HTML entities and Unicode escape sequences in each input
  string.

Example:
  $ echo '&lt;html&gt;' | ptt -t decode
  <html>`,

		"hex": `Mode: hex
Encode the input strings in the $HEX[...] format.

Syntax:
  ptt -f <input_file> -t hex

Description:
  The mode encodes each input string in the $HEX[...] format. Hashcat uses
  this format for special characters and non-printable characters.

Example:
  $ echo 'Hello' | ptt -t hex
  $HEX[48656c6c6f]`,

		"dehex": `Mode: dehex
Decode the $HEX[...] strings in the input.

Syntax:
  ptt -f <input_file> -t dehex

Description:
  The mode decodes each string in the $HEX[...] format to plain text.

Example:
  $ echo '$HEX[48656c6c6f]' | ptt -t dehex
  Hello`,

		"mask": `Mode: mask
Replace characters in the input with a mask.

Syntax:
  ptt -f <input_file> -t mask -rm <mask_characters> -v

Flags:
  -rm <uldsb>   The characters to mask: u=upper, l=lower, d=digit,
                s=special, b=byte. The default is uldsb (all characters).
  -v            Add metadata to each result: the length, the complexity, and
                the mask keyspace. The format is :length:complexity:keyspace.

Description:
  The mode replaces characters in the input strings with Hashcat mask tokens
  (?u, ?l, ?d, ?s, ?b). It masks only the character classes that you give
  with -rm.

Example:
  $ echo 'Password1!' | ptt -t mask
  ?u?l?l?l?l?l?l?l?d?s

  $ echo 'Password1!' | ptt -t mask -rm ds
  Password?d?s

  $ echo 'Password1!' | ptt -t mask -rm ds -v
  1 Password?d?s:10:4:360`,

		"mask-remove": `Mode: mask-remove
Alias: remove
Remove the characters that a mask selects.

Syntax:
  ptt -f <input_file> -t mask-remove -rm <mask_characters>

Flags:
  -rm <uldsb>   The characters to remove: u=upper, l=lower, d=digit,
                s=special, b=byte. The default is uldsb (all characters).

Description:
  The mode makes the mask of each input string and then removes the mask
  tokens. The output has only the parts that have no mask.

Example:
  $ echo 'Password1!' | ptt -t mask-remove -rm ds
  Password`,

		"mask-retain": `Mode: mask-retain
Alias: retain
Make masks that keep the keywords from a file.

Syntax:
  ptt -f <input_file> -t mask-retain -rm <mask_characters> -tf <keep_file> -v

Flags:
  -rm <uldsb>   The mask characters for the parts that the mode does not
                keep. The default is all.
  -tf <file>    The file with the keywords to keep. You must set this flag.
                You can use it more than one time.
  -v            Add metadata: the length, the complexity, and the mask
                keyspace.

Description:
  The mode makes partial masks. It keeps the keywords from the -tf file as
  plain text and replaces all other characters with mask tokens. Each
  keyword match makes one output line.

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

		"mask-match": `Mode: mask-match
Alias: match
Keep only the input strings that match a mask from a file.

Syntax:
  ptt -f <input_file> -t mask-match -tf <mask_file>

Flags:
  -tf <file>    The file with the masks to match. You must set this flag.
                You can use it more than one time.

Description:
  The mode makes the mask of each input string. It compares this mask to the
  masks in the -tf file. It keeps only the input strings that have a mask in
  the file.

Example:
  $ cat masks.txt
  ?u?l?l?l?l?l?l?l?d?s

  $ echo 'Password1!' | ptt -t mask-match -tf masks.txt
  Password1!`,

		"mask-pop": `Mode: mask-pop
Alias: pop
Divide the input at character boundaries and keep the tokens.

Syntax:
  ptt -f <input_file> -t mask-pop -rm <mask_characters>

Flags:
  -rm <uldsbt>  The character boundaries to divide at: u=upper, l=lower,
                d=digit, s=special, b=byte, t=title-case words (use it with u
                and l). The default is uldsbt (all boundaries).

Description:
  The mode divides each input string at the character-class boundaries that
  the mask gives. It collects the tokens. Use it to get words, numbers, and
  special characters from passwords.

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
Swap the tokens in partial masks with tokens from a file.

Syntax:
  ptt -f <mask_input> -t mask-swap -tf <replacement_file>

Flags:
  -tf <file>    The file with the replacement tokens. You must set this flag.
                You can use it more than one time.

Description:
  The input is a partial mask (a retain mask), not a password. The mode
  replaces the masked parts with tokens from the -tf file. There are two
  steps: first make retain masks, then swap the tokens in them.

Example:
  Step 1 - Make retain masks:
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
Make passphrases from sentences.

Syntax:
  ptt -f <input_file> -t passphrase -w <word_count>

Flags:
  -w <count>    The number of words in each passphrase. You must set this
                flag. The value can be a range, for example 2-4.

Description:
  The mode makes new passphrases from the input sentences. Each passphrase
  has the number of words that you give. The input lines must contain words
  with spaces between them.

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
Make new n-grams from sentences.

Syntax:
  ptt -f <input_file> -t regram -w <word_count>

Flags:
  -w <count>    The number of words in each n-gram. You must set this flag.
                The value can be a range, for example 2-4.

Description:
  The mode makes new n-grams from groups of words in the input sentences.
  The input lines must contain words with spaces between them.

Example:
  $ echo 'the quick brown fox' | ptt -t regram -w 2
  the quick
  quick brown
  brown fox

  $ echo 'the quick brown fox' | ptt -t regram -w 3
  the quick brown
  quick brown fox`,

		"brainstorm": `Mode: brainstorm
Make n-grams in title case, with and without apostrophes, in a length range.

Syntax:
  ptt -f <input_file> -t brainstorm -w <word_range> -l <length_range> [-unicode]

Flags:
  -w <range>    The range of words in an n-gram, in the format start-end.
                The default is 1-5.
  -l <range>    The range of the output length, in the format min-max. The
                default is 4-32.
  -unicode      Keep the lines that have non-Latin letters. The mode does not
                do the Latin vowel check on these lines.

Description:
  The mode makes n-grams from the input lines. It changes the results that
  have more than one word to title case. It removes the n-grams that have a
  delimiter with no pair. For an n-gram with an apostrophe, it writes a copy
  with no apostrophe. Use it to make candidate passwords from word lists.

Example:
  $ echo 'hello world' | ptt -t brainstorm -w 1-3 -l 4-20
  Hello
  World
  HelloWorld

  $ echo 'password test123' | ptt -t brainstorm -w 1-2 -l 4-20 -unicode
  Password
  Test123`,

		"analyze": `Mode: analyze
Alias: analyzer
Calculate metadata for the input.

Syntax:
  ptt -f <input_file> -t analyze [-v] [-o <output_file>]

Flags:
  -v            Show a longer report. The report has the token category
                counts, the character composition, and samples of the full
                masks, the partial masks, and the rules.
  -o <dir>      Write the artifacts to this directory. The artifacts are
                full_masks.txt, partial_masks.txt, rules.txt, and tokens.txt.

Description:
  The mode analyzes the input plaintext corpus. It finds the top tokens, the
  token category counts, and the character composition. It also makes full
  masks, partial Hashcat masks, and a set of Hashcat rules.

Example:
  $ echo 'Password1!' | ptt -t analyze
  $ cat passwords.txt | ptt -t analyze -v
  $ ptt -f passwords.txt -t analyze -o report.json`,
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
		"analyzer":       "analyze",
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
				fmt.Fprintf(os.Stderr, "For all the documentation, refer to: https://github.com/hashcracky/ptt/tree/main/docs/USAGE.md\n")
				return
			}
		}

		fmt.Fprintf(os.Stderr, "Usage of Password Transformation Tool (ptt) version (%s):\n\n", version)
		fmt.Fprintf(os.Stderr, "ptt [options]\nThe tool reads standard input. It also reads the files that you give.\n\n")
		fmt.Fprintf(os.Stderr, "You can use the -f, -k, -r, and -tf flags more than one time. You can use them together.\nEach of these flags accepts files and directories.\n")
		fmt.Fprintf(os.Stderr, "-------------------------------------------------------------------------------------------------------------\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "These options change a mode or limit the results.\n\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "-------------------------------------------------------------------------------------------------------------\n")
		fmt.Fprintf(os.Stderr, "Transformation Modes:\n")
		fmt.Fprintf(os.Stderr, "Use the -t flag to select a mode. Each mode does a different change to the input.\n\n")
		modes := map[string]string{
			"rule-append":                           "Make Hashcat append rules from the input. Alias: append.",
			"rule-append-remove":                    "Make append-remove rules from the input. Alias: append-remove.",
			"rule-prepend":                          "Make Hashcat prepend rules from the input. Alias: prepend.",
			"rule-prepend-remove":                   "Make prepend-remove rules from the input. Alias: prepend-remove.",
			"rule-prepend-toggle":                   "Make prepend-toggle rules from the input. Alias: prepend-toggle.",
			"rule-insert -i [index]":                "Make insert rules that start at the index. Alias: insert.",
			"rule-overwrite -i [index]":             "Make overwrite rules that start at the index. Alias: overwrite.",
			"rule-toggle -i [index]":                "Make toggle rules that start at the index. Alias: toggle.",
			"encode":                                "Encode the input as HTML entities and Unicode escape sequences.",
			"decode":                                "Decode HTML entities and Unicode escape sequences in the input.",
			"hex":                                   "Encode the input strings in the $HEX[...] format.",
			"dehex":                                 "Decode the $HEX[...] strings in the input.",
			"mask -rm [uldsb] -v":                   "Replace characters in the input with a mask.",
			"mask-remove -rm [uldsb]":               "Remove the characters that a mask selects. Alias: remove.",
			"mask-retain -rm [uldsb] -tf [file] -v": "Make masks that keep the strings from a file. Alias: retain.",
			"mask-pop -rm [uldsbt]":                 "Divide the input at character boundaries and keep the tokens. Alias: pop.",
			"mask-match -tf [file]":                 "Keep only the input strings that match a mask from a mask file. Alias: match.",
			"mask-swap -tf [file]":                  "Swap the tokens in mask or partial mask input with tokens from a file.",
			"passphrase -w [words]":                 "Make passphrases from sentences. Each passphrase has the number of words that you set.",
			"regram -w [words]":                     "Make new n-grams from sentences. Each n-gram has the number of words that you set.",
			"brainstorm -w [range] -l [range] [-unicode]": "Make n-grams in title case, with and without apostrophes, in a length range.",
			"analyze": "Calculate metadata for the input. Alias: analyzer.",
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
		fmt.Fprintf(os.Stderr, "Note: Use -t <mode> -h to see more data and examples for that mode.\n")
	}

	verbose := flag.Bool("v", false, "Show more output, if possible. Some modes add metadata to each item.")
	verbose2 := flag.Bool("vv", false, "Show output statistics, if possible.")
	verbose3 := flag.Bool("vvv", false, "Show more statistics for the output, if possible.")
	minimum := flag.Int("m", 0, "Remove items from the output if their frequency is less than this number.")
	minComplexity := flag.Int("mc", 0, "Remove input items with a complexity score less than this number, before the transformation. The score is from 1 to 5. It counts the character types: lowercase, uppercase, digit, special, and byte.")
	outputVerboseMax := flag.Int("n", 0, "Set the maximum number of items in the output.")
	transformation := flag.String("t", "", "Set the transformation mode to apply to the input.")
	replacementMask := flag.String("rm", "uldsbt", "Set the mask characters for the modes that use a mask.")
	jsonOutput := flag.String("o", "", "Set the output path. For most modes it is a JSON file. For the analyze mode it is a directory.")
	bypassMap := flag.Bool("b", false, "Transform the input in batches. The tool writes the results to standard output after each batch. The memory use does not increase when the input is large. The tool removes duplicate items only in the same batch. The -k, -r, -m, -n, -ic, -vv, -vvv, and -o options do not work with this flag.")
	workers := flag.Int("p", 0, "Set the number of workers for the -b flag. The workers transform batches at the same time. The default is one worker for each CPU.")
	debugMode := flag.Int("d", 0, "Set the debug level, from 0 to 2. A higher level shows more debug messages.")
	ignoreCase := flag.Bool("ic", false, "Change all output to lowercase. Items that are the same in lowercase become one item.")
	includeNonLatin := flag.Bool("unicode", false, "Keep the lines that have non-Latin letters. The brainstorm mode does not do the Latin vowel check on these lines.")
	flag.Var(&retain, "k", "Keep only the items that are in a file.")
	flag.Var(&remove, "r", "Keep only the items that are not in a file.")
	flag.Var(&readFiles, "f", "Read the input from a file or directory. Use this flag more than one time to read more files.")
	flag.Var(&transformationFiles, "tf", "Read a transformation file or directory for the modes that use one. You can use this flag more than one time.")
	flag.Var(&intRange, "i", "Set the start index for the modes that use an index. The value can be a range, for example 1-5.")
	flag.Var(&lenRange, "l", "Write only the items with a length in this range, for example 4-20. For rules, the length is the length of the rule text.")
	flag.Var(&wordRange, "w", "Set the number of words for the modes that use a word count. The value can be a range, for example 2-4.")
	flag.Parse()

	if *workers < 0 {
		fmt.Fprintf(os.Stderr, "[!] The -p flag must not be negative.\n")
		os.Exit(1)
	}

	if *bypassMap && *transformation == "analyze" {
		fmt.Fprintf(os.Stderr, "[!] The analyze mode needs all of the input at once, so the -b flag is ignored.\n")
		*bypassMap = false
	}

	if !*bypassMap {
		flag.Visit(func(f *flag.Flag) {
			if f.Name == "p" {
				fmt.Fprintf(os.Stderr, "[!] The -p flag only applies with the -b flag, so it is ignored.\n")
			}
		})
	}

	if *bypassMap {
		fmt.Fprintf(os.Stderr, "[*] Bypassing map creation and streaming input to standard output. Memory use does not grow with input size. Duplicates are only removed within a batch of input, pipe to 'sort -u' to remove them all.\n")
		var ignored []string
		flag.Visit(func(f *flag.Flag) {
			switch f.Name {
			case "k", "r", "m", "n", "ic", "vv", "vvv", "o":
				ignored = append(ignored, "-"+f.Name)
			}
		})
		if len(ignored) > 0 {
			fmt.Fprintf(os.Stderr, "[!] Ignoring options that do not apply with -b: %s.\n", strings.Join(ignored, ", "))
		}
	}

	if *debugMode > 0 {
		fmt.Fprintf(os.Stderr, "[*] Debug mode enabled with verbosity level %d.\n", *debugMode)
	}

	fs := &models.RealFileSystem{}

	if *bypassMap {
		stat, _ := os.Stdin.Stat()
		err = bypass.Run(bypass.Options{
			Transformation:      *transformation,
			StartIndex:          intRange.Start,
			EndIndex:            intRange.End,
			Verbose:             *verbose,
			ReplacementMask:     *replacementMask,
			Debug:               *debugMode,
			WordStart:           wordRange.Start,
			WordEnd:             wordRange.End,
			LengthStart:         lenRange.Start,
			LengthEnd:           lenRange.End,
			IncludeNonLatin:     *includeNonLatin,
			MinComplexity:       *minComplexity,
			Files:               readFiles,
			TransformationFiles: transformationFiles,
			Workers:             *workers,
		}, fs, os.Stdin, (stat.Mode()&os.ModeCharDevice) == 0)
		switch {
		case errors.Is(err, bypass.ErrNoInput):
			fmt.Fprintf(os.Stderr, "[!] No input provided. Exiting.\n")
		case errors.Is(err, bypass.ErrNoItems):
			fmt.Fprintf(os.Stderr, "[!] No items remaining after complexity filter. Exiting.\n")
		case err != nil:
			fmt.Fprintf(os.Stderr, "[!] Error: %s.\n", err)
			os.Exit(1)
		}
		return
	}

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

	inputLines = make([]string, 0, len(primaryMap))
	for key := range primaryMap {
		inputLines = append(inputLines, key)
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

	if *transformation == "analyze" {
		analyzeMode = true
	}

	if *transformation != "" && !analyzeMode {
		primaryMap = transform.TransformationController(primaryMap, *transformation, intRange.Start, intRange.End, *verbose, *replacementMask, transformationFilesMap, *bypassMap, *debugMode, wordRange.Start, wordRange.End, lenRange.Start, lenRange.End, *includeNonLatin)
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

	if analyzeMode {
		summary := analyze.Analyze(inputLines)
		analyze.PrintSummary(summary, len(inputLines), *verbose)

		if *jsonOutput != "" {
			fmt.Fprintf(os.Stderr, "[*] Saving analyzer artifacts (full masks, partial masks, rules) to directory: %s.\n", *jsonOutput)
			written, err := analyze.WriteArtifacts(summary, *jsonOutput)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] Error writing analyzer artifacts: %s.\n", err)
				return
			}
			for _, p := range written {
				fmt.Fprintf(os.Stderr, "[*] Wrote artifact: %s\n", p)
			}
		}
	} else if *verbose3 {
		format.PrintStatsToSTDOUT(primaryMap, *verbose3, *outputVerboseMax)
	} else if *verbose2 {
		format.PrintStatsToSTDOUT(primaryMap, *verbose3, *outputVerboseMax)
	} else {
		format.PrintArrayToSTDOUT(primaryMap, *verbose)
	}

	if *jsonOutput != "" && !analyzeMode {
		fmt.Fprintf(os.Stderr, "[*] Saving output to JSON file: %s.\n", *jsonOutput)
	}

	if *jsonOutput != "" && !analyzeMode {
		err = format.SaveArrayToJSON(*jsonOutput, primaryMap)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error saving output to JSON: %s.\n", err)
			return
		}
	}
}
