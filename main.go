// Package main controls the user interaction logic for the application
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

var version = "1.1.0"
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

func main() {
	flag.Usage = func() {
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
			"rule-append":                           "Transforms input by creating append rules.",
			"rule-append-remove":                    "Transforms input by creating append-remove rules.",
			"rule-prepend":                          "Transforms input by creating prepend rules.",
			"rule-prepend-remove":                   "Transforms input by creating prepend-remove rules.",
			"rule-prepend-toggle":                   "Transforms input by creating prepend-toggle rules.",
			"rule-insert -i [index]":                "Transforms input by creating insert rules starting at index.",
			"rule-overwrite -i [index]":             "Transforms input by creating overwrite rules starting at index.",
			"rule-toggle -i [index]":                "Transforms input by creating toggle rules starting at index.",
			"encode":                                "Transforms input by HTML and Unicode escape encoding.",
			"decode":                                "Transforms input by HTML and Unicode escape decoding.",
			"hex":                                   "Transforms input by encoding strings into $HEX[...] format.",
			"dehex":                                 "Transforms input by decoding $HEX[...] formatted strings.",
			"mask -rm [uldsb] -v":                   "Transforms input by masking characters with provided mask.",
			"mask-remove -rm [uldsb]":               "Transforms input by removing characters with provided mask.",
			"mask-retain -rm [uldsb] -tf [file] -v": "Transforms input by creating masks that still retain strings from file.",
			"mask-pop -rm [uldsbt]":                 "Transforms input by 'popping' tokens from character boundaries using the provided mask.",
			"mask-match -tf [file]":                 "Transforms input by keeping only strings with matching masks from a mask file.",
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
