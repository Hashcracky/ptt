 Password Transformation Tool (`ptt`) is a versatile utility designed for password cracking. It facilitates the creation of custom rules and transformations, as well as the generation of wordlists. This tool supports processing data from files and standard input, streamlining cracking workflows.

`PTT` is written in `Go`, is compatible with multiple platforms, and can be easily integrated into existing workflows. The tool is designed to be user-friendly and intuitive, with a wide range of features and options.

## Features:
- **Multiple Input Sources:** Process data from files and standard input. Accepts directories and files as input. Use multiple flags to combine sources.
- **Deduplication and Frequency Filtering:** Remove duplicates and filter by
  frequency automatically.
- **Output Formatting:** Output data in JSON format for easy parsing and
  analysis. Easily load and chain previous results for further processing.
- **Debugging Mode:** Enable debug mode to display verbose output and
  statistics with multiple levels of verbosity.
- **Transformation Modes:** Choose from various transformation modes to
  manipulate input data.
- **Wordlist Generation:** Generate wordlists from input data using custom rules
  and transformations.
- **Rule Creation:** Create custom rules for appending, prepending,
  overwriting, and toggling strings.
- **Mask Making:** Create `Hashcat` masks to mask, remove, retain, or swap characters
  in strings.
- **Multibyte Support:** Support for multibyte characters in transformations.
- **Analysis Tools:** Analyze input data with statistics and verbose output.
- **Complexity Filtering:** Filter input items by password complexity score before processing.

## Getting Started:

Usage documentation can be found in the `/docs/USAGE.md` directory or on the repository here:
- [GitHub Link](https://github.com/hashcracky/ptt/tree/main/docs/USAGE.md)

### Install:

From source with `go`:
```
go install github.com/hashcracky/ptt@latest
```
From `git` clone then build with `go`:
```
git clone https://github.com/hashcracky/ptt && cd ptt && go build ./main.go && mv ./main ~/go/bin/ptt && ptt
```
From `git` then build with `docker`:
```
git clone https://github.com/hashcracky/ptt && cd ptt && docker build -t ptt . && docker run -it -v ${PWD}:/data ptt
```

---
### Usage:
```
Usage of Password Transformation Tool (ptt) version (1.1.0):

ptt [options] [...]
Accepts standard input and/or additonal arguments.

The -f, -k, -r, and -tf flags can be used multiple times, together, and with files or directories.
-------------------------------------------------------------------------------------------------------------
Options:
These modify or filter the transformation mode.

  -b    Bypass map creation and use stdout as primary output. Disables some options.
  -d int
        Enable debug mode with verbosity levels [0-2].
  -f value
        Read additional files for input.
  -i value
        Starting index for transformations if applicable. Accepts ranges separated by '-'.
  -ic
        Ignore case when processing output and converts all output to lowercase.
  -k value
        Only keep items in a file.
  -l value
        Only output items of a certain length (does not adjust for rules). Accepts ranges separated by '-'.
  -m int
        Minimum numerical frequency to include in output.
  -mc int
        Minimum complexity score to include before processing (lowercase, uppercase, digits, specials, bytes) [1-5].
  -n int
        Maximum number of items to return in output.
  -o string
        Output to JSON file in addition to stdout. Accepts file names and paths.
  -r value
        Only keep items not in a file.
  -rm string
        Replacement mask for transformations if applicable. (default "uldsbt")
  -t string
        Transformation to apply to input.
  -tf value
        Read additional files for transformations if applicable.
  -v    Show verbose output when possible. (Can show additional metadata in some modes.)
  -vv
        Show statistics output when possible.
  -vvv
        Show verbose statistics output when possible.
  -w value
        Number of words for transformations if applicable. Accepts ranges separated by '-'.
-------------------------------------------------------------------------------------------------------------
Transformation Modes:
These create or alter based on the selected mode.

  -t decode
        Transforms input by HTML and Unicode escape decoding.
  -t dehex
        Transforms input by decoding $HEX[...] formatted strings.
  -t encode
        Transforms input by HTML and Unicode escape encoding.
  -t hex
        Transforms input by encoding strings into $HEX[...] format.
  -t mask -rm [uldsb] -v
        Transforms input by masking characters with provided mask.
  -t mask-match -tf [file]
        Transforms input by keeping only strings with matching masks from a mask file. (alias: match)
  -t mask-pop -rm [uldsbt]
        Transforms input by 'popping' tokens from character boundaries using the provided mask. (alias: pop)
  -t mask-remove -rm [uldsb]
        Transforms input by removing characters with provided mask. (alias: remove)
  -t mask-retain -rm [uldsb] -tf [file] -v
        Transforms input by creating masks that still retain strings from file. (alias: retain)
  -t mask-swap -tf [file]
        Transforms input by swapping tokens from a mask/partial mask input and a transformation file of tokens.
  -t passphrase -w [words]
        Transforms input by generating passphrases from sentences with a given number of words.
  -t regram -w [words]
        Transforms input by 'regramming' sentences into new n-grams with a given number of words.
  -t rule-append
        Transforms input by creating append rules. (alias: append)
  -t rule-append-remove
        Transforms input by creating append-remove rules. (alias: append-remove)
  -t rule-insert -i [index]
        Transforms input by creating insert rules starting at index. (alias: insert)
  -t rule-overwrite -i [index]
        Transforms input by creating overwrite rules starting at index. (alias: overwrite)
  -t rule-prepend
        Transforms input by creating prepend rules. (alias: prepend)
  -t rule-prepend-remove
        Transforms input by creating prepend-remove rules. (alias: prepend-remove)
  -t rule-prepend-toggle
        Transforms input by creating prepend-toggle rules. (alias: prepend-toggle)
  -t rule-toggle -i [index]
        Transforms input by creating toggle rules starting at index. (alias: toggle)
-------------------------------------------------------------------------------------------------------------
Tip: Use -t <mode> -h for detailed help and examples on a specific mode.
```
