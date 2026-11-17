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
Usage of Password Transformation Tool (ptt) version (1.3.1):

ptt [options]
The tool reads standard input. It also reads the files that you give.

You can use the -f, -k, -r, and -tf flags more than one time. You can use them together.
Each of these flags accepts files and directories.
-------------------------------------------------------------------------------------------------------------
Options:
These options change a mode or limit the results.

  -b	Transform the input in batches. The tool writes the results to standard output after each batch. The memory use does not increase when the input is large. The tool removes duplicate items only in the same batch. The -k, -r, -m, -n, -ic, -vv, -vvv, and -o options do not work with this flag.
  -d int
    	Set the debug level, from 0 to 2. A higher level shows more debug messages.
  -f value
    	Read the input from a file or directory. Use this flag more than one time to read more files.
  -i value
    	Set the start index for the modes that use an index. The value can be a range, for example 1-5.
  -ic
    	Change all output to lowercase. Items that are the same in lowercase become one item.
  -k value
    	Keep only the items that are in a file.
  -l value
    	Write only the items with a length in this range, for example 4-20. For rules, the length is the length of the rule text.
  -m int
    	Remove items from the output if their frequency is less than this number.
  -mc int
    	Remove input items with a complexity score less than this number, before the transformation. The score is from 1 to 5. It counts the character types: lowercase, uppercase, digit, special, and byte.
  -n int
    	Set the maximum number of items in the output.
  -o string
    	Set the output path. For most modes it is a JSON file. For the analyze mode it is a directory.
  -p int
    	Set the number of workers for the -b flag. The workers transform batches at the same time. The default is one worker for each CPU.
  -r value
    	Keep only the items that are not in a file.
  -rm string
    	Set the mask characters for the modes that use a mask. (default "uldsbt")
  -t string
    	Set the transformation mode to apply to the input.
  -tf value
    	Read a transformation file or directory for the modes that use one. You can use this flag more than one time.
  -unicode
    	Keep the lines that have non-Latin letters. The brainstorm mode does not do the Latin vowel check on these lines.
  -v	Show more output, if possible. Some modes add metadata to each item.
  -vv
    	Show output statistics, if possible.
  -vvv
    	Show more statistics for the output, if possible.
  -w value
    	Set the number of words for the modes that use a word count. The value can be a range, for example 2-4.
-------------------------------------------------------------------------------------------------------------
Transformation Modes:
Use the -t flag to select a mode. Each mode does a different change to the input.

  -t analyze
	Calculate metadata for the input. Alias: analyzer.
  -t brainstorm -w [range] -l [range] [-unicode]
	Make n-grams in title case, with and without apostrophes, in a length range.
  -t decode
	Decode HTML entities and Unicode escape sequences in the input.
  -t dehex
	Decode the $HEX[...] strings in the input.
  -t encode
	Encode the input as HTML entities and Unicode escape sequences.
  -t hex
	Encode the input strings in the $HEX[...] format.
  -t mask -rm [uldsb] -v
	Replace characters in the input with a mask.
  -t mask-match -tf [file]
	Keep only the input strings that match a mask from a mask file. Alias: match.
  -t mask-pop -rm [uldsbt]
	Divide the input at character boundaries and keep the tokens. Alias: pop.
  -t mask-remove -rm [uldsb]
	Remove the characters that a mask selects. Alias: remove.
  -t mask-retain -rm [uldsb] -tf [file] -v
	Make masks that keep the strings from a file. Alias: retain.
  -t mask-swap -tf [file]
	Swap the tokens in mask or partial mask input with tokens from a file.
  -t passphrase -w [words]
	Make passphrases from sentences. Each passphrase has the number of words that you set.
  -t regram -w [words]
	Make new n-grams from sentences. Each n-gram has the number of words that you set.
  -t rule-append
	Make Hashcat append rules from the input. Alias: append.
  -t rule-append-remove
	Make append-remove rules from the input. Alias: append-remove.
  -t rule-insert -i [index]
	Make insert rules that start at the index. Alias: insert.
  -t rule-overwrite -i [index]
	Make overwrite rules that start at the index. Alias: overwrite.
  -t rule-prepend
	Make Hashcat prepend rules from the input. Alias: prepend.
  -t rule-prepend-remove
	Make prepend-remove rules from the input. Alias: prepend-remove.
  -t rule-prepend-toggle
	Make prepend-toggle rules from the input. Alias: prepend-toggle.
  -t rule-toggle -i [index]
	Make toggle rules that start at the index. Alias: toggle.
-------------------------------------------------------------------------------------------------------------
Note: Use -t <mode> -h to see more data and examples for that mode.
```
