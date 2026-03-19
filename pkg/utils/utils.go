// Package utils provides utility functions for the application.
package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/hashcracky/ptt/pkg/models"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// ----------------------------------------------------------------------------
// Loading and Processing Functions
// ----------------------------------------------------------------------------

// TrackLoadTime tracks the time it takes to load the input and prints the time
//
// Args:
// done (chan bool): channel to use to track tasks
// work (string): string used in status printing
//
// Returns:
// None
func TrackLoadTime(done <-chan bool, work string) {
	start := time.Now()
	ticker := time.NewTicker(30 * time.Second)
	for {
		select {
		case <-done:
			ticker.Stop()
			fmt.Fprintf(os.Stderr, "[-] Total %s Time: %02d:%02d:%02d.\n", work, int(time.Since(start).Hours()), int(time.Since(start).Minutes())%60, int(time.Since(start).Seconds())%60)
			return
		case t := <-ticker.C:
			elapsed := t.Sub(start)
			memUsage := GetMemoryUsage()
			fmt.Fprintf(os.Stderr, "[-] Please wait loading. Elapsed: %02d:%02d:%02d.%03d. Memory Usage: %.2f MB.\n", int(t.Sub(start).Hours()), int(t.Sub(start).Minutes())%60, int(t.Sub(start).Seconds())%60, elapsed.Milliseconds()%1000, memUsage)
		}
	}
}

// GetMemoryUsage returns the current memory usage in megabytes
func GetMemoryUsage() float64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return float64(m.Alloc) / 1024 / 1024
}

// ReadFilesToMap reads the contents of the multiple files and returns a map of words
//
// Args:
//
//	fs (FileSystem): The filesystem to read the files from (used for testing)
//	filenames ([]string): The names of the files to read
//
// Returns:
//
//	(map[string]int): A map of words from the files
func ReadFilesToMap(fs models.FileSystem, filenames []string) map[string]int {
	wordMap := make(map[string]int)
	// 1 GB read buffer
	chunkSize := int64(1 * 1024 * 1024 * 1024)

	i := 0
	for i < len(filenames) {
		filename := filenames[i]
		if IsFileSystemDirectory(filename) {
			files, err := GetFilesInDirectory(filename)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] Error reading the directory %v: %v.\n", filename, err)
				os.Exit(1)
			}
			filenames = append(filenames, files...)
		} else {
			file, err := fs.Open(filename)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] Error opening file %s.\n", filename)
				os.Exit(1)
			}
			defer file.Close()

			buffer := make([]byte, chunkSize)
			for {
				bytesRead, err := file.Read(buffer)
				if err != nil && err != io.EOF {
					fmt.Fprintf(os.Stderr, "[!] Error reading file %s.\n", filename)
					os.Exit(1)
				}
				if bytesRead == 0 {
					break
				}

				data := buffer[:bytesRead]

				err = json.Unmarshal(data, &wordMap)
				if err == nil {
					fmt.Fprintf(os.Stderr, "[*] Detected ptt JSON output. Importing...\n")
					continue
				}

				fileWords := strings.Split(string(data), "\n")
				for _, word := range fileWords {
					wordMap[word]++
				}

				if err == io.EOF {
					break
				}
			}
		}
		i++
	}

	// Remove empty strings from the map
	delete(wordMap, "")

	return wordMap
}

// LoadStdinToMap reads the contents of stdin and returns a map[string]int
// where the key is the line and the value is the frequency of the line
// in the input
//
// Args:
//
//	scanner (models.Scanner): The scanner to read from stdin
//
// Returns:
//
//	map[string]int: A map of lines from stdin
//	error: An error if one occurred
func LoadStdinToMap(scanner models.Scanner) (map[string]int, error) {
	m := make(map[string]int)
	pttInput := false
	line0 := false
	reDetect := regexp.MustCompile(`^\d+\s(\w+|\W+)$`)
	reParse := regexp.MustCompile(`^\d+`)

	for scanner.Scan() {
		if scanner.Text() == "" {
			continue
		}

		// Detect ptt -v output
		if matched := reDetect.MatchString(scanner.Text()); matched && pttInput == false && line0 == false {
			fmt.Fprintf(os.Stderr, "[*] Detected ptt -v output. Importing...\n")
			pttInput = true
		}

		if pttInput {
			line := scanner.Text()
			match := reParse.FindString(line)
			value, err := strconv.Atoi(match)
			if err != nil {
				return nil, err
			}
			newLine := strings.TrimSpace(strings.Replace(line, match, "", 1))
			m[newLine] += value

		} else {
			line := scanner.Text()
			m[line]++
		}
		line0 = true
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return m, nil
}

// CombineMaps combines any number of maps into a single map combining values for common keys
// and returning a new map
//
// Args:
// maps ([]map[string]int): The maps to combine
//
// Returns:
// map[string]int: A new map combining the values of the input maps
func CombineMaps(maps ...map[string]int) map[string]int {
	var result sync.Map

	for _, m := range maps {
		for k, v := range m {
			if val, ok := result.Load(k); ok {
				result.Store(k, val.(int)+v)
			} else {
				result.Store(k, v)
			}
		}
	}

	finalResult := make(map[string]int)
	result.Range(func(k, v interface{}) bool {
		finalResult[k.(string)] = v.(int)
		return true
	})

	return finalResult
}

// ----------------------------------------------------------------------------
// Transformation Functions
// ----------------------------------------------------------------------------

// ReverseString will return a string in reverse
//
// Args:
//
//	str (string): Input string to transform
//
// Returns:
//
//	(string): Transformed string
func ReverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// ConvertMultiByteCharToRule converts non-ascii characters to a hashcat valid format
// for rule.CharToRule functions
//
// Args:
//
//	str (string): Input string to transform
//
// Returns:
//
//	returnStr (string): Converted string
func ConvertMultiByteCharToRule(str string) string {
	returnStr := ""
	deletedChar := ``
	for i, r := range str {
		if r > 127 {
			if i > 0 {
				deletedChar = string(returnStr[len(returnStr)-1])
				returnStr = returnStr[:len(returnStr)-1]
			}
			byteArr := []byte(string(r))
			if deletedChar == "^" {
				for j := len(byteArr) - 1; j >= 0; j-- {
					b := byteArr[j]
					if j == 0 {
						returnStr += fmt.Sprintf("%s\\x%X", deletedChar, b)
					} else {
						returnStr += fmt.Sprintf("%s\\x%X ", deletedChar, b)
					}
				}
			} else {
				for j, b := range byteArr {
					if j == len(byteArr)-1 {
						returnStr += fmt.Sprintf("%s\\x%X", deletedChar, b)
					} else {
						returnStr += fmt.Sprintf("%s\\x%X ", deletedChar, b)
					}
				}
			}
		} else {
			returnStr += fmt.Sprintf("%c", r)
		}
	}
	return returnStr
}

// IncrementIteratingRuleCall increments the last character of a string for
// rules.CharToIteratingRules functions
//
// For example, "i4" will be incremented to "i5", "iA" will be incremented to
// "IB"
//
// Args:
//
//	s (string): Input string to increment
//
// Returns:
//
//	output (string): Incremented string
func IncrementIteratingRuleCall(s string) string {
	if len(s) == 0 {
		return s
	}

	lastChar := s[len(s)-1]
	incChar := lastChar + 1

	// Replace the last character with the incremented character
	output := s[:len(s)-1] + string(incChar)

	return output
}

// ConvertMultiByteCharToIteratingRule converts non-ascii characters to a hashcat valid format
// for rule.CharToIteratingRule functions
//
// Args:
//
//	index (int): Index to start the iteration
//	str (string): Input string to transform
//
// Returns:
//
//	returnStr (string): Converted string
func ConvertMultiByteCharToIteratingRule(index int, str string) string {
	output := ""
	lastIterationSeen := fmt.Sprintf("%s%d", string([]rune(str)[0]), index)

	re := regexp.MustCompile(`[io][\dA-Z]`)

	for _, word := range strings.Split(str, " ") {
		for _, c := range word {
			if c > 127 {
				// Convert to UTF-8 bytes
				bytes := []byte(string(c))
				firstByteOut := true
				// Convert each byte to its hexadecimal representation
				for i, b := range bytes {
					if firstByteOut {
						output += fmt.Sprintf("\\x%X ", b)
						firstByteOut = false
						continue
					}
					lastIterationSeen = IncrementIteratingRuleCall(lastIterationSeen)
					if i == len(bytes)-1 {
						output += fmt.Sprintf("%s\\x%X", lastIterationSeen, b)
					} else {
						output += fmt.Sprintf("%s\\x%X ", lastIterationSeen, b)
					}
				}
			} else {
				output += string(c)
				if len(output) > 2 && re.MatchString(output[len(output)-2:]) {
					lastIterationSeen = output[len(output)-2:]
				}
			}
		}
		output += " "
	}

	return output
}

// SplitBySeparatorString splits a string by a separator string and returns a slice
// with the separator string included
//
// Args:
//
//	s (string): The string to split
//	sep (string): The separator string
//
// Returns:
//
//	[]string: A slice of strings with the separator string included
func SplitBySeparatorString(s string, sep string) []string {
	if !strings.Contains(s, sep) {
		return []string{s}
	}

	// Limit to 2 to ensure we only split on the first instance of the separator
	parts := strings.SplitN(s, sep, 2)
	parts = append(parts[:1], append([]string{sep}, parts[1:]...)...)
	return parts
}
// GenerateNGrams generates n-grams from a string of text
// and returns a slice of n-grams
//
// Args:
// text (string): The text to generate n-grams from
// n (int): The number of words in each n-gram
//
// Returns:
// []string: A slice of n-grams
func GenerateNGrams(text string, n int) []string {
	words := strings.Fields(text)
	var nGrams []string

	for i := 0; i <= len(words)-n; i++ {
		nGram := strings.Join(words[i:i+n], " ")
		nGrams = append(nGrams, nGram)
	}

	return nGrams
}

// GeneratePassphrase generates a passphrase from a string of text
// and returns a slice of passphrases
//
// Args:
// text (string): The text to generate passphrases from
// n (int): The number of words in the passphrase
//
// Returns:
// []string: A slice of passphrases
func GeneratePassphrase(text string, n int) []string {
	text = strings.ReplaceAll(text, ".", "")
	text = strings.ReplaceAll(text, ",", "")
	text = strings.ReplaceAll(text, ";", "")
	words := strings.Fields(text)
	var passphrases []string

	if len(words) != n {
		return passphrases
	}

	var titleCaseWords string
	var turkTitleCaseWords string
	var CAPSlowerWords []string
	var lowerCAPSWords []string
	tick := false
	titleCaseWords = cases.Title(language.Und, cases.NoLower).String(text)
	turkTitleCaseWords = cases.Upper(language.Turkish, cases.NoLower).String(text)

	for _, word := range words {

		if tick {
			CAPSlowerWords = append(CAPSlowerWords, strings.ToUpper(word))
			lowerCAPSWords = append(lowerCAPSWords, strings.ToLower(word))
		} else {
			CAPSlowerWords = append(CAPSlowerWords, strings.ToLower(word))
			lowerCAPSWords = append(lowerCAPSWords, strings.ToUpper(word))
		}

		tick = !tick

	}

	passphrases = append(passphrases, strings.ReplaceAll(titleCaseWords, " ", ""))
	passphrases = append(passphrases, strings.ReplaceAll(turkTitleCaseWords, " ", ""))
	passphrases = append(passphrases, strings.ReplaceAll(titleCaseWords, " ", "-"))
	passphrases = append(passphrases, strings.ReplaceAll(turkTitleCaseWords, " ", "-"))
	passphrases = append(passphrases, strings.ReplaceAll(titleCaseWords, " ", "_"))
	passphrases = append(passphrases, strings.ReplaceAll(turkTitleCaseWords, " ", "_"))
	passphrases = append(passphrases, strings.Join(CAPSlowerWords, " "))
	passphrases = append(passphrases, strings.Join(CAPSlowerWords, ""))
	passphrases = append(passphrases, strings.Join(lowerCAPSWords, " "))
	passphrases = append(passphrases, strings.Join(lowerCAPSWords, ""))
	passphrases = append(passphrases, strings.ReplaceAll(text, " ", ""))
	passphrases = append(passphrases, titleCaseWords)
	passphrases = append(passphrases, turkTitleCaseWords)

	return passphrases
}

// ----------------------------------------------------------------------------
// Validation Functions
// ----------------------------------------------------------------------------

// CheckASCIIString checks to see if a string only contains ascii characters
//
// Args:
//
//	str (string): Input string to check
//
// Returns:
//
//	(bool): If the string only contained ASCII characters
func CheckASCIIString(str string) bool {
	if utf8.RuneCountInString(str) != len(str) {
		return false
	}
	return true
}

// CheckHexString is used to identify plaintext in the $HEX[...] format
//
// Args:
//
//	s (str): The string to be evaluated
//
// Returns:
//
//	(bool): Returns true if it matches and false if it did not
func CheckHexString(s string) bool {
	var validateInput = regexp.MustCompile(`^\$HEX\[[a-zA-Z0-9]*\]$`).MatchString
	if validateInput(s) == false {
		return false
	}
	return true
}

// CheckAreMapsEqual checks if two maps are equal by comparing the length of the maps
// and the values of the keys in the maps. If the maps are equal, the function returns
// true, otherwise it returns false.
//
// Args:
//
//	a (map[string]int): The first map to compare
//	b (map[string]int): The second map to compare
//
// Returns:
//
//	bool: True if the maps are equal, false otherwise
func CheckAreMapsEqual(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || v != w {
			return false
		}
	}
	return true
}

// CheckAreArraysEqual checks if two arrays are equal by comparing the length of the arrays
// and the values of the elements in the arrays. If the arrays are equal, the function returns
// true, otherwise it returns false.
//
// Args:
// a ([]string): The first array to compare
// b ([]string): The second array to compare
//
// Returns:
// bool: True if the arrays are equal, false otherwise
func CheckAreArraysEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sort.Strings(a)
	sort.Strings(b)
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

// IsFileSystemDirectory checks to see if a string is a valid file system
// directory by checking if the path exists and if it is a directory
//
// Args:
//
//	path (string): The path to check
//
// Returns:
//
//	bool: True if the path is a directory, false otherwise
func IsFileSystemDirectory(path string) bool {
	fileInfo, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return fileInfo.IsDir()
}

// GetFilesInDirectory returns a slice of files in a directory
// by reading the directory and appending the files to a slice
// if they are not directories
//
// Args:
// dir (string): The directory to read
//
// Returns:
// []string: A slice of files in the directory
func GetFilesInDirectory(dir string) ([]string, error) {
	var files []string
	items, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, item := range items {
		if !item.IsDir() {
			files = append(files, filepath.Join(dir, item.Name()))
		}
	}

	return files, nil
}

// IsValidFile checks if a file exists and is not a directory
// by checking if the file exists
//
// Args:
// path (string): The path to the file
//
// Returns:
// bool: True if the file is valid, false otherwise
func IsValidFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
