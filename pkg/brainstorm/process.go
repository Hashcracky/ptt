// Package brainstorm contains the brainstorm transformation mode for PTT.
//
// This package adapts the logic from the brainstorm application (github.com/hashcracky/brainstorm)
// into PTT's map-based transformation pipeline.
package brainstorm

import (
	"fmt"
	"os"
	"strings"
)

// ProcessLines takes a slice of input lines and applies the brainstorm
// transformation to each line, returning the transformed output lines.
func ProcessLines(lines []string, cfg *Config) []string {
	var output []string

	for _, line := range lines {
		transformed := TransformLine(cfg, line)
		if transformed == "" {
			continue
		}

		splitLines := strings.Split(transformed, "\n")
		for _, splitLine := range splitLines {
			if splitLine != "" {
				output = append(output, splitLine)
			}
		}
	}

	return output
}

// ProcessBrainstormMap takes a map of input keys and values and applies the
// brainstorm transformation to each key, returning a new map with the
// transformed keys and their associated values.
//
// Args:
//   input (map[string]int): The original map to transform.
//   wordRangeStart (int): The starting n-gram word count. If 0, defaults to 1.
//   wordRangeEnd (int): The ending n-gram word count. If 0, defaults to 5.
//   outMinLength (int): The minimum output length. If 0, defaults to 4.
//   outMaxLength (int): The maximum output length. If 0, defaults to 32.
//   bypass (bool): If true, print transformed lines directly to stdout instead
//   of building a result map.
//   debug (bool): If true, print additional debug information to stderr.
//   includeNonLatin (bool): If true, relax Latin vowel heuristics to include
//   non-Latin multi-byte letter sequences.
//
// Returns:
//   (map[string]int): A new map with the transformed keys and their values.
func ProcessBrainstormMap(input map[string]int, wordRangeStart int, wordRangeEnd int, outMinLength int, outMaxLength int, bypass bool, debug bool, includeNonLatin bool) map[string]int {
	// Default n-gram range mirrors brainstorm's default flag (1-5).
	if wordRangeStart == 0 && wordRangeEnd == 0 {
		wordRangeStart = 1
		wordRangeEnd = 5
	}

	// Default output length range mirrors brainstorm's default flag (4-32).
	if outMinLength == 0 && outMaxLength == 0 {
		outMinLength = 4
		outMaxLength = 32
	}

	cfg := &Config{
		NGramMin:        wordRangeStart,
		NGramMax:        wordRangeEnd,
		OutMinLength:    outMinLength,
		OutMaxLength:    outMaxLength,
		IncludeNonLatin: includeNonLatin,
	}

	newMap := make(map[string]int)

	for key, value := range input {
		transformed := TransformLine(cfg, key)
		if transformed == "" {
			continue
		}

		if debug {
			fmt.Fprintf(os.Stderr, "Key: %s\n", key)
			fmt.Fprintf(os.Stderr, "Transformed: %s\n", transformed)
		}

		splitLines := strings.Split(transformed, "\n")
		for _, newKey := range splitLines {
			newKey = strings.TrimSpace(newKey)
			if newKey == "" {
				continue
			}

			if !bypass {
				if newMap[newKey] == 0 {
					newMap[newKey] = value
				} else {
					newMap[newKey] += value
				}
			} else {
				fmt.Println(newKey)
			}
		}
	}

	return newMap
}
