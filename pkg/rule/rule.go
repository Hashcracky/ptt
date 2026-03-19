package rule

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode"

	"github.com/hashcracky/ptt/pkg/utils"
)

const hexDigits = "0123456789ABCDEF"

// shouldEncodeAsHex reports whether a rune in a plaintext input must be
// hex-encoded in Hashcat rule syntax to avoid delimiter ambiguity.
// This applies to multi-byte characters (>127), spaces, and tabs.
//
// Args:
//
//	r (rune): Character to check.
//
// Returns:
//
//	(bool): True if the character requires hex encoding.
func shouldEncodeAsHex(r rune) bool {
	return r > 127 || r == ' ' || r == '\t'
}

// writeHexByte writes a single byte in \xHH notation into b.
//
// Args:
//
//	b (*strings.Builder): Destination builder.
//	bt (byte): The byte to encode.
func writeHexByte(b *strings.Builder, bt byte) {
	b.WriteString("\\x")
	b.WriteByte(hexDigits[bt>>4])
	b.WriteByte(hexDigits[bt&0x0f])
}

// LenToRule converts a string to a rule by its length.
//
// Args:
//
//	str (string): Input string to transform
//	rule (string): Rule to insert per length
//
// Returns:
//
//	(string): Transformed string
func LenToRule(str string, rule string) string {
	return strings.TrimSpace(strings.Repeat(rule+" ", len(str)))
}

// CharToRule converts a string to a rule by its characters, encoding spaces,
// tabs, and multi-byte characters as \xHH hex sequences. When the rule
// operator is "^" (prepend), the bytes within each hex-encoded character are
// emitted in reverse order so that Hashcat reconstructs the correct byte
// sequence when prepending each byte to position 0.
//
// Args:
//
//	str (string): Input string to transform
//	rule (string): Rule to insert per character
//
// Returns:
//
//	(string): Transformed string
func CharToRule(str string, rule string) string {
	var b strings.Builder
	first := true

	for _, r := range str {
		if !first {
			b.WriteByte(' ')
		}
		first = false

		if shouldEncodeAsHex(r) {
			bytes := []byte(string(r))
			if rule == "^" {
				for i := len(bytes) - 1; i >= 0; i-- {
					if i < len(bytes)-1 {
						b.WriteByte(' ')
					}
					b.WriteString(rule)
					writeHexByte(&b, bytes[i])
				}
			} else {
				for i, bt := range bytes {
					if i > 0 {
						b.WriteByte(' ')
					}
					b.WriteString(rule)
					writeHexByte(&b, bt)
				}
			}
		} else {
			b.WriteString(rule)
			b.WriteRune(r)
		}
	}

	return b.String()
}

// CharToIteratingRule converts a string to a rule by its characters but
// increments along with each character, encoding spaces, tabs, and multi-byte
// characters as \xHH hex sequences with correct position tracking.
//
// Args:
//
//	str (string): Input string to transform
//	rule (string): Rule to insert per length
//	index (int): Index to start at
//
// Returns:
//
//	(string): Transformed string
func CharToIteratingRule(str string, rule string, index int) string {
	var b strings.Builder
	currentPos := index

	for _, r := range str {
		if shouldEncodeAsHex(r) {
			for _, bt := range []byte(string(r)) {
				if currentPos < 10 {
					b.WriteString(rule)
					b.WriteByte(byte('0' + currentPos))
					writeHexByte(&b, bt)
					b.WriteByte(' ')
				} else if currentPos-10 < 26 {
					b.WriteString(rule)
					b.WriteByte(byte('A' + currentPos - 10))
					writeHexByte(&b, bt)
					b.WriteByte(' ')
				}
				currentPos++
			}
		} else {
			if currentPos < 10 {
				b.WriteString(fmt.Sprintf("%s%d%c ", rule, currentPos, r))
			} else if currentPos-10 < 26 {
				b.WriteString(fmt.Sprintf("%s%c%c ", rule, 'A'+currentPos-10, r))
			}
			currentPos++
		}
	}

	return strings.TrimSpace(b.String())
}

// StringToToggleRule converts a string to toggle rules by looking for upper
// chars.
//
// Args:
//
//	str (string): Input string to transform
//	rule (string): Rule to insert per length
//	index (int): Index to start at
//
// Returns:
//
//	(string): Transformed string
func StringToToggleRule(str string, rule string, index int) string {
	var result strings.Builder
	for i, r := range str {
		if unicode.IsUpper(r) {
			if i+index < 10 {
				result.WriteString(fmt.Sprintf("%s%d ", rule, i+index))
			} else if i+index-10 < 26 {
				result.WriteString(fmt.Sprintf("%s%c ", rule, 'A'+i+index-10))
			}
		}
	}
	return strings.TrimSpace(result.String())
}

// FormatCharToRuleOutput handles formatting of rule output
// for CharToRule functions.
//
// Args:
//
//	strs (...string): Input strings to print
//
// Returns:
//
//	output (string): Formatted output
func FormatCharToRuleOutput(strs ...string) (output string) {
	output = ""
	for _, str := range strs {
		if utils.CheckASCIIString(str) {
			output += str + " "
		} else {
			output += utils.ConvertMultiByteCharToRule(str)
		}
	}

	if strings.HasSuffix(output, "$  ") {
		output = output[:len(output)-1] + ":"
	}

	if output != "" && len(output) < 93 {
		return strings.TrimSpace(output)
	}

	return ""
}

// FormatCharToIteratingRuleOutput handles formatting of rule output
// for CharToIteratingRule functions.
//
// Args:
//
//	index (int): Index to start at
//	strs (...string): Input strings to print
//
// Returns:
//
//	output (string): Formatted output
func FormatCharToIteratingRuleOutput(index int, strs ...string) (output string) {
	output = ""
	for _, str := range strs {
		if utils.CheckASCIIString(str) {
			output += str + " "
		} else {
			output += utils.ConvertMultiByteCharToIteratingRule(index, str)
		}
	}

	if len(output)-3 >= 0 {
		if output[len(output)-3:len(output)-2] == "o" || output[len(output)-3:len(output)-2] == "i" {
			output = output + ":"
		}
	}

	if output != "" && len(output) < 93 {
		return strings.TrimSpace(output)
	}

	return ""
}

// AppendRules transforms input into append rules.
//
// Args:
//
//	items (map[string]int): Items to use in the operation
//	operation (string): Operation to use in the function
//	bypass (bool): If true, the map is not used for output or filtering
//	debug (bool): If true, print additional debug information to stderr
//
// Returns:
//
//	returnMap (map[string]int): Map of items to return
func AppendRules(items map[string]int, operation string, bypass bool, debug bool) (returnMap map[string]int) {
	returnMap = make(map[string]int)
	switch operation {
	case "rule-append-remove", "append-remove":
		for key, value := range items {
			if len(key) > 15 {
				if debug {
					fmt.Fprintf(os.Stderr, "[!] Error: Key is too long for append-remove operation\n")
				}
				continue
			}
			rule := CharToRule(key, "$")
			remove := LenToRule(key, "]")
			appendRemoveRule := FormatCharToRuleOutput(remove, rule)

			if debug {
				fmt.Fprintf(os.Stderr, "[?] AppendRules (remove):\n")
				fmt.Fprintf(os.Stderr, "Key: %s\n", key)
				fmt.Fprintf(os.Stderr, "Rule: %s\n", rule)
				fmt.Fprintf(os.Stderr, "Remove: %s\n", remove)
				fmt.Fprintf(os.Stderr, "AppendRemoveRule: %s\n", appendRemoveRule)
			}

			if appendRemoveRule != "" && !bypass {
				returnMap[appendRemoveRule] = value
			} else if appendRemoveRule != "" && bypass {
				fmt.Println(appendRemoveRule)
			}
		}
		return returnMap
	default:
		for key, value := range items {
			rule := CharToRule(key, "$")
			appendRule := FormatCharToRuleOutput(rule)

			if debug {
				fmt.Fprintf(os.Stderr, "[?] AppendRules:\n")
				fmt.Fprintf(os.Stderr, "Key: %s\n", key)
				fmt.Fprintf(os.Stderr, "Rule: %s\n", rule)
				fmt.Fprintf(os.Stderr, "AppendRule: %s\n", appendRule)
			}

			if appendRule != "" && !bypass {
				returnMap[appendRule] = value
			} else if appendRule != "" && bypass {
				fmt.Println(appendRule)
			}
		}
		return returnMap
	}
}

// PrependRules transforms input into prepend rules.
//
// Args:
//
//	items (map[string]int): Items to use in the operation
//	operation (string): Operation to use in the function
//	bypass (bool): If true, the map is not used for output or filtering
//	debug (bool): If true, print additional debug information to stderr
//
// Returns:
//
//	returnMap (map[string]int): Map of items to return
func PrependRules(items map[string]int, operation string, bypass bool, debug bool) (returnMap map[string]int) {
	returnMap = make(map[string]int)
	switch operation {
	case "rule-prepend-remove", "prepend-remove":
		for key, value := range items {
			if len(key) > 15 {
				if debug {
					fmt.Fprintf(os.Stderr, "[!] Error: Key is too long for prepend-remove operation\n")
				}
				continue
			}
			rule := CharToRule(utils.ReverseString(key), "^")
			remove := LenToRule(key, "[")
			prependRemoveRule := FormatCharToRuleOutput(remove, rule)

			if debug {
				fmt.Fprintf(os.Stderr, "[?] PrependRules (remove):\n")
				fmt.Fprintf(os.Stderr, "Key: %s\n", key)
				fmt.Fprintf(os.Stderr, "Rule: %s\n", rule)
				fmt.Fprintf(os.Stderr, "Remove: %s\n", remove)
				fmt.Fprintf(os.Stderr, "PrependRemoveRule: %s\n", prependRemoveRule)
			}

			if prependRemoveRule != "" && !bypass {
				returnMap[prependRemoveRule] = value
			} else if prependRemoveRule != "" && bypass {
				fmt.Println(prependRemoveRule)
			}
		}
		return returnMap
	case "rule-prepend-toggle", "prepend-toggle":
		for key, value := range items {
			rule := CharToRule(utils.ReverseString(key), "^")
			toggle := StringToToggleRule("A", "T", len(key))
			prependToggleRule := FormatCharToRuleOutput(rule, toggle)

			if debug {
				fmt.Fprintf(os.Stderr, "[?] PrependRules (toggle):\n")
				fmt.Fprintf(os.Stderr, "Key: %s\n", key)
				fmt.Fprintf(os.Stderr, "Rule: %s\n", rule)
				fmt.Fprintf(os.Stderr, "Toggle: %s\n", toggle)
				fmt.Fprintf(os.Stderr, "PrependToggleRule: %s\n", prependToggleRule)
			}

			if prependToggleRule != "" && !bypass {
				returnMap[prependToggleRule] = value
			} else if prependToggleRule != "" && bypass {
				fmt.Println(prependToggleRule)
			}
		}
		return returnMap
	default:
		for key, value := range items {
			rule := CharToRule(utils.ReverseString(key), "^")
			prependRule := FormatCharToRuleOutput(rule)

			if debug {
				fmt.Fprintf(os.Stderr, "[?] PrependRules:\n")
				fmt.Fprintf(os.Stderr, "Key: %s\n", key)
				fmt.Fprintf(os.Stderr, "Rule: %s\n", rule)
				fmt.Fprintf(os.Stderr, "PrependRule: %s\n", prependRule)
			}

			if prependRule != "" && !bypass {
				returnMap[prependRule] = value
			} else if prependRule != "" && bypass {
				fmt.Println(prependRule)
			}
		}
		return returnMap
	}
}

// InsertRules transforms input into insert rules by index.
//
// Args:
//
//	items (map[string]int): Items to use in the operation
//	index (string): Index to insert at
//	end (string): Index to end at
//	bypass (bool): If true, the map is not used for output or filtering
//	debug (bool): If true, print additional debug information to stderr
//
// Returns:
//
//	returnMap (map[string]int): Map of items to return
func InsertRules(items map[string]int, index string, end string, bypass bool, debug bool) (returnMap map[string]int) {
	returnMap = make(map[string]int)
	startIndex, _ := strconv.Atoi(index)
	endIndex, _ := strconv.Atoi(end)

	for i := startIndex; i <= endIndex; i++ {
		for key, value := range items {
			rule := CharToIteratingRule(key, "i", i)
			insertRule := FormatCharToIteratingRuleOutput(i, rule)

			if debug {
				fmt.Fprintf(os.Stderr, "[?] InsertRules:\n")
				fmt.Fprintf(os.Stderr, "Key: %s\n", key)
				fmt.Fprintf(os.Stderr, "Rule: %s\n", rule)
				fmt.Fprintf(os.Stderr, "InsertRule: %s\n", insertRule)
			}

			if insertRule != "" && !bypass {
				returnMap[insertRule] = value
			} else if insertRule != "" && bypass {
				fmt.Println(insertRule)
			}
		}
	}
	return returnMap
}

// OverwriteRules transforms input into overwrite rules by index.
//
// Args:
//
//	items (map[string]int): Items to use in the operation
//	index (string): Index to overwrite at
//	end (string): Index to end at
//	bypass (bool): If true, the map is not used for output or filtering
//	debug (bool): If true, print additional debug information to stderr
//
// Returns:
//
//	returnMap (map[string]int): Map of items to return
func OverwriteRules(items map[string]int, index string, end string, bypass bool, debug bool) (returnMap map[string]int) {
	returnMap = make(map[string]int)
	startIndex, _ := strconv.Atoi(index)
	endIndex, _ := strconv.Atoi(end)

	for i := startIndex; i <= endIndex; i++ {
		for key, value := range items {
			rule := CharToIteratingRule(key, "o", i)
			overwriteRule := FormatCharToIteratingRuleOutput(i, rule)

			if debug {
				fmt.Fprintf(os.Stderr, "[?] OverwriteRules:\n")
				fmt.Fprintf(os.Stderr, "Key: %s\n", key)
				fmt.Fprintf(os.Stderr, "Rule: %s\n", rule)
				fmt.Fprintf(os.Stderr, "OverwriteRule: %s\n", overwriteRule)
			}

			if overwriteRule != "" && !bypass {
				returnMap[overwriteRule] = value
			} else if overwriteRule != "" && bypass {
				fmt.Println(overwriteRule)
			}
		}
	}
	return returnMap
}

// ToggleRules transforms input into toggle rules by index.
//
// Args:
//
//	items (map[string]int): Items to use in the operation
//	index (string): Index to toggle at
//	end (string): Index to end at
//	bypass (bool): If true, the map is not used for output or filtering
//	debug (bool): If true, print additional debug information to stderr
//
// Returns:
//
//	returnMap (map[string]int): Map of items to return
func ToggleRules(items map[string]int, index string, end string, bypass bool, debug bool) (returnMap map[string]int) {
	returnMap = make(map[string]int)
	startIndex, _ := strconv.Atoi(index)
	endIndex, _ := strconv.Atoi(end)

	for i := startIndex; i <= endIndex; i++ {
		for key, value := range items {
			rule := StringToToggleRule(key, "T", i)
			toggleRule := FormatCharToIteratingRuleOutput(i, rule)

			if debug {
				fmt.Fprintf(os.Stderr, "[?] ToggleRules:\n")
				fmt.Fprintf(os.Stderr, "Key: %s\n", key)
				fmt.Fprintf(os.Stderr, "Rule: %s\n", rule)
				fmt.Fprintf(os.Stderr, "ToggleRule: %s\n", toggleRule)
			}

			if toggleRule != "" && !bypass {
				returnMap[toggleRule] = value
			} else if toggleRule != "" && bypass {
				fmt.Println(toggleRule)
			}
		}
	}
	return returnMap
}
