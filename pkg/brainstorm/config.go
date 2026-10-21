// Package brainstorm contains the brainstorm transformation mode for PTT.
//
// This package adapts the logic from the brainstorm application (github.com/hashcracky/brainstorm)
// into PTT's map-based transformation pipeline.
package brainstorm

// Config holds all configuration options for the brainstorm transformation mode.
type Config struct {
	// NGramMin is the minimum n-gram word length.
	NGramMin int
	// NGramMax is the maximum n-gram word length.
	NGramMax int
	// OutMinLength is the minimum output string length.
	OutMinLength int
	// OutMaxLength is the maximum output string length.
	OutMaxLength int
	// IncludeNonLatin, when true, relaxes Latin vowel heuristics to allow
	// multi-byte non-Latin letter sequences.
	IncludeNonLatin bool
}
