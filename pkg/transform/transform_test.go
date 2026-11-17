package transform

import (
	"bytes"
	"sort"
	"strings"
	"testing"

	"github.com/hashcracky/ptt/pkg/utils"
)

// ----------------------------------------------------------------------------
// Functions with Unit Tests
// ----------------------------------------------------------------------------
// - ApplyTransformation(), bypass output matches the normal results
//
// ----------------------------------------------------------------------------
// Functions without Unit Tests
// ----------------------------------------------------------------------------
// - TransformationController()
// - CheckModeRequirements()
// - MakePassphraseMap()
// - GenerateNGramMap()

// Unit Test for ApplyTransformation(). In bypass mode every mode must write
// exactly the results it would otherwise have returned, and keep nothing.
func TestApplyTransformationBypass(t *testing.T) {
	newInput := func() map[string]int {
		return map[string]int{
			"Password123!":        3,
			"summer2024":          2,
			"hello world foo bar": 1,
			"abc":                 1,
			"Zebra$99":            1,
			"correct horse":       1,
			"World&amp;Co3":       1,
			"R&D \u00e9":          1,
			"$HEX[70617373]":      1,
			"iloveyou":            1,
			"Monkey":              1,
			"letmein":             1,
			"?u?l?l?l?l?l?l":      1,
			"?l?l?l?l?l":          1,
		}
	}
	retainFiles := map[string]int{"love": 1, "hello": 1}
	maskFiles := map[string]int{"?u?l?l?l?l?l?l?l?d?d?d?s": 1, "?l?l?l?l?l?l?d?d?d?d": 1}
	swapFiles := map[string]int{"admin": 1, "qwerty": 1, "Welcome": 1}

	tests := []struct {
		mode     string
		files    map[string]int
		wordFrom int
		wordTo   int
	}{
		{mode: "append"},
		{mode: "append-remove"},
		{mode: "prepend"},
		{mode: "prepend-toggle"},
		{mode: "insert"},
		{mode: "overwrite"},
		{mode: "toggle"},
		{mode: "encode"},
		{mode: "decode"},
		{mode: "mask"},
		{mode: "dehex"},
		{mode: "hex"},
		{mode: "remove"},
		{mode: "retain", files: retainFiles},
		{mode: "match", files: maskFiles},
		{mode: "pop"},
		{mode: "mask-swap", files: swapFiles},
		{mode: "passphrase", wordFrom: 2, wordTo: 2},
		{mode: "regram", wordFrom: 2, wordTo: 3},
		{mode: "brainstorm", wordFrom: 1, wordTo: 2},
		{mode: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			run := func(bypass bool) map[string]int {
				return ApplyTransformation(newInput(), tt.mode, 0, 2, false, "ulds", tt.files, bypass, false, tt.wordFrom, tt.wordTo, 0, 0, false)
			}

			want := run(false)
			if len(want) == 0 {
				t.Fatalf("mode %s produced no results without bypass, the test input is not useful", tt.mode)
			}

			var buf bytes.Buffer
			original := utils.BypassOutput
			utils.BypassOutput = utils.NewLineWriter(&buf)
			defer func() { utils.BypassOutput = original }()

			returned := run(true)
			if err := utils.BypassOutput.Flush(); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(returned) != 0 {
				t.Errorf("bypass kept %d results in memory", len(returned))
			}

			got := map[string]bool{}
			for _, line := range strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n") {
				got[line] = true
			}
			if !sameKeys(got, want) {
				t.Errorf("bypass output differs from results:\n got: %v\nwant: %v", sortedKeys(got), sortedKeys(want))
			}
		})
	}
}

func sameKeys[A, B any](a map[string]A, b map[string]B) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
