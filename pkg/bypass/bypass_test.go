package bypass

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/hashcracky/ptt/pkg/models"
	"github.com/hashcracky/ptt/pkg/utils"
)

// capture redirects bypass output to a buffer for the duration of a test.
func capture(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	original := utils.BypassOutput
	utils.BypassOutput = utils.NewLineWriter(&buf)
	t.Cleanup(func() { utils.BypassOutput = original })
	return &buf
}

func sortedLines(s string) []string {
	if s == "" {
		return nil
	}
	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	sort.Strings(lines)
	return lines
}

func TestRun(t *testing.T) {
	fs := &models.MockFileSystem{Files: map[string][]byte{
		"words.txt": []byte("abc\ndef\n\nabc\n"),
	}}

	tests := []struct {
		name  string
		opts  Options
		stdin string
		useIn bool
		want  []string
		err   error
	}{
		{
			name:  "files and stdin are both read",
			opts:  Options{Transformation: "hex", Files: []string{"words.txt"}},
			stdin: "ghi\r\n", useIn: true,
			want: []string{"$HEX[616263]", "$HEX[646566]", "$HEX[676869]"},
		},
		{
			name:  "stdin only",
			opts:  Options{Transformation: "hex"},
			stdin: "abc\n", useIn: true,
			want: []string{"$HEX[616263]"},
		},
		{
			name:  "complexity filter keeps only complex items",
			opts:  Options{Transformation: "hex", MinComplexity: 2},
			stdin: "abc\nabc1\n", useIn: true,
			want: []string{"$HEX[61626331]"},
		},
		{
			name:  "complexity filter removes everything",
			opts:  Options{Transformation: "hex", MinComplexity: 4},
			stdin: "abc\n", useIn: true,
			err: ErrNoItems,
		},
		{
			name: "nothing to read",
			opts: Options{Transformation: "hex"},
			err:  ErrNoInput,
		},
		{
			name:  "only empty lines",
			opts:  Options{Transformation: "hex"},
			stdin: "\n\n", useIn: true,
			err: ErrNoInput,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := capture(t)
			err := Run(tt.opts, fs, strings.NewReader(tt.stdin), tt.useIn)
			if !errors.Is(err, tt.err) {
				t.Fatalf("got error %v, want %v", err, tt.err)
			}
			got := sortedLines(buf.String())
			if strings.Join(got, "\n") != strings.Join(tt.want, "\n") {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// Results written before a read error must not be lost.
func TestRunFlushesResultsBeforeError(t *testing.T) {
	fs := &models.MockFileSystem{Files: map[string][]byte{"words.txt": []byte("abc\n")}}
	buf := capture(t)

	err := Run(Options{Transformation: "hex", Files: []string{"words.txt", "missing.txt"}}, fs, strings.NewReader(""), false)
	if err == nil {
		t.Fatal("expected an error for the missing file")
	}
	if got := buf.String(); got != "$HEX[616263]\n" {
		t.Errorf("got %q, want the first file's result", got)
	}
}

// Input much larger than a batch must still be processed completely.
func TestRunMultipleBatches(t *testing.T) {
	total := utils.BypassBatchEntries*2 + 10
	var in strings.Builder
	for i := 0; i < total; i++ {
		fmt.Fprintf(&in, "word%d\n", i)
	}

	buf := capture(t)
	if err := Run(Options{Transformation: "unknown"}, &models.MockFileSystem{}, strings.NewReader(in.String()), true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := sortedLines(buf.String())
	want := sortedLines(in.String())
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got %d lines, want %d identical lines", len(got), len(want))
	}
}

func TestWorkerCount(t *testing.T) {
	tests := []struct {
		name string
		opts Options
		want int
	}{
		{"default is one per CPU", Options{}, runtime.GOMAXPROCS(0)},
		{"explicit count", Options{Workers: 3}, 3},
		{"debug level 2 uses one worker", Options{Workers: 3, Debug: 2}, 1},
		{"debug level 1 does not limit workers", Options{Workers: 3, Debug: 1}, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := workerCount(tt.opts); got != tt.want {
				t.Errorf("got %d, want %d", got, tt.want)
			}
		})
	}
}

// Every mode must give the same results for one worker and for many workers.
// Small batches make sure that many batches run at the same time, and the race
// detector finds any state that the workers share by mistake.
func TestRunWorkersGiveSameResults(t *testing.T) {
	words := strings.Fields("quick brown fox jumps over lazy dog summer winter password welcome monkey Dragon shadow master love hello")
	var input strings.Builder
	for i := 0; i < 400; i++ {
		fmt.Fprintf(&input, "%s %s %s%d\n", words[i%len(words)], words[(i*7+3)%len(words)], words[(i*5+1)%len(words)], i)
	}
	fs := &models.MockFileSystem{Files: map[string][]byte{
		"tf.txt": []byte("quick\nlove\nhello\n"),
		"in.txt": []byte(input.String()),
	}}

	tests := []struct {
		name string
		opts Options
	}{
		{"hex", Options{Transformation: "hex"}},
		{"append", Options{Transformation: "append"}},
		{"toggle", Options{Transformation: "toggle", StartIndex: 0, EndIndex: 2}},
		{"mask", Options{Transformation: "mask", ReplacementMask: "ulds"}},
		{"pop", Options{Transformation: "pop", ReplacementMask: "ulds"}},
		{"retain", Options{Transformation: "retain", ReplacementMask: "ulds", TransformationFiles: []string{"tf.txt"}}},
		{"passphrase", Options{Transformation: "passphrase", WordStart: 3, WordEnd: 3}},
		{"regram", Options{Transformation: "regram", WordStart: 2, WordEnd: 3}},
		{"brainstorm", Options{Transformation: "brainstorm", WordStart: 1, WordEnd: 2}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			run := func(workers int) []string {
				buf := capture(t)
				opts := tt.opts
				opts.Files = []string{"in.txt"}
				opts.Workers = workers
				opts.batchEntries = 7
				if err := Run(opts, fs, strings.NewReader(""), false); err != nil {
					t.Fatalf("unexpected error with %d workers: %v", workers, err)
				}
				return sortedLines(buf.String())
			}

			want := run(1)
			if len(want) == 0 {
				t.Fatal("the test input gives no results")
			}
			for _, workers := range []int{2, 8} {
				got := run(workers)
				if strings.Join(got, "\n") != strings.Join(want, "\n") {
					t.Errorf("%d workers gave %d lines, one worker gave %d lines", workers, len(got), len(want))
				}
			}
		})
	}
}

// One worker keeps the order of the batches, which gives a repeatable order
// for input that has one item in each batch.
func TestRunOneWorkerKeepsBatchOrder(t *testing.T) {
	var input strings.Builder
	for i := 0; i < 50; i++ {
		fmt.Fprintf(&input, "line%02d\n", i)
	}
	buf := capture(t)
	opts := Options{Transformation: "unknown", Workers: 1, batchEntries: 1}
	if err := Run(opts, &models.MockFileSystem{}, strings.NewReader(input.String()), true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.String() != input.String() {
		t.Errorf("the order of the batches changed:\n%s", buf.String())
	}
}
