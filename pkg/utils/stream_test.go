package utils

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/hashcracky/ptt/pkg/models"
)

// collect gathers the keys passed to a KeyHandler along with their counts.
func collect(into map[string]int) KeyHandler {
	return func(key string, count int) error {
		into[key] += count
		return nil
	}
}

func TestForEachLine(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		trimCR bool
		want   []string
	}{
		{"trailing newline", "a\nb\n", false, []string{"a", "b"}},
		{"no trailing newline", "a\nb", false, []string{"a", "b"}},
		{"empty lines are passed through", "a\n\nb\n", false, []string{"a", "", "b"}},
		{"carriage return kept", "a\r\nb\r\n", false, []string{"a\r", "b\r"}},
		{"carriage return trimmed", "a\r\nb\r\n", true, []string{"a", "b"}},
		{"empty input", "", false, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			err := ForEachLine(strings.NewReader(tt.input), tt.trimCR, func(line string) error {
				got = append(got, line)
				return nil
			}, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestForEachLineLongLine(t *testing.T) {
	long := strings.Repeat("x", 5*1024*1024)
	var got int
	err := ForEachLine(strings.NewReader(long+"\nshort\n"), false, func(line string) error {
		if got == 0 && len(line) != len(long) {
			t.Errorf("long line length = %d, want %d", len(line), len(long))
		}
		got++
		return nil
	}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 2 {
		t.Errorf("got %d lines, want 2", got)
	}
}

func TestForEachLineStopsOnHandlerError(t *testing.T) {
	stop := errors.New("stop")
	calls := 0
	err := ForEachLine(strings.NewReader("a\nb\nc\n"), false, func(string) error {
		calls++
		return stop
	}, nil)
	if err != stop || calls != 1 {
		t.Errorf("got err=%v calls=%d, want err=%v calls=1", err, calls, stop)
	}
}

// pipeReader hands out one chunk per Read, like a slow pipe would.
type pipeReader struct {
	chunks []string
}

func (p *pipeReader) Read(b []byte) (int, error) {
	if len(p.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(b, p.chunks[0])
	p.chunks = p.chunks[1:]
	return n, nil
}

func TestForEachLineIdleRunsBeforeBlocking(t *testing.T) {
	var events []string
	r := &pipeReader{chunks: []string{"a\nb\n", "c\n"}}
	err := ForEachLine(r, false, func(line string) error {
		events = append(events, line)
		return nil
	}, func() error {
		events = append(events, "idle")
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"a", "b", "idle", "c", "idle"}
	if !reflect.DeepEqual(events, want) {
		t.Errorf("got %q, want %q", events, want)
	}
}

func TestStreamFiles(t *testing.T) {
	fs := &models.MockFileSystem{Files: map[string][]byte{
		"text.txt": []byte("one\n\ntwo\r\none"),
		"ptt.json": []byte(`{"alpha": 3, "beta": 1}`),
		"empty":    []byte(""),
		"braces":   []byte("{not json}\nplain\n"),
	}}

	tests := []struct {
		name  string
		files []string
		want  map[string]int
	}{
		{"text keeps carriage returns and skips empty lines", []string{"text.txt"}, map[string]int{"one": 2, "two\r": 1}},
		{"ptt json import keeps counts", []string{"ptt.json"}, map[string]int{"alpha": 3, "beta": 1}},
		{"empty file", []string{"empty"}, map[string]int{}},
		{"text that starts with a brace", []string{"braces"}, map[string]int{"{not json}": 1, "plain": 1}},
		{"multiple files", []string{"text.txt", "ptt.json"}, map[string]int{"one": 2, "two\r": 1, "alpha": 3, "beta": 1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := map[string]int{}
			if err := StreamFiles(fs, tt.files, collect(got), nil); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStreamFilesErrors(t *testing.T) {
	fs := &models.MockFileSystem{Files: map[string][]byte{
		"badjson": []byte(`{"alpha": 3, "beta"`),
	}}

	if err := StreamFiles(fs, []string{"missing"}, collect(map[string]int{}), nil); err == nil {
		t.Error("expected an error for a missing file")
	}
	if err := StreamFiles(fs, []string{"badjson"}, collect(map[string]int{}), nil); err == nil {
		t.Error("expected an error for truncated JSON")
	}
}

func TestStreamStdin(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  map[string]int
	}{
		{"plain lines trim carriage returns", "one\r\ntwo\n\none", map[string]int{"one": 2, "two": 1}},
		{"ptt verbose output keeps counts", "3 alpha\n1 beta gamma\n", map[string]int{"alpha": 3, "beta gamma": 1}},
		{"verbose detection only looks at the first line", "plain\n3 alpha\n", map[string]int{"plain": 1, "3 alpha": 1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := map[string]int{}
			if err := StreamStdin(strings.NewReader(tt.input), collect(got), nil); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBatcher(t *testing.T) {
	t.Run("flushes on entry limit", func(t *testing.T) {
		var batches [][]string
		b := NewBatcher(3, 1<<20, func(m map[string]int) {
			keys := make([]string, 0, len(m))
			for k := range m {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			batches = append(batches, keys)
		})
		for _, k := range []string{"a", "b", "a", "c", "d"} {
			b.Add(k, 1)
		}
		b.Flush()
		want := [][]string{{"a", "b", "c"}, {"d"}}
		if !reflect.DeepEqual(batches, want) {
			t.Errorf("got %v, want %v", batches, want)
		}
	})

	t.Run("flushes on byte limit", func(t *testing.T) {
		batches := 0
		b := NewBatcher(100, 10, func(map[string]int) { batches++ })
		b.Add("12345", 1)
		b.Add("12345", 1) // duplicate keys do not count towards the limit
		if batches != 0 {
			t.Fatalf("flushed too early: %d", batches)
		}
		b.Add("67890", 1)
		if batches != 1 {
			t.Errorf("got %d batches, want 1", batches)
		}
	})

	t.Run("counts are summed and empty flush is a no-op", func(t *testing.T) {
		var got map[string]int
		calls := 0
		b := NewBatcher(10, 1<<20, func(m map[string]int) {
			calls++
			got = map[string]int{}
			for k, v := range m {
				got[k] = v
			}
		})
		b.Flush()
		b.Add("a", 2)
		b.Add("a", 3)
		b.Flush()
		b.Flush()
		if calls != 1 || !reflect.DeepEqual(got, map[string]int{"a": 5}) {
			t.Errorf("got calls=%d map=%v", calls, got)
		}
	})

	t.Run("recycled maps are reused empty and handed-out maps are not touched", func(t *testing.T) {
		var handed []map[string]int
		b := NewBatcher(10, 1<<20, func(m map[string]int) { handed = append(handed, m) })

		b.Add("a", 1)
		b.Flush()
		b.Add("b", 1)
		b.Flush()
		if len(handed[0]) != 1 || handed[0]["a"] != 1 {
			t.Fatalf("the first map changed after it was handed out: %v", handed[0])
		}

		b.Recycle(handed[0])
		if len(handed[0]) != 0 {
			t.Errorf("a recycled map must be empty, got %v", handed[0])
		}
		// The recycled map is used for the batch that starts after this flush.
		b.Add("c", 1)
		b.Flush()
		b.Add("d", 1)
		b.Flush()
		if reflect.ValueOf(handed[3]).Pointer() != reflect.ValueOf(handed[0]).Pointer() {
			t.Error("the recycled map was not reused")
		}
		if len(handed[3]) != 1 || handed[3]["d"] != 1 {
			t.Errorf("got %v, want only the new key", handed[3])
		}
	})
}

func TestLineWriterConcurrent(t *testing.T) {
	var buf bytes.Buffer
	w := NewLineWriter(&buf)

	const goroutines, perGoroutine = 8, 2000
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				w.WriteLine(fmt.Sprintf("g%d-%d", g, i))
				if i%500 == 0 {
					_ = w.Flush()
				}
			}
		}()
	}
	wg.Wait()
	if err := w.Flush(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if w.Lines() != goroutines*perGoroutine {
		t.Errorf("got %d lines, want %d", w.Lines(), goroutines*perGoroutine)
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n") {
		seen[line] = true
	}
	if len(seen) != goroutines*perGoroutine {
		t.Errorf("got %d distinct lines, want %d, lines must not be mixed together", len(seen), goroutines*perGoroutine)
	}
	for line := range seen {
		var g, i int
		if n, err := fmt.Sscanf(line, "g%d-%d", &g, &i); err != nil || n != 2 {
			t.Fatalf("damaged line %q", line)
		}
	}
}

// failingWriter fails every write.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestLineWriter(t *testing.T) {
	var buf bytes.Buffer
	w := NewLineWriter(&buf)
	w.WriteLine("a")
	w.WriteLine("b")
	if buf.Len() != 0 {
		t.Error("output should be buffered until Flush")
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.String() != "a\nb\n" || w.Lines() != 2 {
		t.Errorf("got %q with %d lines", buf.String(), w.Lines())
	}

	bad := NewLineWriter(failingWriter{})
	bad.WriteLine("a")
	if err := bad.Flush(); err == nil {
		t.Error("expected a flush error")
	}
	bad.WriteLine("b")
	if bad.Err() == nil || bad.Lines() != 1 {
		t.Errorf("writes after an error must be dropped, got err=%v lines=%d", bad.Err(), bad.Lines())
	}
}
