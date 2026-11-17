package utils

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/hashcracky/ptt/pkg/models"
)

// ----------------------------------------------------------------------------
// Streaming (bypass mode) Functions
// ----------------------------------------------------------------------------

const (
	// streamBufferSize is the read/write buffer size used while streaming.
	streamBufferSize = 1024 * 1024
	// jsonSniffSize is how much of a file is inspected to detect ptt JSON.
	jsonSniffSize = 64 * 1024

	// BypassBatchEntries is the maximum number of unique keys held in a batch.
	BypassBatchEntries = 100000
	// BypassBatchBytes is the maximum number of key bytes held in a batch.
	BypassBatchBytes = 32 * 1024 * 1024
)

// KeyHandler receives a single input key and how many times it occurred.
type KeyHandler func(key string, count int) error

// LineWriter is a buffered writer that writes one result per line. It is used
// as the destination for results in bypass mode so that each result does not
// cost a write syscall. It is safe for concurrent use. Each line is written
// whole, but lines from different goroutines are in no defined order.
type LineWriter struct {
	mu    sync.Mutex
	w     *bufio.Writer
	lines int64
	err   error
}

// BypassOutput is where transformations write results when bypass is enabled.
// Callers must call Flush before exiting.
var BypassOutput = NewLineWriter(os.Stdout)

// NewLineWriter creates a LineWriter that writes to w.
func NewLineWriter(w io.Writer) *LineWriter {
	return &LineWriter{w: bufio.NewWriterSize(w, streamBufferSize)}
}

// WriteLine writes s followed by a newline. After a write error all further
// writes are dropped and the error is reported by Err and Flush.
func (l *LineWriter) WriteLine(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return
	}
	if _, err := l.w.WriteString(s); err != nil {
		l.err = err
		return
	}
	if err := l.w.WriteByte('\n'); err != nil {
		l.err = err
		return
	}
	l.lines++
}

// Flush writes any buffered data to the underlying writer.
func (l *LineWriter) Flush() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return l.err
	}
	l.err = l.w.Flush()
	return l.err
}

// Err returns the first write error, if any.
func (l *LineWriter) Err() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.err
}

// Lines returns the number of lines written so far.
func (l *LineWriter) Lines() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lines
}

// spareMaps is the number of empty maps a Batcher keeps for reuse.
const spareMaps = 4

// Batcher collects keys into a bounded map and hands the map to process once
// either limit is reached. This keeps memory use independent of input size
// while still letting transformations work on many keys at once.
//
// The Batcher gives each full map to process and does not touch it again, so
// process can pass the map to another goroutine. When the map is no longer
// needed, call Recycle so that the Batcher can reuse its memory. Add and
// Flush must be called from one goroutine only. Recycle can be called from
// any goroutine.
type Batcher struct {
	maxEntries int
	maxBytes   int
	bytes      int
	batch      map[string]int
	spare      chan map[string]int
	process    func(map[string]int)
}

// NewBatcher creates a Batcher that calls process with each full batch.
func NewBatcher(maxEntries int, maxBytes int, process func(map[string]int)) *Batcher {
	return &Batcher{
		maxEntries: maxEntries,
		maxBytes:   maxBytes,
		batch:      make(map[string]int),
		spare:      make(chan map[string]int, spareMaps),
		process:    process,
	}
}

// Recycle empties a map that was given to process and keeps it for reuse. The
// caller must not use the map after this call.
func (b *Batcher) Recycle(m map[string]int) {
	clear(m)
	select {
	case b.spare <- m:
	default:
	}
}

// Add adds a key to the current batch and processes the batch if it is full.
func (b *Batcher) Add(key string, count int) {
	if _, exists := b.batch[key]; !exists {
		b.bytes += len(key)
	}
	b.batch[key] += count
	if len(b.batch) >= b.maxEntries || b.bytes >= b.maxBytes {
		b.Flush()
	}
}

// Flush gives the current batch to process, if it has any keys, and starts a
// new batch.
func (b *Batcher) Flush() {
	if len(b.batch) == 0 {
		return
	}
	full := b.batch
	b.bytes = 0
	select {
	case b.batch = <-b.spare:
	default:
		b.batch = make(map[string]int)
	}
	b.process(full)
}

// ForEachLine calls fn for every line read from r without loading the whole
// input into memory. Line terminators are removed. If trimCR is true a
// trailing carriage return is removed as well. If idle is not nil it is called
// whenever the buffered input has been used up and the next read may block, so
// that callers can flush pending work when input arrives slowly.
//
// Args:
//
//	r (io.Reader): The reader to read lines from
//	trimCR (bool): If true, remove a trailing carriage return from each line
//	fn (func(string) error): Called with each line, including empty lines
//	idle (func() error): Optional, called before the reader waits for more data
//
// Returns:
//
//	error: The first error returned by fn, idle, or the reader
func ForEachLine(r io.Reader, trimCR bool, fn func(line string) error, idle func() error) error {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReaderSize(r, streamBufferSize)
	}

	for {
		line, err := br.ReadString('\n')
		if len(line) > 0 {
			line = strings.TrimSuffix(line, "\n")
			if trimCR {
				line = strings.TrimSuffix(line, "\r")
			}
			if ferr := fn(line); ferr != nil {
				return ferr
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if idle != nil && br.Buffered() == 0 {
			if ierr := idle(); ierr != nil {
				return ierr
			}
		}
	}
}

// StreamFiles reads files and directories one line at a time and calls fn for
// each non-empty line. It mirrors ReadFilesToMap, including expanding
// directories and importing ptt JSON output, but never holds more than a
// buffer of a file in memory.
//
// Args:
//
//	fs (models.FileSystem): The filesystem to read the files from
//	filenames ([]string): The files and directories to read
//	fn (KeyHandler): Called with each key and its frequency
//	idle (func() error): Optional, see ForEachLine
//
// Returns:
//
//	error: An error if a file cannot be opened or read, or if fn fails
func StreamFiles(fs models.FileSystem, filenames []string, fn KeyHandler, idle func() error) error {
	for i := 0; i < len(filenames); i++ {
		filename := filenames[i]
		if IsFileSystemDirectory(filename) {
			files, err := GetFilesInDirectory(filename)
			if err != nil {
				return fmt.Errorf("error reading the directory %s: %w", filename, err)
			}
			filenames = append(filenames, files...)
			continue
		}

		file, err := fs.Open(filename)
		if err != nil {
			return fmt.Errorf("error opening file %s: %w", filename, err)
		}
		err = streamFile(file, fn, idle)
		closeErr := file.Close()
		if err != nil {
			return fmt.Errorf("error reading file %s: %w", filename, err)
		}
		if closeErr != nil {
			return fmt.Errorf("error closing file %s: %w", filename, closeErr)
		}
	}
	return nil
}

// streamFile streams a single file as ptt JSON output if it looks like it,
// otherwise as lines of text.
func streamFile(r io.Reader, fn KeyHandler, idle func() error) error {
	br := bufio.NewReaderSize(r, streamBufferSize)

	if looksLikePttJSON(br) {
		fmt.Fprintf(os.Stderr, "[*] Detected ptt JSON output. Importing...\n")
		return streamJSON(br, fn)
	}

	return ForEachLine(br, false, func(line string) error {
		if line == "" {
			return nil
		}
		return fn(line, 1)
	}, idle)
}

// looksLikePttJSON reports whether the start of r is a JSON object whose first
// entry maps a string to an integer, which is the format ptt writes with -o.
// It only peeks at the reader so nothing is consumed.
func looksLikePttJSON(br *bufio.Reader) bool {
	head, _ := br.Peek(jsonSniffSize)
	dec := json.NewDecoder(bytes.NewReader(head))
	dec.UseNumber()

	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return false
	}
	if !dec.More() {
		tok, err := dec.Token()
		return err == nil && tok == json.Delim('}')
	}
	if tok, err := dec.Token(); err != nil {
		return false
	} else if _, ok := tok.(string); !ok {
		return false
	}
	tok, err := dec.Token()
	if err != nil {
		return false
	}
	number, ok := tok.(json.Number)
	if !ok {
		return false
	}
	_, err = number.Int64()
	return err == nil
}

// streamJSON reads a ptt JSON object entry by entry.
func streamJSON(r io.Reader, fn KeyHandler) error {
	dec := json.NewDecoder(r)
	dec.UseNumber()

	if _, err := dec.Token(); err != nil {
		return err
	}
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return fmt.Errorf("unexpected JSON key %v", keyToken)
		}
		valueToken, err := dec.Token()
		if err != nil {
			return err
		}
		number, ok := valueToken.(json.Number)
		if !ok {
			return fmt.Errorf("unexpected JSON value %v for key %q", valueToken, key)
		}
		count, err := number.Int64()
		if err != nil {
			return err
		}
		if key == "" {
			continue
		}
		if err := fn(key, int(count)); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("unexpected data after JSON object")
	}
	return nil
}

// StreamStdin reads standard input one line at a time and calls fn for each
// non-empty line. It mirrors LoadStdinToMap, including detection of ptt -v
// output, but never holds more than a buffer of the input in memory.
//
// Args:
//
//	r (io.Reader): The reader to read from, usually os.Stdin
//	fn (KeyHandler): Called with each key and its frequency
//	idle (func() error): Optional, see ForEachLine
//
// Returns:
//
//	error: An error if the input cannot be read or parsed, or if fn fails
func StreamStdin(r io.Reader, fn KeyHandler, idle func() error) error {
	first := true
	pttInput := false

	return ForEachLine(r, true, func(line string) error {
		if line == "" {
			return nil
		}

		if first {
			first = false
			if pttVerboseDetect.MatchString(line) {
				fmt.Fprintf(os.Stderr, "[*] Detected ptt -v output. Importing...\n")
				pttInput = true
			}
		}

		if pttInput {
			key, count, err := parsePttVerboseLine(line)
			if err != nil {
				return err
			}
			return fn(key, count)
		}
		return fn(line, 1)
	}, idle)
}

// parsePttVerboseLine splits a line of ptt -v output into its key and its
// frequency.
func parsePttVerboseLine(line string) (string, int, error) {
	match := pttVerboseCount.FindString(line)
	count, err := strconv.Atoi(match)
	if err != nil {
		return "", 0, err
	}
	return strings.TrimSpace(strings.Replace(line, match, "", 1)), count, nil
}
