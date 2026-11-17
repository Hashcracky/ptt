// Package bypass streams input through a transformation straight to standard
// output without building a map of the input or of the results. This is what
// the -b flag uses so that very large inputs can be processed with a small,
// fixed amount of memory.
package bypass

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/hashcracky/ptt/pkg/format"
	"github.com/hashcracky/ptt/pkg/models"
	"github.com/hashcracky/ptt/pkg/transform"
	"github.com/hashcracky/ptt/pkg/utils"
)

const (
	// flushInterval is how often buffered results are written to the output.
	flushInterval = 50 * time.Millisecond
	// errorCheckInterval is how many input items are read between checks for
	// an output error.
	errorCheckInterval = 4096
)

var (
	// ErrNoInput is returned by Run when there was nothing to process.
	ErrNoInput = errors.New("no input provided")
	// ErrNoItems is returned by Run when the complexity filter removed every
	// input item.
	ErrNoItems = errors.New("no items remaining after complexity filter")
)

// Options holds the flags that apply to bypass mode.
type Options struct {
	Transformation      string
	StartIndex          int
	EndIndex            int
	Verbose             bool
	ReplacementMask     string
	Debug               int
	WordStart           int
	WordEnd             int
	LengthStart         int
	LengthEnd           int
	IncludeNonLatin     bool
	MinComplexity       int
	Files               []string
	TransformationFiles []string
	// Workers is the number of batches that are transformed at the same time.
	// If it is zero, Run uses one worker for each available CPU.
	Workers int

	// batchEntries replaces utils.BypassBatchEntries when it is not zero, so
	// that tests can make many small batches.
	batchEntries int
}

// workerCount returns the number of workers to use. Debug output of level 2 is
// printed per item, so it would be mixed together by more than one worker.
func workerCount(opts Options) int {
	if opts.Debug > 1 {
		if opts.Workers > 1 {
			fmt.Fprintf(os.Stderr, "[!] Debug level 2 uses one worker, so the -p flag is ignored.\n")
		}
		return 1
	}
	if opts.Workers > 0 {
		return opts.Workers
	}
	return runtime.GOMAXPROCS(0)
}

// Run streams input through a transformation and writes the results to
// utils.BypassOutput. Files are read first, then standard input if it has data.
// Input is transformed in bounded batches, so memory use does not depend on the
// size of the input. Because nothing is remembered between batches, duplicates
// are only collapsed within a batch of input and duplicate results are not
// removed.
//
// Batches are transformed by a pool of workers (see Options.Workers). With
// more than one worker, the order of the results is not defined. Memory use is
// bounded by the batch limits multiplied by the number of workers plus one.
//
// Args:
//
//	opts (Options): The flags to apply
//	fs (models.FileSystem): The filesystem to read files from
//	stdin (io.Reader): The reader to use for standard input
//	stdinHasInput (bool): If true, stdin is read after the files
//
// Returns:
//
//	error: ErrNoInput if nothing was read, ErrNoItems if the complexity filter
//	removed everything, or the error that stopped the stream. Results written
//	before an error are still flushed.
func Run(opts Options, fs models.FileSystem, stdin io.Reader, stdinHasInput bool) error {
	if len(opts.Files) == 0 && !stdinHasInput {
		return ErrNoInput
	}

	var transformationFilesMap map[string]int
	if len(opts.TransformationFiles) > 0 {
		fmt.Fprintf(os.Stderr, "[*] Reading files for input.\n")
		transformationFilesMap = utils.ReadFilesToMap(fs, opts.TransformationFiles)
	}

	transform.CheckModeRequirements(opts.Transformation, transformationFilesMap, opts.WordStart)

	functionDebug := opts.Debug > 1
	workers := workerCount(opts)
	entries := utils.BypassBatchEntries
	if opts.batchEntries > 0 {
		entries = opts.batchEntries
	}

	// The reader hands each full batch to the next free worker. The channel
	// has no buffer, so at most workers+1 batches exist at the same time and
	// memory use stays bounded.
	batches := make(chan map[string]int)
	batcher := utils.NewBatcher(entries, utils.BypassBatchBytes, func(batch map[string]int) {
		batches <- batch
	})

	var workersDone sync.WaitGroup
	for i := 0; i < workers; i++ {
		workersDone.Add(1)
		go func() {
			defer workersDone.Done()
			for batch := range batches {
				transform.ApplyTransformation(batch, opts.Transformation, opts.StartIndex, opts.EndIndex, opts.Verbose, opts.ReplacementMask, transformationFilesMap, true, functionDebug, opts.WordStart, opts.WordEnd, opts.LengthStart, opts.LengthEnd, opts.IncludeNonLatin)
				batcher.Recycle(batch)
			}
		}()
	}

	// Results are written out at a fixed interval, so slow or interactive
	// input is not held back by the output buffer.
	stopFlusher := make(chan struct{})
	var flusherDone sync.WaitGroup
	flusherDone.Add(1)
	go func() {
		defer flusherDone.Done()
		ticker := time.NewTicker(flushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				// A write error is kept by the writer and found by the reader.
				_ = utils.BypassOutput.Flush()
			case <-stopFlusher:
				return
			}
		}
	}()

	var read, kept int64
	handle := func(key string, count int) error {
		read++
		if opts.MinComplexity > 0 && !format.MeetsComplexity(key, opts.MinComplexity) {
			return nil
		}
		kept++
		batcher.Add(key, count)
		if read%errorCheckInterval == 0 {
			return utils.BypassOutput.Err()
		}
		return nil
	}
	// When input stops arriving, the partial batch is processed now instead
	// of when more input arrives.
	idle := func() error {
		batcher.Flush()
		return utils.BypassOutput.Err()
	}

	if opts.MinComplexity > 0 {
		fmt.Fprintf(os.Stderr, "[*] Filtering input items with complexity less than %d.\n", opts.MinComplexity)
	}
	fmt.Fprintf(os.Stderr, "[*] Starting Processing with %d worker(s).\n", workers)

	done := make(chan bool)
	go utils.TrackLoadTime(done, "Processing")

	err := utils.StreamFiles(fs, opts.Files, handle, idle)
	if err == nil && stdinHasInput {
		err = utils.StreamStdin(stdin, handle, idle)
	}
	batcher.Flush()
	close(batches)
	workersDone.Wait()
	close(stopFlusher)
	flusherDone.Wait()
	flushErr := utils.BypassOutput.Flush()

	done <- true
	close(done)

	if err == nil {
		err = flushErr
	}
	if err != nil {
		return err
	}
	if read == 0 {
		return ErrNoInput
	}
	if kept == 0 {
		return ErrNoItems
	}

	fmt.Fprintf(os.Stderr, "[*] Task complete. Read %d input items and wrote %d output lines.\n", read, utils.BypassOutput.Lines())
	return nil
}
