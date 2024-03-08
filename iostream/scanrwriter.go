// Package iostream contains various io.Reader and io.Writer implementations.
package iostream

import (
	"bufio"
	"io"
	"sync"
)

// ScanWriterMaxBufferSize is the maximum size of the ScanWriter buffer. If the buffer
// is full before the delimiter is encountered, the buffer contents are flushed like
// the delimiter was encountered.
var ScanWriterMaxBufferSize = 1024 * 1024

// ScanWriter is an io.WriteCloser wrapper for bufio.Scanner.
// Instead of calling scanner.Scan() like in bufio.Scanner, you write to it and it
// calls the given callback function with the contents of the internal buffer every
// time it encounters the given delimiter.
//
// You must call Close() to flush the remaining buffer contents to the scanner.
type ScanWriter struct {
	fn      CallbackFn
	pipeR   *io.PipeReader
	pipeW   *io.PipeWriter
	scanner *bufio.Scanner
	once    sync.Once
	closed  bool
	closeCh chan struct{}
}

// CallbackFn is a function that takes a string as an argument and returns nothing.
type CallbackFn func(string)

// NewScanWriter returns a new ScanWriter.
func NewScanWriter(fn CallbackFn) io.WriteCloser {
	sw := &ScanWriter{fn: fn, closeCh: make(chan struct{})}
	sw.pipeR, sw.pipeW = io.Pipe()
	sw.scanner = bufio.NewScanner(sw.pipeR)
	sw.scanner.Buffer(nil, ScanWriterMaxBufferSize)
	return sw
}

// Write writes the given bytes to the scanner.
func (w *ScanWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, io.ErrUnexpectedEOF
	}
	w.once.Do(func() {
		go func() {
			for w.scanner.Scan() {
				w.fn(w.scanner.Text())
			}
			close(w.closeCh)
		}()
	})
	return w.pipeW.Write(p) //nolint:wrapcheck
}

// Close closes the writer and the underlying pipe. It returns the last error encountered by the scanner.
func (w *ScanWriter) Close() error {
	return w.CloseWithError(nil)
}

// CloseWithError closes the underlying pipe with an error.
func (w *ScanWriter) CloseWithError(reason error) error {
	if w.closed {
		return io.ErrClosedPipe
	}
	w.closed = true

	if err := w.pipeW.CloseWithError(reason); err != nil {
		return err //nolint:wrapcheck
	}

	<-w.closeCh

	return w.scanner.Err() //nolint:wrapcheck
}

// Err returns the last error encountered by the scanner.
func (w *ScanWriter) Err() error {
	return w.scanner.Err() //nolint:wrapcheck
}

// Split sets the split function for the scanner. see [bufio.Scanner](https://pkg.go.dev/bufio#Scanner)
func (w *ScanWriter) Split(split bufio.SplitFunc) {
	w.scanner.Split(split)
}

// Text returns the most recent token generated by a call to Scan as a newly allocated string holding its bytes.
func (w *ScanWriter) Text() string {
	return w.scanner.Text()
}
