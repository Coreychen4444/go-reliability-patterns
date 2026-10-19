package redact

import (
	"io"
	"sync"
)

// Writer redacts everything written to it before passing it on.
//
// Each Write call is redacted on its own, so a secret split across two calls
// is not detected. Log handlers such as log/slog, zap and zerolog write one
// complete record per call, which is the case Writer is built for. Writer adds
// no locking: it is as safe for concurrent use as the writer it wraps.
type Writer struct {
	w io.Writer
	r *Redactor
}

// NewWriter returns a Writer that redacts with r, or with New() if r is nil.
func NewWriter(w io.Writer, r *Redactor) *Writer {
	if r == nil {
		r = New()
	}
	return &Writer{w: w, r: r}
}

var bufPool = sync.Pool{New: func() any { return new([]byte) }}

// Write redacts p and writes the result to the underlying writer. On success
// it reports len(p), not the length of the redacted output, as io.Writer
// requires; log.Logger and others treat a short count as an error.
func (w *Writer) Write(p []byte) (int, error) {
	if !w.r.mayContain(p) {
		return w.w.Write(p) // fast path: no copy
	}
	bp := bufPool.Get().(*[]byte)
	out := w.r.appendLines((*bp)[:0], p, false)
	n, err := w.w.Write(out)
	if err == nil && n < len(out) {
		err = io.ErrShortWrite
	}
	if cap(out) <= maxPooled {
		*bp = out[:0]
		bufPool.Put(bp)
	}
	if err != nil {
		// The redacted output does not map back to positions in p, so a
		// partial write is reported as nothing written.
		return 0, err
	}
	return len(p), nil
}
