package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"time"
)

var (
	ErrClosed     = errors.New("cryptkit/audit: log closed")
	ErrNotSameKey = errors.New("cryptkit/audit: wrong log key")
)

// Log is an append-only, hash-chained, HMAC-signed operation log.
// Safe for concurrent use.
type Log struct {
	mu      sync.Mutex
	w       io.Writer
	closeFn func() error
	key     []byte
	seq     uint64
	prev    string
	closed  bool
}

// NewWriterLog creates a log writing JSONL to w. key must be ≥32 bytes.
func NewWriterLog(w io.Writer, key []byte) (*Log, error) {
	if len(key) < 32 {
		return nil, errors.New("cryptkit/audit: key must be ≥32 bytes")
	}
	return &Log{w: w, key: key}, nil
}

// NewFileLog opens (or creates) a log file in append mode.
func NewFileLog(path string, key []byte) (*Log, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	l, err := NewWriterLog(f, key)
	if err != nil {
		f.Close()
		return nil, err
	}
	l.closeFn = f.Close
	return l, nil
}

// OpenReaderLog reads an existing log into memory, verifies the chain,
// and prepares it for appending to w. If w is nil, the log is read-only.
func OpenReaderLog(r io.Reader, w io.Writer, key []byte) (*Log, error) {
	if len(key) < 32 {
		return nil, errors.New("cryptkit/audit: key must be ≥32 bytes")
	}
	recs, err := ReadAll(r)
	if err != nil {
		return nil, err
	}
	if err := Verify(recs, key); err != nil {
		return nil, err
	}
	l := &Log{w: w, key: key}
	if len(recs) > 0 {
		last := recs[len(recs)-1]
		l.seq = last.Seq + 1
		l.prev = last.hashRecord()
	}
	return l, nil
}

// ReadAll decodes a JSONL audit log from r.
func ReadAll(r io.Reader) ([]Record, error) {
	dec := json.NewDecoder(r)
	var out []Record
	for {
		var rec Record
		if err := dec.Decode(&rec); err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			return nil, err
		}
		out = append(out, rec)
	}
}

// Append writes one record. Fields Seq, PrevHash, Signature are filled in.
func (l *Log) Append(r Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return ErrClosed
	}
	if l.w == nil {
		return errors.New("cryptkit/audit: log is read-only")
	}
	r.Seq = l.seq
	if r.Timestamp.IsZero() {
		r.Timestamp = time.Now().UTC().Truncate(time.Millisecond)
	} else {
		r.Timestamp = r.Timestamp.UTC().Truncate(time.Millisecond)
	}
	r.PrevHash = l.prev
	if err := r.sign(l.key); err != nil {
		return err
	}
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if _, err := l.w.Write(body); err != nil {
		return err
	}
	if f, ok := l.w.(*bufio.Writer); ok {
		_ = f.Flush()
	}
	l.seq++
	l.prev = r.hashRecord()
	return nil
}

// Close closes the underlying file if the log owns it.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	if l.closeFn != nil {
		return l.closeFn()
	}
	return nil
}

// Seq returns the next sequence number that will be assigned.
func (l *Log) Seq() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.seq
}
