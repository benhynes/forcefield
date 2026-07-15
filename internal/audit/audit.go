// Package audit writes metadata-only JSON Lines records. Its Record type has
// no fields for request bodies, credential values, or bearer tokens, making
// accidental serialization of those values harder at the API boundary.
package audit

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

const maxMetadataLength = 1024

var (
	ErrInvalidMode   = errors.New("audit: invalid failure mode")
	ErrInvalidRecord = errors.New("audit: invalid record")
	ErrWriteFailed   = errors.New("audit: write failed")
	ErrClosed        = errors.New("audit: logger closed")
)

// FailureMode controls what Record returns when the sink cannot accept an
// audit record.
type FailureMode uint8

const (
	// FailClosed returns a non-nil error so the data plane can deny the request.
	FailClosed FailureMode = iota
	// FailOpen records the failure in LastError but returns nil so traffic can
	// continue. Operators must separately monitor LastError or sink health.
	FailOpen
)

// Decision is the policy outcome recorded for a request.
type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
	DecisionError Decision = "error"
)

// Record contains request metadata only. BytesIn and BytesOut refer to HTTP
// payload sizes; no payload content is accepted by this type.
type Record struct {
	Timestamp      time.Time
	RequestID      string
	TokenID        string
	RootTokenID    string
	PolicyRevision string
	RuleID         string
	Reason         string
	Method         string
	PathHash       string
	WorkloadID     string
	GrantID        string
	Service        string
	Decision       Decision
	Status         int
	Latency        time.Duration
	BytesIn        int64
	BytesOut       int64
}

type wireRecord struct {
	Timestamp      time.Time `json:"timestamp"`
	RequestID      string    `json:"request_id,omitempty"`
	TokenID        string    `json:"token_id,omitempty"`
	RootTokenID    string    `json:"root_token_id,omitempty"`
	PolicyRevision string    `json:"policy_revision,omitempty"`
	RuleID         string    `json:"rule_id,omitempty"`
	Reason         string    `json:"reason,omitempty"`
	Method         string    `json:"method,omitempty"`
	PathHash       string    `json:"path_sha256,omitempty"`
	WorkloadID     string    `json:"workload_id,omitempty"`
	GrantID        string    `json:"grant_id,omitempty"`
	Service        string    `json:"service"`
	Decision       Decision  `json:"decision"`
	Status         int       `json:"status"`
	LatencyMicros  int64     `json:"latency_us"`
	BytesIn        int64     `json:"bytes_in"`
	BytesOut       int64     `json:"bytes_out"`
}

// Logger serializes complete JSONL appends through one mutex. It is safe for
// concurrent use.
type Logger struct {
	mu      sync.Mutex
	writer  io.Writer
	closer  io.Closer
	mode    FailureMode
	now     func() time.Time
	closed  bool
	lastErr error
}

// New constructs a Logger around writer. The caller retains ownership of the
// writer; Close only closes writers opened by Open.
func New(writer io.Writer, mode FailureMode) (*Logger, error) {
	if writer == nil {
		return nil, ErrWriteFailed
	}
	if mode != FailClosed && mode != FailOpen {
		return nil, ErrInvalidMode
	}
	return &Logger{writer: writer, mode: mode, now: time.Now}, nil
}

// Open opens path for synchronized append. New files are created as 0600 and
// the descriptor is verified to refer to a regular file. Existing files are
// tightened to 0600 before use.
func Open(path string, mode FailureMode) (*Logger, error) {
	if mode != FailClosed && mode != FailOpen {
		return nil, ErrInvalidMode
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, ErrWriteFailed
	}
	closeOnError := func() (*Logger, error) {
		_ = file.Close()
		return nil, ErrWriteFailed
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return closeOnError()
	}
	// Refuse a symlink even though its target may be a regular file. Comparing
	// the opened descriptor with Lstat also catches a path replacement between
	// creation/open and validation.
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, pathInfo) {
		return closeOnError()
	}
	if err := file.Chmod(0o600); err != nil {
		return closeOnError()
	}
	logger, err := New(file, mode)
	if err != nil {
		return closeOnError()
	}
	logger.closer = file
	return logger, nil
}

// Record appends one JSON object and newline. In FailOpen mode a sink or
// validation failure is retained in LastError but suppressed from the caller.
func (l *Logger) Record(record Record) error {
	if l == nil {
		return ErrClosed
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return l.handleErrorLocked(ErrClosed)
	}
	if record.Timestamp.IsZero() {
		record.Timestamp = l.now().UTC()
	} else {
		record.Timestamp = record.Timestamp.UTC()
	}
	if err := validate(record); err != nil {
		return l.handleErrorLocked(err)
	}
	wire := wireRecord{
		Timestamp:      record.Timestamp,
		RequestID:      record.RequestID,
		TokenID:        record.TokenID,
		RootTokenID:    record.RootTokenID,
		PolicyRevision: record.PolicyRevision,
		RuleID:         record.RuleID,
		Reason:         record.Reason,
		Method:         record.Method,
		PathHash:       record.PathHash,
		WorkloadID:     record.WorkloadID,
		GrantID:        record.GrantID,
		Service:        record.Service,
		Decision:       record.Decision,
		Status:         record.Status,
		LatencyMicros:  record.Latency.Microseconds(),
		BytesIn:        record.BytesIn,
		BytesOut:       record.BytesOut,
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return l.handleErrorLocked(ErrInvalidRecord)
	}
	encoded = append(encoded, '\n')
	if err := writeAll(l.writer, encoded); err != nil {
		return l.handleErrorLocked(ErrWriteFailed)
	}
	l.lastErr = nil
	return nil
}

// LastError reports the most recent suppressed or returned record failure.
// Errors are deliberately value-free so they can be logged safely.
func (l *Logger) LastError() error {
	if l == nil {
		return ErrClosed
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lastErr
}

// Healthy reports whether the most recent Record operation succeeded.
func (l *Logger) Healthy() bool { return l.LastError() == nil }

// Close serializes with active writes and closes a file opened by Open. Close
// errors are always returned regardless of FailureMode because no request is
// being authorized by this operation.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	if l.closer != nil {
		if err := l.closer.Close(); err != nil {
			l.lastErr = ErrWriteFailed
			return ErrWriteFailed
		}
	}
	return nil
}

func (l *Logger) handleErrorLocked(err error) error {
	l.lastErr = err
	if l.mode == FailOpen {
		return nil
	}
	return err
}

func validate(record Record) error {
	if record.Timestamp.Year() < 1 || record.Service == "" {
		return ErrInvalidRecord
	}
	if record.Decision != DecisionAllow && record.Decision != DecisionDeny && record.Decision != DecisionError {
		return ErrInvalidRecord
	}
	if record.Status < 0 || record.Status > 999 || record.Latency < 0 || record.BytesIn < 0 || record.BytesOut < 0 {
		return ErrInvalidRecord
	}
	for _, value := range []string{
		record.RequestID,
		record.TokenID,
		record.RootTokenID,
		record.PolicyRevision,
		record.RuleID,
		record.Reason,
		record.Method,
		record.PathHash,
		record.WorkloadID,
		record.GrantID,
		record.Service,
	} {
		if len(value) > maxMetadataLength || containsForcefieldBearer(value) {
			return ErrInvalidRecord
		}
	}
	return nil
}

func containsForcefieldBearer(value string) bool {
	const (
		prefix       = "ff_"
		encodedBytes = 32
	)
	encodedLength := base64.RawURLEncoding.EncodedLen(encodedBytes)
	for offset := 0; ; {
		index := strings.Index(value[offset:], prefix)
		if index < 0 {
			return false
		}
		index += offset
		end := index + len(prefix) + encodedLength
		if end <= len(value) {
			raw, err := base64.RawURLEncoding.DecodeString(value[index+len(prefix) : end])
			if err == nil && len(raw) == encodedBytes {
				return true
			}
		}
		offset = index + len(prefix)
	}
}

func writeAll(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		n, err := writer.Write(value)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(value) {
			return io.ErrShortWrite
		}
		value = value[n:]
	}
	return nil
}
