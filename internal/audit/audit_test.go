package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func validRecord(index int) Record {
	return Record{
		PolicyRevision: "rev-42",
		RuleID:         fmt.Sprintf("rule-%d", index),
		WorkloadID:     "workload-7",
		GrantID:        "grant-9",
		Service:        "github",
		Decision:       DecisionAllow,
		Status:         200,
		Latency:        1500 * time.Microsecond,
		BytesIn:        12,
		BytesOut:       34,
	}
}

func TestOpenCreates0600MetadataOnlyJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := Open(path, FailClosed)
	if err != nil {
		t.Fatal(err)
	}
	const records = 100
	var wg sync.WaitGroup
	for i := 0; i < records; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			if err := logger.Record(validRecord(index)); err != nil {
				t.Errorf("Record: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %04o, want 0600", got)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	seen := 0
	for scanner.Scan() {
		seen++
		var object map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &object); err != nil {
			t.Fatalf("invalid JSONL line: %v: %q", err, scanner.Bytes())
		}
		for _, expected := range []string{
			"timestamp", "policy_revision", "rule_id", "workload_id", "grant_id",
			"service", "decision", "status", "latency_us", "bytes_in", "bytes_out",
		} {
			if _, ok := object[expected]; !ok {
				t.Fatalf("record missing %q: %v", expected, object)
			}
		}
		for _, forbidden := range []string{"body", "token", "authorization", "credential", "secret"} {
			if _, ok := object[forbidden]; ok {
				t.Fatalf("record exposes forbidden field %q", forbidden)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if seen != records {
		t.Fatalf("records = %d, want %d", seen, records)
	}
}

func TestRecordRejectsBearerMaterialInMetadata(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	logger, err := New(&output, FailClosed)
	if err != nil {
		t.Fatal(err)
	}
	record := validRecord(1)
	record.WorkloadID = "ip:127.0.0.1/" + "ff_" + strings.Repeat("A", 43)
	if err := logger.Record(record); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("bearer metadata error = %v", err)
	}
	if output.Len() != 0 {
		t.Fatalf("bearer-shaped metadata was written: %q", output.String())
	}
}

func TestOpenRejectsSymlinkWithoutChangingTarget(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "audit.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if logger, err := Open(link, FailClosed); err == nil {
		_ = logger.Close()
		t.Fatal("Open accepted a symlink")
	}
	contents, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "keep" {
		t.Fatalf("target changed: %q", contents)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Fatalf("target mode changed to %04o", got)
	}
}

type failingWriter struct {
	writes int
}

func (w *failingWriter) Write(value []byte) (int, error) {
	w.writes++
	return 0, errors.New("sink says credential=do-not-leak")
}

func TestFailureModes(t *testing.T) {
	for _, test := range []struct {
		name    string
		mode    FailureMode
		wantErr bool
	}{
		{name: "closed", mode: FailClosed, wantErr: true},
		{name: "open", mode: FailOpen, wantErr: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			writer := &failingWriter{}
			logger, err := New(writer, test.mode)
			if err != nil {
				t.Fatal(err)
			}
			err = logger.Record(validRecord(1))
			if (err != nil) != test.wantErr {
				t.Fatalf("Record error = %v, wantErr %v", err, test.wantErr)
			}
			if !errors.Is(logger.LastError(), ErrWriteFailed) {
				t.Fatalf("LastError = %v", logger.LastError())
			}
			if strings.Contains(fmt.Sprint(logger.LastError()), "do-not-leak") {
				t.Fatalf("sink error leaked through LastError: %v", logger.LastError())
			}
		})
	}
}

func TestFailOpenSuppressesInvalidRecord(t *testing.T) {
	logger, err := New(&bytes.Buffer{}, FailOpen)
	if err != nil {
		t.Fatal(err)
	}
	if err := logger.Record(Record{}); err != nil {
		t.Fatalf("FailOpen returned invalid record error: %v", err)
	}
	if !errors.Is(logger.LastError(), ErrInvalidRecord) {
		t.Fatalf("LastError = %v", logger.LastError())
	}
}

func TestRecordAfterCloseHonorsMode(t *testing.T) {
	for _, test := range []struct {
		mode    FailureMode
		wantErr bool
	}{
		{FailClosed, true},
		{FailOpen, false},
	} {
		logger, err := New(&bytes.Buffer{}, test.mode)
		if err != nil {
			t.Fatal(err)
		}
		_ = logger.Close()
		err = logger.Record(validRecord(1))
		if (err != nil) != test.wantErr {
			t.Fatalf("mode %v: error = %v", test.mode, err)
		}
	}
}

func TestRedactorExactValuesOverlapAndLifetime(t *testing.T) {
	redactor := NewRedactor(nil)
	short, err := redactor.Register([]byte("token"))
	if err != nil {
		t.Fatal(err)
	}
	long, err := redactor.Register([]byte("token-long"))
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := redactor.Register([]byte("token-long"))
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("a token-long and token")
	redacted, changed := redactor.Redact(input)
	if !changed || string(redacted) != "a [REDACTED] and [REDACTED]" {
		t.Fatalf("redacted = %q, changed %v", redacted, changed)
	}
	if string(input) != "a token-long and token" {
		t.Fatalf("input was modified: %q", input)
	}
	if !redactor.Contains(input) {
		t.Fatal("Contains did not detect value")
	}
	_ = long.Close()
	if !redactor.Contains([]byte("token-long")) {
		t.Fatal("duplicate registration was not reference counted")
	}
	_ = duplicate.Close()
	// The shorter exact value still matches inside token-long, as expected for
	// an exact substring guard.
	if !redactor.Contains([]byte("token-long")) {
		t.Fatal("shorter registration unexpectedly absent")
	}
	_ = short.Close()
	if redactor.Contains(input) {
		t.Fatal("closed registrations remain active")
	}
}

func TestRedactorCopiesRegisteredValuesAndConcurrentUse(t *testing.T) {
	redactor := NewRedactor([]byte("X"))
	value := []byte("credential")
	registration, err := redactor.Register(value)
	if err != nil {
		t.Fatal(err)
	}
	value[0] = 'Z'
	if !redactor.Contains([]byte("credential")) {
		t.Fatal("Register retained caller's mutable slice")
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				got, changed := redactor.Redact([]byte("credential"))
				if !changed || string(got) != "X" {
					t.Errorf("Redact = %q, %v", got, changed)
					return
				}
			}
		}()
	}
	wg.Wait()
	_ = registration.Close()
	_ = registration.Close()
	redactor.Clear()
}

func TestRedactorRejectsEmptyValue(t *testing.T) {
	redactor := NewRedactor(nil)
	if _, err := redactor.Register(nil); !errors.Is(err, ErrEmptyRedaction) {
		t.Fatalf("Register empty error = %v", err)
	}
}
