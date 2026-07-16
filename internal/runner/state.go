package runner

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const runRecordVersion = 1

type RunStatus string

const (
	RunStarting RunStatus = "starting"
	RunRunning  RunStatus = "running"
	RunExited   RunStatus = "exited"
	RunFailed   RunStatus = "failed"
)

// RunRecord is the secret-free crash and audit correlation record for one
// sandbox. It intentionally omits the command, environment, bearer, and TLS
// key paths.
type RunRecord struct {
	Version       int        `json:"version"`
	SandboxID     string     `json:"sandbox_id"`
	Agent         string     `json:"agent"`
	Profile       string     `json:"profile"`
	ProfileDigest string     `json:"profile_digest"`
	TokenID       string     `json:"token_id"`
	Workload      string     `json:"workload"`
	Workspace     string     `json:"workspace"`
	Services      []string   `json:"services"`
	HiveAgent     string     `json:"hive_agent,omitempty"`
	Unit          string     `json:"unit"`
	Status        RunStatus  `json:"status"`
	SupervisorPID int        `json:"supervisor_pid,omitempty"`
	MainPID       int        `json:"main_pid,omitempty"`
	ExitCode      *int       `json:"exit_code,omitempty"`
	StartedAt     time.Time  `json:"started_at"`
	StoppedAt     *time.Time `json:"stopped_at,omitempty"`
}

func NewSandboxID() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", errors.New("generate sandbox identifier")
	}
	return hex.EncodeToString(random[:]), nil
}

func PrepareStateDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return errors.New("runner state directory must be a clean absolute path")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return errors.New("create runner state directory")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("runner state directory must be a non-symlink private directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("runner state directory must be owned by the runner")
	}
	return nil
}

func WriteRunRecord(directory string, record RunRecord) error {
	if err := PrepareStateDirectory(directory); err != nil {
		return err
	}
	if err := validateRunRecord(record); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return errors.New("encode runner state")
	}
	encoded = append(encoded, '\n')
	temporary, err := os.CreateTemp(directory, ".run-*.tmp")
	if err != nil {
		return errors.New("create runner state file")
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return errors.New("secure runner state file")
	}
	if _, err := temporary.Write(encoded); err != nil {
		return errors.New("write runner state file")
	}
	if err := temporary.Sync(); err != nil {
		return errors.New("sync runner state file")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("close runner state file")
	}
	destination := filepath.Join(directory, record.SandboxID+".json")
	if err := os.Rename(temporaryPath, destination); err != nil {
		return errors.New("commit runner state file")
	}
	committed = true
	directoryFile, err := os.Open(directory)
	if err != nil {
		return errors.New("open runner state directory")
	}
	defer directoryFile.Close()
	if err := directoryFile.Sync(); err != nil {
		return errors.New("sync runner state directory")
	}
	return nil
}

func validateRunRecord(record RunRecord) error {
	if record.Version != runRecordVersion {
		return errors.New("runner state version must be 1")
	}
	if len(record.SandboxID) != 32 || strings.ToLower(record.SandboxID) != record.SandboxID {
		return errors.New("invalid sandbox identifier")
	}
	if decoded, err := hex.DecodeString(record.SandboxID); err != nil || len(decoded) != 16 {
		return errors.New("invalid sandbox identifier")
	}
	if !validIdentifier(record.Agent) || !validIdentifier(record.Profile) {
		return errors.New("invalid runner identity")
	}
	if len(record.ProfileDigest) != len("sha256:")+64 || !strings.HasPrefix(record.ProfileDigest, "sha256:") {
		return errors.New("invalid runner profile digest")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(record.ProfileDigest, "sha256:")); err != nil {
		return errors.New("invalid runner profile digest")
	}
	if len(record.TokenID) != 64 {
		return errors.New("invalid runner token identifier")
	}
	if _, err := hex.DecodeString(record.TokenID); err != nil {
		return errors.New("invalid runner token identifier")
	}
	if record.Workload == "" || !filepath.IsAbs(record.Workspace) || filepath.Clean(record.Workspace) != record.Workspace {
		return errors.New("invalid runner workload or workspace")
	}
	if len(record.Services) == 0 {
		return errors.New("runner state requires granted services")
	}
	if record.HiveAgent != "" && (!validHiveAddress(record.HiveAgent) || !strings.Contains(record.HiveAgent, "@")) {
		return errors.New("invalid runner Hive identity")
	}
	if !validSystemdUnit(record.Unit) {
		return errors.New("invalid runner systemd unit")
	}
	seenServices := make(map[string]struct{}, len(record.Services))
	for _, service := range record.Services {
		if !validIdentifier(service) {
			return errors.New("invalid runner service")
		}
		if _, exists := seenServices[service]; exists {
			return errors.New("duplicate runner service")
		}
		seenServices[service] = struct{}{}
	}
	if record.StartedAt.IsZero() || record.StartedAt.Location() != time.UTC {
		return errors.New("invalid runner start time")
	}
	switch record.Status {
	case RunStarting:
		if record.SupervisorPID != 0 || record.MainPID != 0 || record.ExitCode != nil || record.StoppedAt != nil {
			return errors.New("invalid starting runner state")
		}
	case RunRunning:
		if record.SupervisorPID < 1 || record.MainPID < 0 || record.ExitCode != nil || record.StoppedAt != nil {
			return errors.New("invalid running runner state")
		}
	case RunExited, RunFailed:
		if record.StoppedAt == nil || record.StoppedAt.Location() != time.UTC || record.StoppedAt.Before(record.StartedAt) {
			return errors.New("invalid stopped runner state")
		}
		if record.Status == RunExited && record.ExitCode == nil {
			return errors.New("exited runner state requires an exit code")
		}
	default:
		return fmt.Errorf("invalid runner status %q", record.Status)
	}
	return nil
}
