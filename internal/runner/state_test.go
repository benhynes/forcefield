package runner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWriteRunRecordIsPrivateAndSecretFree(t *testing.T) {
	t.Parallel()
	directory := filepath.Join(t.TempDir(), "state")
	record := validRunRecord()
	if err := WriteRunRecord(directory, record); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, record.SandboxID+".json")
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 || !info.Mode().IsRegular() {
		t.Fatalf("state mode = %v", info.Mode())
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), "bearer") || strings.Contains(string(contents), "command") {
		t.Fatalf("state contains forbidden authority fields: %s", contents)
	}
	var decoded RunRecord
	if err := json.Unmarshal(contents, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.TokenID != record.TokenID || decoded.Status != RunStarting {
		t.Fatalf("decoded state = %#v", decoded)
	}
}

func TestWriteRunRecordRejectsUnsafeState(t *testing.T) {
	t.Parallel()
	directory := filepath.Join(t.TempDir(), "state")
	tests := []func(*RunRecord){
		func(record *RunRecord) { record.SandboxID = "../escape" },
		func(record *RunRecord) { record.Agent = "@all" },
		func(record *RunRecord) { record.TokenID = "ff_secret" },
		func(record *RunRecord) { record.Services = append(record.Services, record.Services[0]) },
		func(record *RunRecord) { record.Status = RunRunning },
	}
	for index, mutate := range tests {
		record := validRunRecord()
		mutate(&record)
		if err := WriteRunRecord(directory, record); err == nil {
			t.Fatalf("case %d was accepted", index)
		}
	}
}

func TestWriteRunRecordAcceptsRemoteCapabilityWithoutLocalTokenID(t *testing.T) {
	t.Parallel()
	record := validRunRecord()
	record.TokenID = ""
	record.Workload = "remote-capability"
	if err := WriteRunRecord(filepath.Join(t.TempDir(), "state"), record); err != nil {
		t.Fatal(err)
	}
	record.TokenID = strings.Repeat("c", 64)
	if err := WriteRunRecord(filepath.Join(t.TempDir(), "state"), record); err == nil {
		t.Fatal("remote capability accepted a local token identifier")
	}
}

func validRunRecord() RunRecord {
	return RunRecord{
		Version: runRecordVersion, SandboxID: strings.Repeat("a", 32), Agent: "codex-1", Profile: "worker",
		ProfileDigest: "sha256:" + strings.Repeat("b", 64), TokenID: strings.Repeat("c", 64),
		Workload: "ip:127.0.0.1", Workspace: "/workspace-agent-1", Services: []string{"openai"},
		HiveAgent: "codex-1@vm1", NetworkMode: "isolated",
		Unit:   "forcefield-agent-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.service",
		Status: RunStarting, StartedAt: time.Unix(1_700_000_000, 0).UTC(),
	}
}

func TestReconcileRunRecordsMarksLostProcessFailed(t *testing.T) {
	t.Parallel()
	directory := filepath.Join(t.TempDir(), "state")
	record := validRunRecord()
	record.Status = RunRunning
	record.SupervisorPID = 100
	record.MainPID = 101
	if err := WriteRunRecord(directory, record); err != nil {
		t.Fatal(err)
	}
	if err := ReconcileRunRecords(directory, func(int) bool { return false }); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(filepath.Join(directory, record.SandboxID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var got RunRecord
	if err := json.Unmarshal(contents, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status != RunFailed || got.Reason != "lost_process" || got.StoppedAt == nil {
		t.Fatalf("reconciled record = %#v", got)
	}
}
