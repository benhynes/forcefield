package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/benhynes/forcefield/internal/capabilities"
)

func TestRunCapabilitiesHookLookupFailureReturnsSafeContext(t *testing.T) {
	t.Parallel()
	token := "ff_" + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, format := range []string{"claude-hook", "codex-hook"} {
		format := format
		for _, event := range []string{"SessionStart", "SubagentStart"} {
			event := event
			t.Run(format+"/"+event, func(t *testing.T) {
				t.Parallel()
				input := `{"hook_event_name":` + string(mustJSON(t, event)) + `}`
				var stdout, stderr bytes.Buffer
				err := runCapabilities([]string{
					"--format", format,
					"--url", "https://forcefield.test",
					"--token-file", tokenFile,
					// Fetch validates the timeout after securely reading the token,
					// giving this test a deterministic lookup failure without a network.
					"--timeout", "500ms",
				}, strings.NewReader(input), &stdout, &stderr)
				if err != nil {
					t.Fatalf("hook lookup failure returned an error: %v", err)
				}
				if stderr.String() != "ff: Forcefield capability lookup was not confirmed\n" {
					t.Fatalf("stderr was not generic: %q", stderr.String())
				}
				if strings.Contains(stdout.String(), token) || strings.Contains(stderr.String(), token) || strings.Contains(stderr.String(), tokenFile) {
					t.Fatal("hook failure output exposed token material or its path")
				}

				var output struct {
					HookSpecificOutput struct {
						HookEventName     string `json:"hookEventName"`
						AdditionalContext string `json:"additionalContext"`
					} `json:"hookSpecificOutput"`
				}
				decoder := json.NewDecoder(strings.NewReader(stdout.String()))
				decoder.DisallowUnknownFields()
				if err := decoder.Decode(&output); err != nil {
					t.Fatalf("decode hook output: %v; output=%q", err, stdout.String())
				}
				var trailing any
				if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
					t.Fatalf("hook output was not one JSON value: %v; output=%q", err, stdout.String())
				}
				if output.HookSpecificOutput.HookEventName != event {
					t.Fatalf("hook event = %q", output.HookSpecificOutput.HookEventName)
				}
				if output.HookSpecificOutput.AdditionalContext != capabilities.UnavailableContext() {
					t.Fatalf("additionalContext = %q", output.HookSpecificOutput.AdditionalContext)
				}
			})
		}
	}
}

func TestRunCapabilitiesRejectsMalformedHookEventBeforeLookup(t *testing.T) {
	t.Parallel()
	for _, format := range []string{"claude-hook", "codex-hook"} {
		format := format
		for name, input := range map[string]string{
			"invalid json":      `{"hook_event_name":`,
			"missing event":     `{}`,
			"unsupported event": `{"hook_event_name":"PreToolUse"}`,
			"trailing json":     `{"hook_event_name":"SessionStart"}{}`,
			"oversized":         `{"hook_event_name":"SessionStart"}` + strings.Repeat(" ", 70<<10),
		} {
			name, input := name, input
			t.Run(format+"/"+name, func(t *testing.T) {
				t.Parallel()
				var stdout, stderr bytes.Buffer
				err := runCapabilities([]string{
					"--format", format,
					"--url", "https://forcefield.test",
					"--token-file", filepath.Join(t.TempDir(), "does-not-exist"),
				}, strings.NewReader(input), &stdout, &stderr)
				if err == nil {
					t.Fatal("malformed hook event succeeded")
				}
				if stdout.Len() != 0 || stderr.Len() != 0 {
					t.Fatalf("malformed input emitted output: stdout=%q stderr=%q", stdout.String(), stderr.String())
				}
			})
		}
	}
}

func TestRunCapabilitiesHelpIncludesCodexHook(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if err := runCapabilities([]string{"--help"}, strings.NewReader(""), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if stderr.Len() != 0 || !strings.Contains(stdout.String(), "codex-hook") {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
