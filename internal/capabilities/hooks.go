package capabilities

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

const maxAgentHookInput = 64 << 10

type agentHookInput struct {
	HookEventName string `json:"hook_event_name"`
}

type agentHookOutput struct {
	HookSpecificOutput agentHookSpecificOutput `json:"hookSpecificOutput"`
}

type agentHookSpecificOutput struct {
	HookEventName     string `json:"hookEventName"`
	AdditionalContext string `json:"additionalContext"`
}

func ReadClaudeHookEvent(reader io.Reader) (string, error) {
	return readAgentHookEvent(reader, "Claude")
}

func ReadCodexHookEvent(reader io.Reader) (string, error) {
	return readAgentHookEvent(reader, "Codex")
}

func readAgentHookEvent(reader io.Reader, runtime string) (string, error) {
	if reader == nil {
		return "", fmt.Errorf("%s hook input is required", runtime)
	}
	encoded, err := io.ReadAll(io.LimitReader(reader, maxAgentHookInput+1))
	if err != nil || len(encoded) == 0 || len(encoded) > maxAgentHookInput {
		return "", fmt.Errorf("invalid %s hook input", runtime)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	var input agentHookInput
	if err := decoder.Decode(&input); err != nil {
		return "", fmt.Errorf("invalid %s hook input", runtime)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("invalid %s hook input", runtime)
	}
	if input.HookEventName != "SessionStart" && input.HookEventName != "SubagentStart" {
		return "", fmt.Errorf("unsupported %s hook event %q", runtime, input.HookEventName)
	}
	return input.HookEventName, nil
}

func WriteClaudeHook(writer io.Writer, event, context string) error {
	return writeAgentHook(writer, event, context, "Claude")
}

func WriteCodexHook(writer io.Writer, event, context string) error {
	return writeAgentHook(writer, event, context, "Codex")
}

func writeAgentHook(writer io.Writer, event, context, runtime string) error {
	if writer == nil || event != "SessionStart" && event != "SubagentStart" || context == "" || len(context) > MaxContextBytes || !utf8.ValidString(context) {
		return fmt.Errorf("invalid %s hook output", runtime)
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(agentHookOutput{HookSpecificOutput: agentHookSpecificOutput{
		HookEventName: event, AdditionalContext: context,
	}})
}
