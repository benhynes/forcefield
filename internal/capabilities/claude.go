package capabilities

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

const maxClaudeHookInput = 64 << 10

type claudeHookInput struct {
	HookEventName string `json:"hook_event_name"`
}

type claudeHookOutput struct {
	HookSpecificOutput claudeHookSpecificOutput `json:"hookSpecificOutput"`
}

type claudeHookSpecificOutput struct {
	HookEventName     string `json:"hookEventName"`
	AdditionalContext string `json:"additionalContext"`
}

func ReadClaudeHookEvent(reader io.Reader) (string, error) {
	if reader == nil {
		return "", errors.New("Claude hook input is required")
	}
	encoded, err := io.ReadAll(io.LimitReader(reader, maxClaudeHookInput+1))
	if err != nil || len(encoded) == 0 || len(encoded) > maxClaudeHookInput {
		return "", errors.New("invalid Claude hook input")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	var input claudeHookInput
	if err := decoder.Decode(&input); err != nil {
		return "", errors.New("invalid Claude hook input")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return "", errors.New("invalid Claude hook input")
	}
	if input.HookEventName != "SessionStart" && input.HookEventName != "SubagentStart" {
		return "", fmt.Errorf("unsupported Claude hook event %q", input.HookEventName)
	}
	return input.HookEventName, nil
}

func WriteClaudeHook(writer io.Writer, event, context string) error {
	if writer == nil || event != "SessionStart" && event != "SubagentStart" || context == "" || len(context) > MaxContextBytes || !utf8.ValidString(context) {
		return errors.New("invalid Claude hook output")
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(claudeHookOutput{HookSpecificOutput: claudeHookSpecificOutput{
		HookEventName: event, AdditionalContext: context,
	}})
}
