package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"go.yaml.in/yaml/v3"
)

const maxYAMLJSONDepth = 128

// UnmarshalYAML keeps JSONMatcherSpec usable from a strict YAML configuration
// while retaining json.RawMessage internally. YAML values are restricted to
// the JSON data model; aliases, anchors, duplicate keys, custom scalar types,
// and non-string mapping keys are rejected.
func (s *JSONMatcherSpec) UnmarshalYAML(node *yaml.Node) error {
	if node == nil || node.Kind != yaml.MappingNode || node.Tag != "!!map" {
		return fmt.Errorf("JSON matcher must be a mapping")
	}
	*s = JSONMatcherSpec{}
	seen := make(map[string]struct{}, len(node.Content)/2)
	for i := 0; i < len(node.Content); i += 2 {
		if i+1 >= len(node.Content) {
			return fmt.Errorf("malformed JSON matcher mapping")
		}
		keyNode, valueNode := node.Content[i], node.Content[i+1]
		key, err := yamlString(keyNode)
		if err != nil {
			return fmt.Errorf("JSON matcher field: %w", err)
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("duplicate JSON matcher field %q", key)
		}
		seen[key] = struct{}{}
		switch key {
		case "pointer":
			value, err := yamlString(valueNode)
			if err != nil {
				return fmt.Errorf("JSON matcher pointer: %w", err)
			}
			s.Pointer = value
		case "op":
			value, err := yamlString(valueNode)
			if err != nil {
				return fmt.Errorf("JSON matcher op: %w", err)
			}
			s.Op = JSONOp(value)
		case "value":
			raw, err := yamlNodeToJSON(valueNode, 0)
			if err != nil {
				return fmt.Errorf("JSON matcher value: %w", err)
			}
			s.Value = json.RawMessage(raw)
		case "values":
			if err := rejectYAMLReference(valueNode); err != nil {
				return fmt.Errorf("JSON matcher values: %w", err)
			}
			if valueNode.Kind != yaml.SequenceNode {
				return fmt.Errorf("JSON matcher values must be a sequence")
			}
			s.Values = make([]json.RawMessage, len(valueNode.Content))
			for j, item := range valueNode.Content {
				raw, err := yamlNodeToJSON(item, 0)
				if err != nil {
					return fmt.Errorf("JSON matcher values[%d]: %w", j, err)
				}
				s.Values[j] = json.RawMessage(raw)
			}
		default:
			return fmt.Errorf("unknown JSON matcher field %q", key)
		}
	}
	return nil
}

func yamlString(node *yaml.Node) (string, error) {
	if err := rejectYAMLReference(node); err != nil {
		return "", err
	}
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return "", fmt.Errorf("must be a string")
	}
	return node.Value, nil
}

func rejectYAMLReference(node *yaml.Node) error {
	if node == nil {
		return fmt.Errorf("value is missing")
	}
	if node.Kind == yaml.AliasNode || node.Alias != nil || node.Anchor != "" {
		return fmt.Errorf("YAML aliases and anchors are not allowed")
	}
	return nil
}

func yamlNodeToJSON(node *yaml.Node, depth int) ([]byte, error) {
	if err := rejectYAMLReference(node); err != nil {
		return nil, err
	}
	if depth > maxYAMLJSONDepth {
		return nil, fmt.Errorf("YAML nesting exceeds %d", maxYAMLJSONDepth)
	}
	switch node.Kind {
	case yaml.DocumentNode:
		if len(node.Content) != 1 {
			return nil, fmt.Errorf("YAML document must contain one value")
		}
		return yamlNodeToJSON(node.Content[0], depth+1)
	case yaml.ScalarNode:
		return yamlScalarToJSON(node)
	case yaml.SequenceNode:
		if node.Tag != "!!seq" {
			return nil, fmt.Errorf("YAML sequence type %q is not a JSON type", node.Tag)
		}
		var result bytes.Buffer
		result.WriteByte('[')
		for i, child := range node.Content {
			if i != 0 {
				result.WriteByte(',')
			}
			encoded, err := yamlNodeToJSON(child, depth+1)
			if err != nil {
				return nil, err
			}
			result.Write(encoded)
		}
		result.WriteByte(']')
		return result.Bytes(), nil
	case yaml.MappingNode:
		if node.Tag != "!!map" {
			return nil, fmt.Errorf("YAML mapping type %q is not a JSON type", node.Tag)
		}
		var result bytes.Buffer
		result.WriteByte('{')
		seen := make(map[string]struct{}, len(node.Content)/2)
		for i := 0; i < len(node.Content); i += 2 {
			if i+1 >= len(node.Content) {
				return nil, fmt.Errorf("malformed YAML mapping")
			}
			key, err := yamlString(node.Content[i])
			if err != nil {
				return nil, fmt.Errorf("JSON object key: %w", err)
			}
			if key == "<<" {
				return nil, fmt.Errorf("YAML merge keys are not allowed")
			}
			if _, duplicate := seen[key]; duplicate {
				return nil, fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}
			if i != 0 {
				result.WriteByte(',')
			}
			encodedKey, _ := json.Marshal(key)
			result.Write(encodedKey)
			result.WriteByte(':')
			encodedValue, err := yamlNodeToJSON(node.Content[i+1], depth+1)
			if err != nil {
				return nil, err
			}
			result.Write(encodedValue)
		}
		result.WriteByte('}')
		return result.Bytes(), nil
	default:
		return nil, fmt.Errorf("unsupported YAML node kind %d", node.Kind)
	}
}

func yamlScalarToJSON(node *yaml.Node) ([]byte, error) {
	switch node.Tag {
	case "!!null":
		return []byte("null"), nil
	case "!!bool":
		switch strings.ToLower(node.Value) {
		case "true":
			return []byte("true"), nil
		case "false":
			return []byte("false"), nil
		default:
			return nil, fmt.Errorf("invalid boolean %q", node.Value)
		}
	case "!!int":
		value := strings.ReplaceAll(node.Value, "_", "")
		if len(value) > maxJSONNumberBytes {
			return nil, fmt.Errorf("integer exceeds %d bytes", maxJSONNumberBytes)
		}
		integer, ok := new(big.Int).SetString(value, 0)
		if !ok {
			return nil, fmt.Errorf("invalid integer %q", node.Value)
		}
		return []byte(integer.String()), nil
	case "!!float":
		value, err := normalizeYAMLFloat(node.Value)
		if err != nil {
			return nil, err
		}
		return []byte(value), nil
	case "!!str":
		return json.Marshal(node.Value)
	default:
		return nil, fmt.Errorf("YAML scalar type %q is not a JSON type", node.Tag)
	}
}

func normalizeYAMLFloat(raw string) (string, error) {
	value := strings.ReplaceAll(raw, "_", "")
	if len(value) > maxJSONNumberBytes {
		return "", fmt.Errorf("number exceeds %d bytes", maxJSONNumberBytes)
	}
	lower := strings.ToLower(value)
	if strings.Contains(lower, ".nan") || strings.Contains(lower, ".inf") {
		return "", fmt.Errorf("non-finite number %q is not JSON", raw)
	}
	if strings.HasPrefix(value, "+") {
		value = value[1:]
	}
	exponentAt := strings.IndexAny(value, "eE")
	mantissa, exponent := value, ""
	if exponentAt >= 0 {
		mantissa, exponent = value[:exponentAt], value[exponentAt:]
	}
	sign := ""
	if strings.HasPrefix(mantissa, "-") {
		sign, mantissa = "-", mantissa[1:]
	}
	if strings.HasPrefix(mantissa, ".") {
		mantissa = "0" + mantissa
	}
	if strings.HasSuffix(mantissa, ".") {
		mantissa += "0"
	}
	integerPart := mantissa
	if dot := strings.IndexByte(mantissa, '.'); dot >= 0 {
		integerPart = mantissa[:dot]
	}
	trimmed := strings.TrimLeft(integerPart, "0")
	if trimmed == "" {
		trimmed = "0"
	}
	mantissa = trimmed + mantissa[len(integerPart):]
	value = sign + mantissa + exponent
	decoded, err := decodeUniqueJSON([]byte(value))
	if err != nil {
		return "", fmt.Errorf("invalid JSON-compatible float %q: %w", raw, err)
	}
	if _, ok := decoded.(json.Number); !ok {
		return "", fmt.Errorf("invalid float %q", raw)
	}
	return value, nil
}
