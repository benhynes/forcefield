package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"mime"
	"strconv"
	"strings"
	"unicode/utf8"

	celtypes "github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

const maxJSONDepth = 128

const (
	maxJSONNumberBytes    = 1024
	maxJSONNumberExponent = 10_000
)

// decodeUniqueJSON decodes exactly one JSON value without converting numbers
// through float64 and rejects duplicate keys at every object depth.
func decodeUniqueJSON(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("JSON is not valid UTF-8")
	}
	if err := validateJSONSurrogates(data); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	value, err := decodeJSONValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("multiple JSON values")
		}
		return nil, fmt.Errorf("trailing JSON data: %w", err)
	}
	return value, nil
}

func validateJSONSurrogates(data []byte) error {
	for index := 0; index < len(data); index++ {
		if data[index] != '"' {
			continue
		}
		for index++; index < len(data); index++ {
			switch data[index] {
			case '"':
				goto stringDone
			case '\\':
				if index+1 >= len(data) {
					return fmt.Errorf("unterminated JSON escape")
				}
				if data[index+1] != 'u' {
					index++
					continue
				}
				code, ok := parseJSONHex4(data, index+2)
				if !ok {
					return fmt.Errorf("invalid JSON unicode escape")
				}
				index += 5
				switch {
				case code >= 0xd800 && code <= 0xdbff:
					if index+6 >= len(data) || data[index+1] != '\\' || data[index+2] != 'u' {
						return fmt.Errorf("unpaired high surrogate in JSON string")
					}
					low, valid := parseJSONHex4(data, index+3)
					if !valid || low < 0xdc00 || low > 0xdfff {
						return fmt.Errorf("unpaired high surrogate in JSON string")
					}
					index += 6
				case code >= 0xdc00 && code <= 0xdfff:
					return fmt.Errorf("unpaired low surrogate in JSON string")
				}
			}
		}
		return fmt.Errorf("unterminated JSON string")
	stringDone:
	}
	return nil
}

func parseJSONHex4(data []byte, start int) (uint16, bool) {
	if start+4 > len(data) {
		return 0, false
	}
	var result uint16
	for _, value := range data[start : start+4] {
		result <<= 4
		switch {
		case value >= '0' && value <= '9':
			result |= uint16(value - '0')
		case value >= 'a' && value <= 'f':
			result |= uint16(value-'a') + 10
		case value >= 'A' && value <= 'F':
			result |= uint16(value-'A') + 10
		default:
			return 0, false
		}
	}
	return result, true
}

func decodeJSONValue(dec *json.Decoder, depth int) (any, error) {
	if depth > maxJSONDepth {
		return nil, fmt.Errorf("JSON nesting exceeds %d", maxJSONDepth)
	}
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		if number, ok := token.(json.Number); ok {
			if err := validateJSONNumber(number); err != nil {
				return nil, err
			}
		}
		return token, nil
	}
	switch delim {
	case '{':
		object := make(map[string]any)
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, fmt.Errorf("JSON object key is not a string")
			}
			if _, duplicate := object[key]; duplicate {
				return nil, fmt.Errorf("duplicate JSON key %q", key)
			}
			value, err := decodeJSONValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim('}') {
			return nil, fmt.Errorf("unterminated JSON object")
		}
		return object, nil
	case '[':
		array := make([]any, 0)
		for dec.More() {
			value, err := decodeJSONValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim(']') {
			return nil, fmt.Errorf("unterminated JSON array")
		}
		return array, nil
	default:
		return nil, fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
}

func validateJSONNumber(number json.Number) error {
	value := number.String()
	if len(value) > maxJSONNumberBytes {
		return fmt.Errorf("JSON number exceeds %d bytes", maxJSONNumberBytes)
	}
	exponentAt := strings.IndexAny(value, "eE")
	if exponentAt < 0 {
		return nil
	}
	exponent := value[exponentAt+1:]
	if strings.HasPrefix(exponent, "+") || strings.HasPrefix(exponent, "-") {
		exponent = exponent[1:]
	}
	if len(exponent) > 6 {
		return fmt.Errorf("JSON number exponent exceeds %d", maxJSONNumberExponent)
	}
	magnitude, err := strconv.Atoi(exponent)
	if err != nil || magnitude > maxJSONNumberExponent {
		return fmt.Errorf("JSON number exponent exceeds %d", maxJSONNumberExponent)
	}
	return nil
}

type jsonMatcher struct {
	pointer []string
	op      JSONOp
	values  []any
}

func compileJSONMatcher(spec JSONMatcherSpec) (jsonMatcher, error) {
	pointer, err := compileJSONPointer(spec.Pointer)
	if err != nil {
		return jsonMatcher{}, err
	}
	matcher := jsonMatcher{pointer: pointer, op: spec.Op}
	switch spec.Op {
	case JSONEqual:
		if len(spec.Value) == 0 || len(spec.Values) != 0 {
			return jsonMatcher{}, fmt.Errorf("eq requires value and forbids values")
		}
		value, err := decodeUniqueJSON(spec.Value)
		if err != nil {
			return jsonMatcher{}, fmt.Errorf("invalid comparison value: %w", err)
		}
		matcher.values = []any{value}
	case JSONIn:
		if len(spec.Value) != 0 || len(spec.Values) == 0 {
			return jsonMatcher{}, fmt.Errorf("in requires non-empty values and forbids value")
		}
		matcher.values = make([]any, len(spec.Values))
		for i, raw := range spec.Values {
			value, err := decodeUniqueJSON(raw)
			if err != nil {
				return jsonMatcher{}, fmt.Errorf("invalid comparison value %d: %w", i, err)
			}
			matcher.values[i] = value
		}
	default:
		return jsonMatcher{}, fmt.Errorf("unsupported JSON operation %q", spec.Op)
	}
	return matcher, nil
}

func compileJSONPointer(pointer string) ([]string, error) {
	if pointer == "" {
		return nil, nil
	}
	if !strings.HasPrefix(pointer, "/") {
		return nil, fmt.Errorf("JSON pointer must be empty or begin with /")
	}
	raw := strings.Split(pointer[1:], "/")
	parts := make([]string, len(raw))
	for i, part := range raw {
		var b strings.Builder
		for j := 0; j < len(part); j++ {
			if part[j] != '~' {
				b.WriteByte(part[j])
				continue
			}
			if j+1 >= len(part) {
				return nil, fmt.Errorf("invalid ~ escape in JSON pointer")
			}
			j++
			switch part[j] {
			case '0':
				b.WriteByte('~')
			case '1':
				b.WriteByte('/')
			default:
				return nil, fmt.Errorf("invalid ~ escape in JSON pointer")
			}
		}
		parts[i] = b.String()
	}
	return parts, nil
}

func (m jsonMatcher) matches(document any) bool {
	value, found := lookupJSONPointer(document, m.pointer)
	if !found {
		return false
	}
	for _, candidate := range m.values {
		if jsonEqual(value, candidate) {
			return true
		}
	}
	return false
}

func lookupJSONPointer(value any, pointer []string) (any, bool) {
	current := value
	for _, part := range pointer {
		switch node := current.(type) {
		case map[string]any:
			var ok bool
			current, ok = node[part]
			if !ok {
				return nil, false
			}
		case []any:
			if part == "" || (len(part) > 1 && part[0] == '0') {
				return nil, false
			}
			index, err := strconv.ParseUint(part, 10, 31)
			if err != nil || index >= uint64(len(node)) {
				return nil, false
			}
			current = node[index]
		default:
			return nil, false
		}
	}
	return current, true
}

func jsonEqual(left, right any) bool {
	switch l := left.(type) {
	case nil:
		return right == nil
	case bool:
		r, ok := right.(bool)
		return ok && l == r
	case string:
		r, ok := right.(string)
		return ok && l == r
	case json.Number:
		r, ok := right.(json.Number)
		if !ok {
			return false
		}
		lr, lok := new(big.Rat).SetString(l.String())
		rr, rok := new(big.Rat).SetString(r.String())
		return lok && rok && lr.Cmp(rr) == 0
	case []any:
		r, ok := right.([]any)
		if !ok || len(l) != len(r) {
			return false
		}
		for i := range l {
			if !jsonEqual(l[i], r[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		r, ok := right.(map[string]any)
		if !ok || len(l) != len(r) {
			return false
		}
		for key, value := range l {
			other, ok := r[key]
			if !ok || !jsonEqual(value, other) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func (r *canonicalRequest) parseJSON() (any, error) {
	if !r.jsonParsed {
		r.jsonParsed = true
		mediaType, parameters, err := mime.ParseMediaType(r.contentType)
		if err != nil || mediaType != "application/json" && !strings.HasSuffix(mediaType, "+json") {
			r.jsonErr = fmt.Errorf("JSON matcher requires application/json or +json content type")
		} else if !validJSONMediaParameters(parameters) {
			r.jsonErr = fmt.Errorf("JSON matcher requires UTF-8 without semantic media parameters")
		} else if len(bytes.TrimSpace(r.body)) == 0 {
			r.jsonErr = fmt.Errorf("empty JSON body")
		} else {
			r.json, r.jsonErr = decodeUniqueJSON(r.body)
		}
	}
	return r.json, r.jsonErr
}

func validJSONMediaParameters(parameters map[string]string) bool {
	for name, value := range parameters {
		if name != "charset" || !strings.EqualFold(value, "utf-8") {
			return false
		}
	}
	return true
}

// jsonForCEL wraps decoded JSON in a lazy CEL adapter. An unrelated decimal
// therefore cannot break a policy which only inspects an integer field, while
// any decimal that is actually inspected must have an exact CEL double
// representation or evaluation fails closed.
func jsonForCEL(value any) (any, error) {
	return (jsonCELAdapter{}).NativeToValue(value), nil
}

type jsonCELAdapter struct{}

func (adapter jsonCELAdapter) NativeToValue(value any) ref.Val {
	switch value := value.(type) {
	case json.Number:
		if integer, err := value.Int64(); err == nil {
			return celtypes.Int(integer)
		}
		if !strings.ContainsAny(value.String(), ".eE") && !strings.HasPrefix(value.String(), "-") {
			if integer, err := strconv.ParseUint(value.String(), 10, 64); err == nil {
				return celtypes.Uint(integer)
			}
		}
		double, err := value.Float64()
		if err != nil || math.IsInf(double, 0) || math.IsNaN(double) {
			return celtypes.NewErr("JSON number is outside CEL numeric range")
		}
		exact, exactOK := new(big.Rat).SetString(value.String())
		binary := new(big.Rat).SetFloat64(double)
		if !exactOK || binary == nil || exact.Cmp(binary) != 0 {
			return celtypes.NewErr("JSON number cannot be represented exactly in CEL")
		}
		return celtypes.Double(double)
	case []any:
		return celtypes.NewDynamicList(adapter, value)
	case map[string]any:
		return celtypes.NewStringInterfaceMap(adapter, value)
	default:
		return celtypes.DefaultTypeAdapter.NativeToValue(value)
	}
}
