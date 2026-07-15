package policy

import (
	"bytes"
	"context"
	"fmt"
	"mime"
	"strings"
	"time"

	"github.com/google/cel-go/cel"
)

const maxCELExpressionBytes = 4096

type celMatcher struct {
	program cel.Program
	timeout time.Duration
}

func newCELEnv() (*cel.Env, error) {
	// Only these four request values are declared. There are no ambient secrets,
	// clocks, network callbacks, or extension functions in the environment.
	return cel.NewEnv(
		cel.Variable("method", cel.StringType),
		cel.Variable("path", cel.StringType),
		cel.Variable("query", cel.MapType(cel.StringType, cel.ListType(cel.StringType))),
		cel.Variable("body", cel.DynType),
		cel.ParserExpressionSizeLimit(maxCELExpressionBytes),
		cel.ParserRecursionLimit(64),
	)
}

func compileCELMatcher(env *cel.Env, spec CELSpec, opts Options) (*celMatcher, error) {
	expression := strings.TrimSpace(spec.Expression)
	if expression == "" {
		return nil, fmt.Errorf("CEL expression is empty")
	}
	if len(expression) > maxCELExpressionBytes {
		return nil, fmt.Errorf("CEL expression exceeds %d bytes", maxCELExpressionBytes)
	}
	checked, issues := env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("compile CEL: %w", issues.Err())
	}
	if !checked.OutputType().IsExactType(cel.BoolType) {
		return nil, fmt.Errorf("CEL expression returns %s, want bool", checked.OutputType())
	}
	program, err := env.Program(
		checked,
		cel.CostLimit(opts.CELCostLimit),
		cel.InterruptCheckFrequency(opts.CELInterruptCheckFrequency),
	)
	if err != nil {
		return nil, fmt.Errorf("build CEL program: %w", err)
	}
	return &celMatcher{program: program, timeout: opts.CELTimeout}, nil
}

func (m *celMatcher) matches(ctx context.Context, request *canonicalRequest) (bool, error) {
	body, err := request.celBody()
	if err != nil {
		return false, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	evalCtx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	value, _, err := m.program.ContextEval(evalCtx, map[string]any{
		"method": request.method,
		"path":   request.path,
		"query":  map[string][]string(request.query),
		"body":   body,
	})
	if err != nil {
		return false, fmt.Errorf("evaluate CEL: %w", err)
	}
	result, ok := value.Value().(bool)
	if !ok {
		return false, fmt.Errorf("CEL returned runtime type %T, want bool", value.Value())
	}
	return result, nil
}

func (r *canonicalRequest) celBody() (any, error) {
	if len(bytes.TrimSpace(r.body)) == 0 {
		return nil, nil
	}
	mediaType, _, err := mime.ParseMediaType(r.contentType)
	if err != nil {
		return nil, fmt.Errorf("invalid content type: %w", err)
	}
	if mediaType != "application/json" && !strings.HasSuffix(mediaType, "+json") {
		// CEL never receives opaque bytes. Silently substituting null here could
		// let an expression which does not mention body authorize uninspected
		// bytes, so an unsupported non-empty body fails closed.
		return nil, fmt.Errorf("CEL cannot inspect content type %q", mediaType)
	}
	document, err := r.parseJSON()
	if err != nil {
		return nil, fmt.Errorf("parse CEL JSON body: %w", err)
	}
	return jsonForCEL(document)
}
