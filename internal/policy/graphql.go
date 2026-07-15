package policy

import (
	"bytes"
	"fmt"
	"mime"
	"regexp"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

var graphqlName = regexp.MustCompile(`^[_A-Za-z][_0-9A-Za-z]*$`)

const (
	maxGraphQLExpansionDepth = 128
	maxGraphQLSyntaxDepth    = 128
	maxGraphQLTokens         = 10_000
)

type graphqlMatcher struct {
	operationType string
	operationName string
	rootFields    map[string]struct{}
}

type graphqlRequest struct {
	operationType string
	operationName string
	rootFields    map[string]struct{}
}

func compileGraphQLMatcher(spec GraphQLSpec) (graphqlMatcher, error) {
	matcher := graphqlMatcher{
		operationType: spec.OperationType,
		operationName: spec.OperationName,
	}
	if matcher.operationType != "" && matcher.operationType != "query" &&
		matcher.operationType != "mutation" && matcher.operationType != "subscription" {
		return graphqlMatcher{}, fmt.Errorf("unsupported operation type %q", matcher.operationType)
	}
	if matcher.operationName != "" && !graphqlName.MatchString(matcher.operationName) {
		return graphqlMatcher{}, fmt.Errorf("invalid operation name %q", matcher.operationName)
	}
	if len(spec.RootFields) != 0 {
		matcher.rootFields = make(map[string]struct{}, len(spec.RootFields))
		for _, field := range spec.RootFields {
			if !graphqlName.MatchString(field) {
				return graphqlMatcher{}, fmt.Errorf("invalid root field %q", field)
			}
			if _, duplicate := matcher.rootFields[field]; duplicate {
				return graphqlMatcher{}, fmt.Errorf("duplicate root field %q", field)
			}
			matcher.rootFields[field] = struct{}{}
		}
	}
	if matcher.operationType == "" && matcher.operationName == "" && matcher.rootFields == nil {
		return graphqlMatcher{}, fmt.Errorf("GraphQL matcher has no constraints")
	}
	return matcher, nil
}

func (m graphqlMatcher) matches(request *graphqlRequest) bool {
	if m.operationType != "" && request.operationType != m.operationType {
		return false
	}
	if m.operationName != "" && request.operationName != m.operationName {
		return false
	}
	if m.rootFields != nil {
		if len(request.rootFields) == 0 {
			return false
		}
		// RootFields is an allowlist, not an existential predicate: every field
		// which may execute must be listed.
		for field := range request.rootFields {
			if _, allowed := m.rootFields[field]; !allowed {
				return false
			}
		}
	}
	return true
}

func (r *canonicalRequest) parseGraphQL() (*graphqlRequest, error) {
	if r.graphqlParsed {
		return r.graphql, r.graphqlErr
	}
	r.graphqlParsed = true

	query, operationName, err := r.graphqlPayload()
	if err != nil {
		r.graphqlErr = err
		return nil, err
	}
	if err := validateGraphQLSyntaxDepth(query); err != nil {
		r.graphqlErr = err
		return nil, err
	}
	document, parseErr := parser.ParseQueryWithTokenLimit(&ast.Source{Name: "request.graphql", Input: query}, maxGraphQLTokens)
	if parseErr != nil {
		r.graphqlErr = fmt.Errorf("invalid GraphQL document: %w", parseErr)
		return nil, r.graphqlErr
	}
	operation, err := selectGraphQLOperation(document, operationName)
	if err != nil {
		r.graphqlErr = err
		return nil, err
	}
	fields, err := graphqlRootFields(document, operation.SelectionSet)
	if err != nil {
		r.graphqlErr = err
		return nil, err
	}
	r.graphql = &graphqlRequest{
		operationType: string(operation.Operation),
		operationName: operation.Name,
		rootFields:    fields,
	}
	return r.graphql, nil
}

func validateGraphQLSyntaxDepth(document string) error {
	depth := 0
	for index := 0; index < len(document); index++ {
		switch document[index] {
		case '#':
			for index < len(document) && document[index] != '\n' && document[index] != '\r' {
				index++
			}
		case '"':
			if index+2 < len(document) && document[index:index+3] == `"""` {
				index += 3
				for index+2 < len(document) {
					if document[index] == '\\' {
						index += 2
						continue
					}
					if document[index:index+3] == `"""` {
						index += 2
						break
					}
					index++
				}
			} else {
				for index++; index < len(document); index++ {
					if document[index] == '\\' {
						index++
						continue
					}
					if document[index] == '"' {
						break
					}
				}
			}
		case '{', '[', '(':
			depth++
			if depth > maxGraphQLSyntaxDepth {
				return fmt.Errorf("GraphQL syntax nesting exceeds %d", maxGraphQLSyntaxDepth)
			}
		case '}', ']', ')':
			if depth > 0 {
				depth--
			}
		}
	}
	return nil
}

func (r *canonicalRequest) graphqlPayload() (query, operationName string, err error) {
	if r.method == "GET" {
		if len(bytes.TrimSpace(r.body)) != 0 {
			return "", "", fmt.Errorf("GraphQL GET must not include a body")
		}
		queries := r.query["query"]
		if len(queries) != 1 {
			return "", "", fmt.Errorf("GraphQL GET requires exactly one query parameter")
		}
		names := r.query["operationName"]
		if len(names) > 1 {
			return "", "", fmt.Errorf("GraphQL GET has duplicate operationName")
		}
		if len(names) == 1 {
			operationName = names[0]
		}
		return queries[0], operationName, nil
	}
	if r.method != "POST" {
		return "", "", fmt.Errorf("GraphQL body mode requires POST")
	}
	if _, exists := r.query["query"]; exists {
		return "", "", fmt.Errorf("GraphQL POST must not include a query URL parameter")
	}
	if _, exists := r.query["operationName"]; exists {
		return "", "", fmt.Errorf("GraphQL POST must not include an operationName URL parameter")
	}

	mediaType, _, parseErr := mime.ParseMediaType(r.contentType)
	if parseErr != nil {
		return "", "", fmt.Errorf("invalid content type: %w", parseErr)
	}
	switch {
	case mediaType == "application/graphql":
		if len(bytes.TrimSpace(r.body)) == 0 {
			return "", "", fmt.Errorf("empty GraphQL body")
		}
		return string(r.body), "", nil
	case mediaType == "application/json" || strings.HasSuffix(mediaType, "+json"):
		document, err := r.parseJSON()
		if err != nil {
			return "", "", fmt.Errorf("invalid GraphQL JSON envelope: %w", err)
		}
		object, ok := document.(map[string]any)
		if !ok {
			return "", "", fmt.Errorf("GraphQL JSON envelope must be an object")
		}
		queryValue, ok := object["query"]
		if !ok {
			return "", "", fmt.Errorf("GraphQL JSON envelope is missing query")
		}
		query, ok = queryValue.(string)
		if !ok || query == "" {
			return "", "", fmt.Errorf("GraphQL query must be a non-empty string")
		}
		if nameValue, exists := object["operationName"]; exists && nameValue != nil {
			operationName, ok = nameValue.(string)
			if !ok {
				return "", "", fmt.Errorf("GraphQL operationName must be a string or null")
			}
		}
		return query, operationName, nil
	default:
		return "", "", fmt.Errorf("unsupported GraphQL content type %q", mediaType)
	}
}

func selectGraphQLOperation(document *ast.QueryDocument, name string) (*ast.OperationDefinition, error) {
	seenNames := make(map[string]struct{}, len(document.Operations))
	for _, operation := range document.Operations {
		if operation.Name == "" {
			continue
		}
		if _, duplicate := seenNames[operation.Name]; duplicate {
			return nil, fmt.Errorf("duplicate GraphQL operation name %q", operation.Name)
		}
		seenNames[operation.Name] = struct{}{}
	}
	if name != "" {
		for _, operation := range document.Operations {
			if operation.Name == name {
				return operation, nil
			}
		}
		return nil, fmt.Errorf("GraphQL operation %q was not found", name)
	}
	if len(document.Operations) != 1 {
		return nil, fmt.Errorf("GraphQL document requires operationName when it has %d operations", len(document.Operations))
	}
	return document.Operations[0], nil
}

func graphqlRootFields(document *ast.QueryDocument, selections ast.SelectionSet) (map[string]struct{}, error) {
	fragments := make(map[string]*ast.FragmentDefinition, len(document.Fragments))
	for _, fragment := range document.Fragments {
		if _, duplicate := fragments[fragment.Name]; duplicate {
			return nil, fmt.Errorf("duplicate GraphQL fragment %q", fragment.Name)
		}
		fragments[fragment.Name] = fragment
	}
	fields := make(map[string]struct{})
	visiting := make(map[string]bool)
	var walk func(ast.SelectionSet, int) error
	walk = func(set ast.SelectionSet, depth int) error {
		if depth > maxGraphQLExpansionDepth {
			return fmt.Errorf("GraphQL selection expansion exceeds %d", maxGraphQLExpansionDepth)
		}
		for _, selection := range set {
			switch selection := selection.(type) {
			case *ast.Field:
				// Use the actual field name, never the client-controlled alias.
				fields[selection.Name] = struct{}{}
			case *ast.InlineFragment:
				if err := walk(selection.SelectionSet, depth+1); err != nil {
					return err
				}
			case *ast.FragmentSpread:
				fragment, ok := fragments[selection.Name]
				if !ok {
					return fmt.Errorf("undefined GraphQL fragment %q", selection.Name)
				}
				if visiting[selection.Name] {
					return fmt.Errorf("cyclic GraphQL fragment %q", selection.Name)
				}
				visiting[selection.Name] = true
				if err := walk(fragment.SelectionSet, depth+1); err != nil {
					return err
				}
				delete(visiting, selection.Name)
			default:
				return fmt.Errorf("unsupported GraphQL selection")
			}
		}
		return nil
	}
	if err := walk(selections, 0); err != nil {
		return nil, err
	}
	return fields, nil
}
