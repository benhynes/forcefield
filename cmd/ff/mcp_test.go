package main

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/benhynes/forcefield/internal/capabilities"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestCapabilityMCPServerExposesOneSanitizedLiveTool(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	manifest := capabilities.Manifest{
		Version: capabilities.SchemaVersion, GeneratedAt: now, ExpiresAt: now.Add(time.Hour),
		Services: []capabilities.Service{{
			Name: "github", Adapter: "http", BaseURL: "https://forcefield.example/github",
			PathPrefix: "/github", Auth: capabilities.Auth{Header: "Authorization", Prefix: "Bearer "},
			CapabilitySummary: "Read selected repository resources.",
		}},
	}
	options := capabilities.ClientOptions{
		BaseURL: "https://forcefield.example", TokenFile: "/run/forcefield/token",
		CACertPath: "/run/forcefield/ca.crt", ClientCert: "/run/forcefield/client.crt",
		ClientKey: "/run/forcefield/client.key", Timeout: 7 * time.Second,
	}
	var calls atomic.Int64
	server := newCapabilityMCPServer(options, func(_ context.Context, got capabilities.ClientOptions) (capabilities.Manifest, error) {
		if got.BaseURL != options.BaseURL || got.TokenFile != options.TokenFile || got.CACertPath != options.CACertPath ||
			got.ClientCert != options.ClientCert || got.ClientKey != options.ClientKey || got.Timeout != options.Timeout {
			return capabilities.Manifest{}, errors.New("client options were not propagated")
		}
		calls.Add(1)
		return manifest, nil
	})
	client, session := connectMCPTest(t, server)
	defer client.Close()
	defer session.Close()

	listed, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Tools) != 1 || listed.Tools[0].Name != capabilityMCPToolName || listed.Tools[0].Annotations == nil ||
		!listed.Tools[0].Annotations.ReadOnlyHint || !listed.Tools[0].Annotations.IdempotentHint ||
		listed.Tools[0].Annotations.OpenWorldHint == nil || *listed.Tools[0].Annotations.OpenWorldHint ||
		listed.Tools[0].Meta["anthropic/alwaysLoad"] != true {
		t.Fatalf("tools = %#v", listed.Tools)
	}
	for attempt := 0; attempt < 2; attempt++ {
		result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: capabilityMCPToolName})
		if err != nil {
			t.Fatal(err)
		}
		if result.IsError || len(result.Content) != 1 {
			t.Fatalf("result=%#v", result)
		}
		text, ok := result.Content[0].(*mcp.TextContent)
		if !ok || !strings.Contains(text.Text, "Read selected repository resources") ||
			!strings.Contains(text.Text, options.ClientCert) || !strings.Contains(text.Text, options.ClientKey) || strings.Contains(text.Text, "ff_") {
			t.Fatalf("content = %#v", result.Content)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("live fetch calls = %d, want 2", calls.Load())
	}
}

func TestCapabilityMCPServerFailsClosedWithoutStaleContext(t *testing.T) {
	t.Parallel()
	server := newCapabilityMCPServer(capabilities.ClientOptions{}, func(context.Context, capabilities.ClientOptions) (capabilities.Manifest, error) {
		return capabilities.Manifest{}, errors.New("secret backend detail")
	})
	client, session := connectMCPTest(t, server)
	defer client.Close()
	defer session.Close()
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: capabilityMCPToolName})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError || len(result.Content) != 1 {
		t.Fatalf("result = %#v", result)
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok || !strings.Contains(text.Text, errCapabilityMCP.Error()) || strings.Contains(text.Text, "backend") {
		t.Fatalf("error content = %#v", result.Content)
	}
}

func TestCapabilityMCPServerPaginatesLargeLiveManifest(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	manifest := capabilities.Manifest{Version: capabilities.SchemaVersion, GeneratedAt: now, ExpiresAt: now.Add(time.Hour)}
	for index := 0; index < 20; index++ {
		name := fmt.Sprintf("service%02d", index)
		manifest.Services = append(manifest.Services, capabilities.Service{
			Name: name, Adapter: "http", PathPrefix: "/" + name + "-" + strings.Repeat("x", 3000),
			Auth: capabilities.Auth{Header: "Authorization", Prefix: "Bearer "}, CapabilitySummary: strings.Repeat("scope", 100),
		})
	}
	var calls atomic.Int64
	server := newCapabilityMCPServer(capabilities.ClientOptions{}, func(context.Context, capabilities.ClientOptions) (capabilities.Manifest, error) {
		calls.Add(1)
		return manifest, nil
	})
	client, session := connectMCPTest(t, server)
	defer client.Close()
	defer session.Close()

	cursorPattern := regexp.MustCompile(`\{"cursor":"([a-z0-9_-]+)"\}`)
	seen := make(map[string]bool, len(manifest.Services))
	cursor := ""
	pages := 0
	for {
		result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
			Name: capabilityMCPToolName, Arguments: capabilityMCPInput{Cursor: cursor},
		})
		if err != nil || result.IsError || len(result.Content) != 1 {
			t.Fatalf("page %d result=%#v err=%v", pages, result, err)
		}
		content, ok := result.Content[0].(*mcp.TextContent)
		if !ok || len(content.Text) > capabilities.MaxToolContextBytes {
			t.Fatalf("page content = %#v", result.Content)
		}
		pages++
		for _, service := range manifest.Services {
			if strings.Contains(content.Text, "- "+service.Name+" (http)") {
				if seen[service.Name] {
					t.Fatalf("service %s appeared twice", service.Name)
				}
				seen[service.Name] = true
			}
		}
		match := cursorPattern.FindStringSubmatch(content.Text)
		if len(match) == 0 {
			break
		}
		if match[1] <= cursor {
			t.Fatalf("non-monotonic cursor %q after %q", match[1], cursor)
		}
		cursor = match[1]
		if pages > len(manifest.Services) {
			t.Fatal("pagination did not terminate")
		}
	}
	if pages < 2 || len(seen) != len(manifest.Services) || calls.Load() != int64(pages) {
		t.Fatalf("pages=%d services=%d/%d fetches=%d", pages, len(seen), len(manifest.Services), calls.Load())
	}
}

func TestRunMCPHelp(t *testing.T) {
	t.Parallel()
	var output strings.Builder
	if err := runMCP([]string{"--help"}, strings.NewReader(""), &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Usage: ff mcp [options]") || !strings.Contains(output.String(), "-token-file") {
		t.Fatalf("help = %q", output.String())
	}
}

func connectMCPTest(t *testing.T, server *mcp.Server) (*mcp.ServerSession, *mcp.ClientSession) {
	t.Helper()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(context.Background(), serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "forcefield-test", Version: "1"}, nil)
	clientSession, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil {
		_ = serverSession.Close()
		t.Fatal(err)
	}
	return serverSession, clientSession
}
