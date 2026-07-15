package main

import (
	"context"
	"errors"
	"io"
	"os"
	"time"

	"github.com/benhynes/forcefield/internal/capabilities"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const capabilityMCPToolName = "capabilities"

const capabilityMCPInstructions = "External-service access is brokered by Forcefield. Consult the capabilities tool before planning or making external API calls and whenever startup context may be stale; follow every returned cursor. Use only advertised Forcefield origins. Never reveal or send the Forcefield token or mTLS private key except as Forcefield client inputs. Remaining quota is not reported, and a 404 may mean outside the grant. Snapshots are advisory; Forcefield remains authoritative."

var errCapabilityMCP = errors.New("Forcefield capability lookup was not confirmed")

type capabilityMCPInput struct {
	Cursor string `json:"cursor,omitempty" jsonschema:"Stable service-name cursor from the previous capabilities result; omit for the first page."`
}

type capabilityFetcher func(context.Context, capabilities.ClientOptions) (capabilities.Manifest, error)

func runMCP(args []string, stdin io.Reader, stdout io.Writer) error {
	flags := newFlagSet("mcp")
	baseURL := flags.String("url", os.Getenv("FORCEFIELD_URL"), "Forcefield origin (or FORCEFIELD_URL)")
	tokenFile := flags.String("token-file", envDefault("FORCEFIELD_TOKEN_FILE", "~/.config/forcefield/token"), "0600 Forcefield bearer file")
	caCert := flags.String("ca-cert", os.Getenv("FORCEFIELD_CA_CERT"), "additional TLS CA certificate")
	clientCert := flags.String("client-cert", os.Getenv("FORCEFIELD_CLIENT_CERT"), "mTLS client certificate")
	clientKey := flags.String("client-key", os.Getenv("FORCEFIELD_CLIENT_KEY"), "mTLS client private key")
	allowInsecure := flags.Bool("allow-insecure", false, "allow loopback HTTP for development")
	timeout := flags.Duration("timeout", 5*time.Second, "lookup timeout")
	if done, err := parseCommandFlags(flags, args, stdout); done || err != nil {
		return err
	}
	options := capabilities.ClientOptions{
		BaseURL: *baseURL, TokenFile: *tokenFile, CACertPath: *caCert,
		ClientCert: *clientCert, ClientKey: *clientKey, AllowInsecure: *allowInsecure,
		Timeout: *timeout, UserAgent: "forcefield-mcp/" + version,
	}
	server := newCapabilityMCPServer(options, capabilities.Fetch)
	transport := &mcp.IOTransport{
		Reader: io.NopCloser(stdin),
		Writer: nopWriteCloser{Writer: stdout},
	}
	return server.Run(context.Background(), transport)
}

func newCapabilityMCPServer(options capabilities.ClientOptions, fetch capabilityFetcher) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name: "forcefield", Title: "Forcefield capabilities", Version: version,
	}, &mcp.ServerOptions{Instructions: capabilityMCPInstructions})
	closedWorld := false
	mcp.AddTool(server, &mcp.Tool{
		Meta:  mcp.Meta{"anthropic/alwaysLoad": true},
		Name:  capabilityMCPToolName,
		Title: "Forcefield configured grants",
		Description: "Return a fresh, sanitized, cursor-paginated snapshot of revision-current configured external-service grants for this Forcefield token; remaining quota is not reported. " +
			"Call this before planning external API work or whenever the startup snapshot may be stale, and follow any returned cursor until complete.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: &closedWorld,
		},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input capabilityMCPInput) (*mcp.CallToolResult, any, error) {
		if fetch == nil {
			return nil, nil, errCapabilityMCP
		}
		manifest, err := fetch(ctx, options)
		if err != nil {
			return nil, nil, errCapabilityMCP
		}
		text, _, err := capabilities.RenderMarkdownPage(manifest, capabilities.RenderOptions{
			TokenFile: options.TokenFile, CACertPath: options.CACertPath,
			ClientCertPath: options.ClientCert, ClientKeyPath: options.ClientKey,
		}, input.Cursor)
		if err != nil {
			return nil, nil, errCapabilityMCP
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, nil, nil
	})
	return server
}

type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }
