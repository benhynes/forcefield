package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/benhynes/forcefield/internal/capabilities"
)

func runCapabilities(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags := newFlagSet("capabilities")
	baseURL := flags.String("url", os.Getenv("FORCEFIELD_URL"), "Forcefield origin (or FORCEFIELD_URL)")
	tokenFile := flags.String("token-file", envDefault("FORCEFIELD_TOKEN_FILE", "~/.config/forcefield/token"), "0600 Forcefield bearer file")
	caCert := flags.String("ca-cert", os.Getenv("FORCEFIELD_CA_CERT"), "additional TLS CA certificate")
	clientCert := flags.String("client-cert", os.Getenv("FORCEFIELD_CLIENT_CERT"), "mTLS client certificate")
	clientKey := flags.String("client-key", os.Getenv("FORCEFIELD_CLIENT_KEY"), "mTLS client private key")
	format := flags.String("format", "text", "output format: text, json, or claude-hook")
	jsonOutput := flags.Bool("json", false, "emit JSON (alias for --format json)")
	allowInsecure := flags.Bool("allow-insecure", false, "allow loopback HTTP for development")
	timeout := flags.Duration("timeout", 5*time.Second, "lookup timeout")
	if done, err := parseCommandFlags(flags, args, stdout); done || err != nil {
		return err
	}
	if *jsonOutput {
		if *format != "text" {
			return errors.New("json and format cannot both be specified")
		}
		*format = "json"
	}
	if *format != "text" && *format != "json" && *format != "claude-hook" {
		return errors.New("format must be text, json, or claude-hook")
	}

	event := ""
	if *format == "claude-hook" {
		var err error
		event, err = capabilities.ReadClaudeHookEvent(stdin)
		if err != nil {
			return err
		}
	}
	manifest, err := capabilities.Fetch(context.Background(), capabilities.ClientOptions{
		BaseURL: *baseURL, TokenFile: *tokenFile, CACertPath: *caCert,
		ClientCert: *clientCert, ClientKey: *clientKey, AllowInsecure: *allowInsecure,
		Timeout: *timeout, UserAgent: "forcefield/" + version,
	})
	if err != nil {
		if *format == "claude-hook" {
			_, _ = fmt.Fprintln(stderr, "ff: Forcefield capability lookup was not confirmed")
			return capabilities.WriteClaudeHook(stdout, event, capabilities.UnavailableContext())
		}
		return err
	}
	switch *format {
	case "json":
		return writeJSONOutput(stdout, manifest)
	case "claude-hook":
		contextText, err := capabilities.RenderMarkdown(manifest, capabilities.RenderOptions{
			TokenFile: *tokenFile, CACertPath: *caCert, ClientCertPath: *clientCert, ClientKeyPath: *clientKey,
		})
		if err != nil {
			return capabilities.WriteClaudeHook(stdout, event, capabilities.UnavailableContext())
		}
		return capabilities.WriteClaudeHook(stdout, event, contextText)
	default:
		contextText, err := capabilities.RenderMarkdown(manifest, capabilities.RenderOptions{
			TokenFile: *tokenFile, CACertPath: *caCert, ClientCertPath: *clientCert, ClientKeyPath: *clientKey,
		})
		if err != nil {
			return err
		}
		_, err = io.WriteString(stdout, contextText)
		return err
	}
}

func envDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
