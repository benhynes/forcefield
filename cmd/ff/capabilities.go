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
	format := flags.String("format", "text", "output format: text, json, claude-hook, or codex-hook")
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
	if *format != "text" && *format != "json" && *format != "claude-hook" && *format != "codex-hook" {
		return errors.New("format must be text, json, claude-hook, or codex-hook")
	}

	event := ""
	var readHook func(io.Reader) (string, error)
	var writeHook func(io.Writer, string, string) error
	switch *format {
	case "claude-hook":
		readHook = capabilities.ReadClaudeHookEvent
		writeHook = capabilities.WriteClaudeHook
	case "codex-hook":
		readHook = capabilities.ReadCodexHookEvent
		writeHook = capabilities.WriteCodexHook
	}
	if readHook != nil {
		var hookErr error
		event, hookErr = readHook(stdin)
		if hookErr != nil {
			return hookErr
		}
	}
	manifest, err := capabilities.Fetch(context.Background(), capabilities.ClientOptions{
		BaseURL: *baseURL, TokenFile: *tokenFile, CACertPath: *caCert,
		ClientCert: *clientCert, ClientKey: *clientKey, AllowInsecure: *allowInsecure,
		Timeout: *timeout, UserAgent: "forcefield/" + version,
	})
	if err != nil {
		if writeHook != nil {
			_, _ = fmt.Fprintln(stderr, "ff: Forcefield capability lookup was not confirmed")
			return writeHook(stdout, event, capabilities.UnavailableContext())
		}
		return err
	}
	switch *format {
	case "json":
		return writeJSONOutput(stdout, manifest)
	case "claude-hook", "codex-hook":
		contextText, err := capabilities.RenderMarkdown(manifest, capabilities.RenderOptions{
			TokenFile: *tokenFile, CACertPath: *caCert, ClientCertPath: *clientCert, ClientKeyPath: *clientKey,
		})
		if err != nil {
			return writeHook(stdout, event, capabilities.UnavailableContext())
		}
		return writeHook(stdout, event, contextText)
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
