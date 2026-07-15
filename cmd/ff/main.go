package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/benhynes/forcefield/internal/audit"
	"github.com/benhynes/forcefield/internal/config"
	"github.com/benhynes/forcefield/internal/control"
	"github.com/benhynes/forcefield/internal/gateway"
	"github.com/benhynes/forcefield/internal/secrets"
	"github.com/benhynes/forcefield/internal/tokens"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "ff: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printUsage(stderr)
		return errors.New("a command is required")
	}
	switch args[0] {
	case "serve":
		return runServe(args[1:], stderr)
	case "check":
		return runCheck(args[1:], stdout)
	case "mint":
		return runMint(args[1:], stdout, stderr)
	case "delegate":
		return runDelegate(args[1:], stdin, stdout, stderr)
	case "revoke":
		return runRevoke(args[1:], stdout)
	case "identity":
		return runIdentity(args[1:], stdout)
	case "capabilities":
		return runCapabilities(args[1:], stdin, stdout, stderr)
	case "mcp":
		return runMCP(args[1:], stdin, stdout)
	case "version", "--version", "-version":
		_, err := fmt.Fprintln(stdout, version)
		return err
	case "help", "-h", "--help":
		printUsage(stdout)
		return nil
	default:
		printUsage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runServe(args []string, stderr io.Writer) error {
	flags := newFlagSet("serve")
	configPath := flags.String("config", "forcefield.yaml", "configuration file")
	if done, err := parseCommandFlags(flags, args, stderr); done || err != nil {
		return err
	}
	compiled, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if err := ensurePrivateParent(compiled.File.State.TokenFile); err != nil {
		return err
	}
	if err := ensurePrivateParent(compiled.File.State.AuditFile); err != nil {
		return err
	}
	store, err := tokens.Open(compiled.File.State.TokenFile, tokens.Options{})
	if err != nil {
		return fmt.Errorf("open token store: %w", err)
	}
	defer store.Close()
	backend, closeBackend, err := buildSecretBackend(compiled.File.Secrets)
	if err != nil {
		return err
	}
	defer closeBackend()
	auditMode := audit.FailClosed
	if compiled.File.State.AuditFailure == "open" {
		auditMode = audit.FailOpen
	}
	auditor, err := audit.Open(compiled.File.State.AuditFile, auditMode)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer auditor.Close()

	logger := log.New(stderr, "ff: ", log.LstdFlags|log.LUTC)
	dataPlane, err := gateway.New(compiled, store, backend, auditor, gateway.Options{ErrorLog: logger})
	if err != nil {
		return err
	}
	admin, err := control.NewServer(compiled, store, auditor)
	if err != nil {
		return err
	}
	if err := admin.Listen(); err != nil {
		return err
	}
	defer admin.Shutdown(context.Background())

	listener, err := net.Listen("tcp", compiled.File.Server.Listen)
	if err != nil {
		return fmt.Errorf("listen on data plane: %w", err)
	}
	defer listener.Close()
	httpServer := &http.Server{
		Handler: dataPlane, ReadHeaderTimeout: compiled.File.Server.ReadHeaderTimeout.Value(),
		ReadTimeout: compiled.File.Server.ReadTimeout.Value(),
		IdleTimeout: compiled.File.Server.IdleTimeout.Value(), MaxHeaderBytes: 64 << 10,
		ErrorLog: logger,
	}
	if compiled.File.Server.TLSCert != "" {
		tlsConfig, err := serverTLSConfig(compiled.File.Server.ClientCA)
		if err != nil {
			return err
		}
		httpServer.TLSConfig = tlsConfig
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errorsChannel := make(chan error, 2)
	go func() { errorsChannel <- admin.Serve() }()
	go func() {
		if compiled.File.Server.TLSCert != "" {
			errorsChannel <- httpServer.ServeTLS(listener, compiled.File.Server.TLSCert, compiled.File.Server.TLSKey)
			return
		}
		errorsChannel <- httpServer.Serve(listener)
	}()
	logger.Printf("serving data=%s admin=%s", compiled.File.Server.Listen, compiled.File.Server.AdminSocket)
	if compiled.File.Server.AllowInsecureIngress {
		logger.Printf("WARNING: insecure non-loopback ingress explicitly enabled")
	}
	if compiled.File.Secrets.Type == "env" {
		logger.Printf("WARNING: environment secret backend is for development only")
	}
	for name, service := range compiled.File.Services {
		if service.AllowInsecureUpstream {
			logger.Printf("WARNING: service=%s explicitly permits an insecure HTTP upstream", name)
		}
	}

	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errorsChannel:
		if errors.Is(serveErr, http.ErrServerClosed) || errors.Is(serveErr, net.ErrClosed) {
			serveErr = nil
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dataErr := httpServer.Shutdown(shutdownCtx)
	adminErr := admin.Shutdown(shutdownCtx)
	if serveErr != nil {
		return serveErr
	}
	return errors.Join(dataErr, adminErr)
}

func runCheck(args []string, stdout io.Writer) error {
	flags := newFlagSet("check")
	configPath := flags.String("config", "forcefield.yaml", "configuration file")
	if done, err := parseCommandFlags(flags, args, stdout); done || err != nil {
		return err
	}
	compiled, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "valid: services=%d credentials=%d policies=%d roles=%d\n", len(compiled.File.Services), len(compiled.File.Credentials), len(compiled.Policies), len(compiled.Roles))
	return err
}

func runMint(args []string, stdout, stderr io.Writer) error {
	flags := newFlagSet("mint")
	configPath := flags.String("config", "forcefield.yaml", "configuration file")
	role := flags.String("role", "", "role template")
	workload := flags.String("workload", "", "bound workload identity")
	ttl := flags.Duration("ttl", time.Hour, "token lifetime")
	allowDelegation := flags.Bool("allow-delegation", false, "permit monotonic child tokens")
	jsonOutput := flags.Bool("json", false, "emit token and claims as JSON")
	if done, err := parseCommandFlags(flags, args, stdout); done || err != nil {
		return err
	}
	if *role == "" || *workload == "" || *ttl < time.Second {
		return errors.New("role, workload, and a ttl of at least one second are required")
	}
	compiled, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	client, err := control.NewClient(compiled.File.Server.AdminSocket)
	if err != nil {
		return err
	}
	issued, err := client.Mint(context.Background(), control.MintRequest{
		Role: *role, Workload: *workload, TTLSeconds: int64(*ttl / time.Second), AllowDelegation: *allowDelegation,
	})
	if err != nil {
		return err
	}
	if *jsonOutput {
		if err := writeJSONOutput(stdout, issued); err != nil {
			_ = client.Revoke(context.Background(), issued.Claims.TokenID)
			return fmt.Errorf("write token output: %w", err)
		}
		return nil
	}
	if _, err := fmt.Fprintln(stdout, issued.Bearer); err != nil {
		_ = client.Revoke(context.Background(), issued.Claims.TokenID)
		return fmt.Errorf("write token output: %w", err)
	}
	_, err = fmt.Fprintf(stderr, "token_id=%s expires=%s\n", issued.Claims.TokenID, issued.Claims.ExpiresAt.Format(time.RFC3339))
	return err
}

func runDelegate(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags := newFlagSet("delegate")
	configPath := flags.String("config", "forcefield.yaml", "configuration file")
	caller := flags.String("caller-workload", "", "parent token workload")
	workload := flags.String("workload", "", "child workload identity")
	services := flags.String("services", "", "comma-separated service subset; empty keeps all")
	ttl := flags.Duration("ttl", time.Hour, "child token lifetime")
	allowDelegation := flags.Bool("allow-delegation", false, "permit another monotonic delegation")
	jsonOutput := flags.Bool("json", false, "emit token and claims as JSON")
	if done, err := parseCommandFlags(flags, args, stdout); done || err != nil {
		return err
	}
	if *caller == "" || *workload == "" || *ttl < time.Second {
		return errors.New("caller-workload, workload, and a ttl of at least one second are required")
	}
	parent, err := io.ReadAll(io.LimitReader(stdin, 1024))
	if err != nil {
		return errors.New("read parent token")
	}
	parentToken := strings.TrimSpace(string(parent))
	clear(parent)
	if !strings.HasPrefix(parentToken, tokens.BearerPrefix) {
		return errors.New("parent token must be provided on stdin")
	}
	compiled, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	client, err := control.NewClient(compiled.File.Server.AdminSocket)
	if err != nil {
		return err
	}
	var serviceList []string
	if *services != "" {
		for _, service := range strings.Split(*services, ",") {
			serviceList = append(serviceList, strings.TrimSpace(service))
		}
	}
	issued, err := client.Delegate(context.Background(), control.DelegateRequest{
		ParentToken: parentToken, CallerWorkload: *caller, Workload: *workload,
		Services: serviceList, TTLSeconds: int64(*ttl / time.Second), AllowDelegation: *allowDelegation,
	})
	if err != nil {
		return err
	}
	if *jsonOutput {
		if err := writeJSONOutput(stdout, issued); err != nil {
			_ = client.Revoke(context.Background(), issued.Claims.TokenID)
			return fmt.Errorf("write token output: %w", err)
		}
		return nil
	}
	if _, err := fmt.Fprintln(stdout, issued.Bearer); err != nil {
		_ = client.Revoke(context.Background(), issued.Claims.TokenID)
		return fmt.Errorf("write token output: %w", err)
	}
	_, err = fmt.Fprintf(stderr, "token_id=%s parent=%s expires=%s\n", issued.Claims.TokenID, issued.Claims.ParentTokenID, issued.Claims.ExpiresAt.Format(time.RFC3339))
	return err
}

func runRevoke(args []string, stdout io.Writer) error {
	flags := newFlagSet("revoke")
	configPath := flags.String("config", "forcefield.yaml", "configuration file")
	tokenID := flags.String("token-id", "", "public token ID")
	if done, err := parseCommandFlags(flags, args, stdout); done || err != nil {
		return err
	}
	if *tokenID == "" {
		return errors.New("token-id is required")
	}
	compiled, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	client, err := control.NewClient(compiled.File.Server.AdminSocket)
	if err != nil {
		return err
	}
	return client.Revoke(context.Background(), *tokenID)
}

func runIdentity(args []string, stdout io.Writer) error {
	flags := newFlagSet("identity")
	ipValue := flags.String("ip", "", "VM source IP")
	certPath := flags.String("cert", "", "mTLS client certificate")
	if done, err := parseCommandFlags(flags, args, stdout); done || err != nil {
		return err
	}
	if (*ipValue == "") == (*certPath == "") {
		return errors.New("exactly one of ip or cert is required")
	}
	if *ipValue != "" {
		ip := net.ParseIP(*ipValue)
		if ip == nil {
			return errors.New("invalid IP address")
		}
		_, err := fmt.Fprintln(stdout, "ip:"+ip.String())
		return err
	}
	data, err := os.ReadFile(*certPath)
	if err != nil {
		return errors.New("read certificate")
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("parse certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.New("parse certificate")
	}
	digest := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	_, err = fmt.Fprintln(stdout, "mtls-spki:"+hex.EncodeToString(digest[:]))
	return err
}

func buildSecretBackend(cfg config.SecretBackendConfig) (secrets.Backend, func(), error) {
	var backend secrets.Backend
	switch cfg.Type {
	case "exec":
		execBackend, err := secrets.NewExecBackend(cfg.Command, secrets.ExecOptions{
			Args: cfg.Args, Timeout: cfg.Timeout.Value(), MaxOutput: cfg.MaxOutputBytes,
		})
		if err != nil {
			return nil, func() {}, fmt.Errorf("initialize secret backend: %w", err)
		}
		backend = execBackend
	case "env":
		backend = secrets.NewEnvBackend(cfg.EnvPrefix)
	default:
		return nil, func() {}, errors.New("unsupported secret backend")
	}
	cache, err := secrets.NewCache(backend, secrets.CacheOptions{TTL: cfg.CacheTTL.Value(), MaxEntries: cfg.MaxCacheEntries})
	if err != nil {
		return nil, func() {}, err
	}
	return cache, func() { _ = cache.Close() }, nil
}

func serverTLSConfig(clientCAPath string) (*tls.Config, error) {
	config := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}
	if clientCAPath == "" {
		return config, nil
	}
	data, err := os.ReadFile(clientCAPath)
	if err != nil {
		return nil, errors.New("read client CA")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("parse client CA")
	}
	config.ClientCAs = pool
	config.ClientAuth = tls.RequireAndVerifyClientCert
	return config, nil
}

func ensurePrivateParent(path string) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("state directory must be a non-symlink 0700 directory")
	}
	return nil
}

func writeJSONOutput(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func newFlagSet(name string) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	return flags
}

func parseCommandFlags(flags *flag.FlagSet, args []string, output io.Writer) (bool, error) {
	flags.SetOutput(output)
	flags.Usage = func() {
		_, _ = fmt.Fprintf(output, "Usage: ff %s [options]\n", flags.Name())
		flags.PrintDefaults()
	}
	err := flags.Parse(args)
	if errors.Is(err, flag.ErrHelp) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if flags.NArg() != 0 {
		return false, fmt.Errorf("unexpected positional arguments: %s", strings.Join(flags.Args(), " "))
	}
	return false, nil
}

func printUsage(writer io.Writer) {
	_, _ = io.WriteString(writer, `Forcefield credential capability gateway

Usage:
  ff serve    --config forcefield.yaml
  ff check    --config forcefield.yaml
  ff mint     --config forcefield.yaml --role ROLE --workload ID [--ttl 1h]
  ff delegate --config forcefield.yaml --caller-workload ID --workload CHILD_ID < parent-token
  ff revoke   --config forcefield.yaml --token-id TOKEN_ID
  ff identity --ip VM_IP | --cert CLIENT_CERT
  ff capabilities --url FORCEFIELD_ORIGIN [--format text|json|claude-hook]
  ff mcp --url FORCEFIELD_ORIGIN [--token-file PATH]
  ff version
`)
}
