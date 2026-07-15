package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/benhynes/forcefield/internal/audit"
	"github.com/benhynes/forcefield/internal/config"
	"github.com/benhynes/forcefield/internal/secrets"
	"github.com/benhynes/forcefield/internal/sshclient"
	"github.com/benhynes/forcefield/internal/tokens"
	"golang.org/x/crypto/ssh"
)

func TestSSHSessionAdapterEndToEndAndProtocolIsolation(t *testing.T) {
	fixture := newSSHIntegrationFixture(t, sshFixtureOptions{})
	issued := fixture.mint(t, fixture.workload, time.Minute)
	client := fixture.dial(t, issued.Bearer)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("open allowed session: %v", err)
	}
	defer session.Close()

	// A Forcefield SSH stream deliberately represents one upstream session,
	// even though the nested SSH transport can technically carry many.
	if additional, err := client.NewSession(); err == nil {
		_ = additional.Close()
		t.Fatal("additional session channel was accepted")
	}

	// Direct and reverse TCP forwarding must terminate at Forcefield and must
	// never reach the pinned upstream server.
	if forwarded, err := client.Dial("tcp", "127.0.0.1:22"); err == nil {
		_ = forwarded.Close()
		t.Fatal("direct-tcpip forwarding was accepted")
	}
	if listener, err := client.Listen("tcp", "127.0.0.1:0"); err == nil {
		_ = listener.Close()
		t.Fatal("tcpip-forward request was accepted")
	}

	// Adapter v1 rejects environment, subsystem, agent-forwarding, and PTY
	// requests unless the narrow request type is explicitly part of policy.
	if err := session.Setenv("FORCEFIELD_TEST", "secret"); err == nil {
		t.Fatal("environment request was accepted")
	}
	if err := session.RequestSubsystem("sftp"); err == nil {
		t.Fatal("subsystem request was accepted")
	}
	if ok, err := session.SendRequest("auth-agent-req@openssh.com", true, nil); err != nil || ok {
		t.Fatalf("agent-forwarding request result=(%v, %v), want (false, nil)", ok, err)
	}
	if err := session.RequestPty("xterm-256color", 24, 80, ssh.TerminalModes{}); err == nil {
		t.Fatal("PTY request was accepted by a policy that did not grant PTY")
	}
	if err := session.Shell(); err == nil {
		t.Fatal("shell request was accepted by an exec-only policy")
	}

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr
	if err := session.Run("emit"); err != nil {
		t.Fatalf("run allowed command: %v", err)
	}
	if got, want := stdout.String(), "stdout from upstream\n"; got != want {
		t.Fatalf("stdout=%q want=%q", got, want)
	}
	if got, want := stderr.String(), "stderr from upstream\n"; got != want {
		t.Fatalf("stderr=%q want=%q", got, want)
	}

	stats := fixture.upstream.snapshot()
	if stats.authenticatedConnections != 1 || stats.sessionChannels != 1 {
		t.Fatalf("upstream connections=%d session channels=%d, want 1 and 1", stats.authenticatedConnections, stats.sessionChannels)
	}
	for _, forbidden := range []string{"direct-tcpip", "forwarded-tcpip", "env", "subsystem", "auth-agent-req@openssh.com", "pty-req", "shell", "tcpip-forward"} {
		if stats.events[forbidden] != 0 {
			t.Fatalf("forbidden SSH operation %q reached upstream %d time(s)", forbidden, stats.events[forbidden])
		}
	}
	if stats.events["exec"] != 1 {
		t.Fatalf("upstream exec count=%d want=1", stats.events["exec"])
	}

	auditText := fixture.audit.String()
	if strings.Contains(auditText, issued.Bearer) || strings.Contains(auditText, "emit") ||
		strings.Contains(auditText, "stdout from upstream") || strings.Contains(auditText, "stderr from upstream") ||
		strings.Contains(auditText, string(fixture.privateKey)) {
		t.Fatal("SSH audit output exposed token, command, output, or private-key material")
	}
}

func TestSSHSessionAdapterEndToEndOverTLSHTTP2(t *testing.T) {
	fixture := newSSHIntegrationFixture(t, sshFixtureOptions{tlsHTTP2: true})
	issued := fixture.mint(t, fixture.workload, time.Minute)
	client := fixture.dial(t, issued.Bearer)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	var stdout bytes.Buffer
	session.Stdout = &stdout
	if err := session.Run("emit"); err != nil {
		t.Fatal(err)
	}
	if fixture.requestProtocol.Load() != 2 {
		t.Fatalf("outer protocol major = %d, want HTTP/2", fixture.requestProtocol.Load())
	}
	if stdout.String() != "stdout from upstream\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	_ = client.Close()

	revokedToken := fixture.mint(t, fixture.workload, time.Minute)
	revokedClient := fixture.dial(t, revokedToken.Bearer)
	defer revokedClient.Close()
	revokedSession, err := revokedClient.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer revokedSession.Close()
	if err := revokedSession.Start("hold"); err != nil {
		t.Fatal(err)
	}
	wait := make(chan error, 1)
	go func() { wait <- revokedSession.Wait() }()
	if err := fixture.store.Revoke(context.Background(), revokedToken.Bearer); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-wait:
		if err == nil {
			t.Fatal("revoked HTTP/2 SSH stream ended successfully")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("revoked HTTP/2 SSH stream remained open")
	}
	fixture.waitForSSHCleanup(t, 2*time.Second)
}

func TestSSHSessionAdapterAllowsGrantedShellAndPTY(t *testing.T) {
	fixture := newSSHIntegrationFixture(t, sshFixtureOptions{allowShell: true, allowPTY: true})
	issued := fixture.mint(t, fixture.workload, time.Minute)
	client := fixture.dial(t, issued.Bearer)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	var stdout bytes.Buffer
	session.Stdout = &stdout
	if err := session.RequestPty("xterm-256color", 24, 80, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
		t.Fatalf("request granted PTY: %v", err)
	}
	if err := session.Shell(); err != nil {
		t.Fatalf("start granted shell: %v", err)
	}
	if err := session.Wait(); err != nil {
		t.Fatalf("wait for granted shell: %v", err)
	}
	if got, want := stdout.String(), "shell from upstream\n"; got != want {
		t.Fatalf("shell stdout=%q want=%q", got, want)
	}
	stats := fixture.upstream.snapshot()
	if stats.events["pty-req"] != 1 || stats.events["shell"] != 1 {
		t.Fatalf("upstream PTY requests=%d shell requests=%d, want 1 and 1", stats.events["pty-req"], stats.events["shell"])
	}
}

func TestSSHSessionAdapterRelaysRemoteExitStatusAndSignal(t *testing.T) {
	fixture := newSSHIntegrationFixture(t, sshFixtureOptions{})
	issued := fixture.mint(t, fixture.workload, time.Minute)
	for _, test := range []struct {
		command string
		status  int
	}{{command: "exit42", status: 42}, {command: "signal", status: 143}} {
		client := fixture.dial(t, issued.Bearer)
		session, err := client.NewSession()
		if err != nil {
			_ = client.Close()
			t.Fatal(err)
		}
		err = session.Run(test.command)
		_ = session.Close()
		_ = client.Close()
		var exitError *ssh.ExitError
		if !errors.As(err, &exitError) || exitError.ExitStatus() != test.status {
			t.Fatalf("command %q error=%v status=%v, want %d", test.command, err, exitError, test.status)
		}
	}
}

func TestSSHSessionAdapterRejectsAuthenticationBeforeUpstream(t *testing.T) {
	fixture := newSSHIntegrationFixture(t, sshFixtureOptions{})

	tests := []struct {
		name   string
		bearer string
	}{
		{
			name:   "wrong workload",
			bearer: fixture.mint(t, "ip:192.0.2.10", time.Minute).Bearer,
		},
		{
			name:   "unknown token",
			bearer: tokens.BearerPrefix + strings.Repeat("A", tokens.BearerLength-len(tokens.BearerPrefix)),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			client, err := sshclient.Dial(ctx, sshclient.Options{
				Endpoint: fixture.endpoint, Bearer: test.bearer,
				Transport: fixture.httpServer.Client().Transport, HandshakeTimeout: 2 * time.Second,
			})
			if err == nil {
				_ = client.Close()
				t.Fatal("unauthorized SSH stream was accepted")
			}
			if !errors.Is(err, sshclient.ErrConnection) {
				t.Fatalf("dial error=%v want ErrConnection", err)
			}
		})
	}
	if got := fixture.upstream.snapshot().acceptedTCPConnections; got != 0 {
		t.Fatalf("authentication failures opened %d upstream TCP connection(s)", got)
	}
}

func TestSSHSessionAdapterRevalidatesAfterBlockedSecretLookup(t *testing.T) {
	var backend *blockingSSHBackend
	fixture := newSSHIntegrationFixture(t, sshFixtureOptions{
		backendFactory: func(privateKey []byte) secrets.Backend {
			backend = newBlockingSSHBackend(privateKey)
			return backend
		},
	})
	issued := fixture.mint(t, fixture.workload, time.Minute)
	writer, cancel, result := fixture.startOuterSSHStream(t, issued.Bearer)
	defer cancel()
	defer writer.Close()

	select {
	case <-backend.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("secret lookup did not block")
	}
	if err := fixture.store.Revoke(context.Background(), issued.Bearer); err != nil {
		t.Fatal(err)
	}
	close(backend.release)
	select {
	case outcome := <-result:
		if outcome.err != nil {
			t.Fatalf("outer request after revocation: %v", outcome.err)
		}
		defer outcome.response.Body.Close()
		if outcome.response.StatusCode != http.StatusNotFound {
			t.Fatalf("status after lookup-time revocation = %d, want 404", outcome.response.StatusCode)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("request did not finish after blocked secret lookup was released")
	}
	stats := fixture.upstream.snapshot()
	if stats.acceptedTCPConnections != 0 || stats.authenticatedConnections != 0 {
		t.Fatalf("lookup-time revocation reached upstream: connections=%d authenticated=%d", stats.acceptedTCPConnections, stats.authenticatedConnections)
	}
}

func TestSSHSessionAdapterRejectsUnpinnedUpstreamHostKey(t *testing.T) {
	fixture := newSSHIntegrationFixture(t, sshFixtureOptions{wrongHostKeyPin: true})
	issued := fixture.mint(t, fixture.workload, time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client, err := sshclient.Dial(ctx, sshclient.Options{
		Endpoint: fixture.endpoint, Bearer: issued.Bearer,
		Transport: fixture.httpServer.Client().Transport, HandshakeTimeout: 2 * time.Second,
	})
	if err == nil {
		_ = client.Close()
		t.Fatal("SSH stream with an unpinned upstream host key was accepted")
	}
	stats := fixture.upstream.snapshot()
	if stats.acceptedTCPConnections != 1 {
		t.Fatalf("host-key test opened %d upstream TCP connections, want 1", stats.acceptedTCPConnections)
	}
	if stats.authenticatedConnections != 0 {
		t.Fatalf("host-key mismatch authenticated %d upstream connection(s)", stats.authenticatedConnections)
	}
}

func TestSSHSessionAdapterRejectsLegacyRSASignatureOnlyUpstream(t *testing.T) {
	fixture := newSSHIntegrationFixture(t, sshFixtureOptions{legacyRSAOnly: true})
	issued := fixture.mint(t, fixture.workload, time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client, err := sshclient.Dial(ctx, sshclient.Options{
		Endpoint: fixture.endpoint, Bearer: issued.Bearer,
		Transport: fixture.httpServer.Client().Transport, HandshakeTimeout: 2 * time.Second,
	})
	if err == nil {
		_ = client.Close()
		t.Fatal("SSH upstream requiring legacy SHA-1 ssh-rsa was accepted")
	}
	stats := fixture.upstream.snapshot()
	if stats.acceptedTCPConnections != 1 || stats.authenticatedConnections != 0 {
		t.Fatalf("legacy RSA upstream connections=%d authenticated=%d, want 1 and 0", stats.acceptedTCPConnections, stats.authenticatedConnections)
	}
}

func TestSSHSessionAdapterRejectsWeakPinnedRSAHostKey(t *testing.T) {
	fixture := newSSHIntegrationFixture(t, sshFixtureOptions{weakRSAHostKey: true})
	issued := fixture.mint(t, fixture.workload, time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client, err := sshclient.Dial(ctx, sshclient.Options{
		Endpoint: fixture.endpoint, Bearer: issued.Bearer,
		Transport: fixture.httpServer.Client().Transport, HandshakeTimeout: 2 * time.Second,
	})
	if err == nil {
		_ = client.Close()
		t.Fatal("pinned 1024-bit RSA host key was accepted")
	}
	stats := fixture.upstream.snapshot()
	if stats.acceptedTCPConnections != 1 || stats.authenticatedConnections != 0 {
		t.Fatalf("weak host-key upstream connections=%d authenticated=%d, want 1 and 0", stats.acceptedTCPConnections, stats.authenticatedConnections)
	}
}

func TestSSHSessionAdapterChargesForwardedRequestPayloads(t *testing.T) {
	fixture := newSSHIntegrationFixture(t, sshFixtureOptions{maxRequestBytes: 4})
	issued := fixture.mint(t, fixture.workload, time.Minute)
	client := fixture.dial(t, issued.Bearer)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := session.Start("emit"); err == nil {
		t.Fatal("exec payload above max_request_bytes was accepted")
	}
	if got := fixture.upstream.snapshot().events["exec"]; got != 0 {
		t.Fatalf("over-budget exec reached upstream %d time(s)", got)
	}
}

func TestSSHSessionAdapterClosesLiveSessionAfterRevocation(t *testing.T) {
	fixture := newSSHIntegrationFixture(t, sshFixtureOptions{})
	issued := fixture.mint(t, fixture.workload, time.Minute)
	client := fixture.dial(t, issued.Bearer)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := session.Start("hold"); err != nil {
		t.Fatalf("start held command: %v", err)
	}

	wait := make(chan error, 1)
	go func() { wait <- session.Wait() }()
	if err := fixture.store.Revoke(context.Background(), issued.Bearer); err != nil {
		t.Fatalf("revoke live token: %v", err)
	}
	select {
	case err := <-wait:
		if err == nil {
			t.Fatal("revoked live SSH session ended successfully instead of being terminated")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("revoked live SSH session remained open past revalidation interval")
	}
}

func TestSSHSessionAdapterClosesLiveSessionAtTokenExpiry(t *testing.T) {
	fixture := newSSHIntegrationFixture(t, sshFixtureOptions{})
	issued := fixture.mint(t, fixture.workload, 1500*time.Millisecond)
	client := fixture.dial(t, issued.Bearer)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := session.Start("hold"); err != nil {
		t.Fatalf("start held command: %v", err)
	}

	wait := make(chan error, 1)
	go func() { wait <- session.Wait() }()
	select {
	case err := <-wait:
		if err == nil {
			t.Fatal("expired live SSH session ended successfully instead of being terminated")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("live SSH session remained open past token expiry")
	}
}

func TestSSHSessionAdapterBoundsStalledGuestHandshake(t *testing.T) {
	fixture := newSSHIntegrationFixture(t, sshFixtureOptions{guestHandshakeTimeout: time.Second})
	issued := fixture.mint(t, fixture.workload, time.Minute)
	response, writer, cancel := fixture.openOuterSSHStream(t, issued.Bearer)
	defer cancel()
	defer writer.Close()
	defer response.Body.Close()

	ended := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, response.Body)
		ended <- err
	}()
	select {
	case <-ended:
	case <-time.After(3 * time.Second):
		t.Fatal("stalled guest SSH handshake outlived its explicit timeout")
	}
	fixture.waitForSSHCleanup(t, 2*time.Second)
}

func TestSSHSessionAdapterRevokesStalledGuestWithoutClientCooperation(t *testing.T) {
	fixture := newSSHIntegrationFixture(t, sshFixtureOptions{})
	issued := fixture.mint(t, fixture.workload, time.Minute)
	response, writer, cancel := fixture.openOuterSSHStream(t, issued.Bearer)
	defer cancel()
	defer writer.Close()
	defer response.Body.Close()

	if err := fixture.store.Revoke(context.Background(), issued.Bearer); err != nil {
		t.Fatal(err)
	}
	ended := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, response.Body)
		ended <- err
	}()
	select {
	case <-ended:
	case <-time.After(3 * time.Second):
		t.Fatal("revocation waited on a stalled client's request body")
	}
	fixture.waitForSSHCleanup(t, 2*time.Second)
}

type sshFixtureOptions struct {
	wrongHostKeyPin       bool
	allowShell            bool
	allowPTY              bool
	maxRequestBytes       uint64
	legacyRSAOnly         bool
	weakRSAHostKey        bool
	tlsHTTP2              bool
	guestHandshakeTimeout time.Duration
	backendFactory        func([]byte) secrets.Backend
}

type sshIntegrationFixture struct {
	workload        string
	endpoint        string
	privateKey      []byte
	grants          []tokens.Grant
	upstream        *sshTestUpstream
	store           *tokens.Store
	backend         secrets.Backend
	gateway         *Gateway
	httpServer      *httptest.Server
	audit           *lockedBuffer
	requestProtocol atomic.Int32
}

func newSSHIntegrationFixture(t *testing.T, options sshFixtureOptions) *sshIntegrationFixture {
	t.Helper()
	upstream := newSSHTestUpstream(t, options)
	privateKey := append([]byte(nil), upstream.clientPrivateKey...)
	pin := ssh.FingerprintSHA256(upstream.hostSigner.PublicKey())
	if options.wrongHostKeyPin {
		other, _ := newSSHSigner(t)
		pin = ssh.FingerprintSHA256(other.PublicKey())
	}

	temp := t.TempDir()
	compiled, err := config.Compile(config.File{
		Version: 1,
		Server: config.ServerConfig{
			Listen: "127.0.0.1:7902", Audience: "ssh-integration", AdvertisedBaseURL: "http://127.0.0.1:7902",
			AdminSocket: filepath.Join(temp, "admin.sock"),
		},
		State: config.StateConfig{
			TokenFile: filepath.Join(temp, "tokens.json"), AuditFile: filepath.Join(temp, "audit.jsonl"), AuditFailure: "closed",
		},
		Secrets: config.SecretBackendConfig{Type: "env", EnvPrefix: "FF_TEST_", MaxOutputBytes: 16 << 10, MaxCacheEntries: 8},
		Services: map[string]config.ServiceConfig{
			"infra": {
				Adapter: config.AdapterSSHSession, Upstream: "ssh://" + upstream.listener.Addr().String(), PathPrefix: "/infra",
				SSH:          &config.SSHServiceConfig{User: sshTestUser, HostKeySHA256: []string{pin}, ConnectTimeout: config.Duration(2 * time.Second)},
				AllowedCIDRs: []string{"127.0.0.0/8"}, ClientAuth: config.HeaderAuth{Header: "Authorization", Prefix: "Bearer "},
			},
		},
		Credentials: map[string]config.CredentialConfig{
			"infra-key": {Service: "infra", SecretRef: "INFRA_KEY"},
		},
		Policies: map[string]config.PolicyConfig{
			"infra-exec": {
				Service: "infra", CapabilitySummary: "Run commands on the pinned integration host without forwarding.",
				SSH: &config.SSHPolicyConfig{
					AllowExec: true, AllowShell: options.allowShell, AllowPTY: options.allowPTY,
					MaxSessionDuration: config.Duration(time.Minute),
				},
			},
		},
		Roles: map[string]config.RoleConfig{
			"infra-agent": {Grants: []config.GrantConfig{{
				Service: "infra", Credential: "infra-key", Policy: "infra-exec",
				Limits: config.LimitsConfig{MaxRequestBytes: options.maxRequestBytes},
			}}},
		},
	})
	if err != nil {
		upstream.Close()
		t.Fatalf("compile SSH fixture: %v", err)
	}
	store, err := tokens.Open(compiled.File.State.TokenFile, tokens.Options{})
	if err != nil {
		upstream.Close()
		t.Fatal(err)
	}
	var backend secrets.Backend = secrets.NewFixedBackend(privateKey)
	if options.backendFactory != nil {
		backend = options.backendFactory(privateKey)
	}
	auditOutput := &lockedBuffer{}
	auditor, err := audit.New(auditOutput, audit.FailClosed)
	if err != nil {
		_ = store.Close()
		closeSSHTestBackend(backend)
		upstream.Close()
		t.Fatal(err)
	}
	gateway, err := New(compiled, store, backend, auditor, Options{SSHHandshakeTimeout: options.guestHandshakeTimeout})
	if err != nil {
		_ = store.Close()
		closeSSHTestBackend(backend)
		upstream.Close()
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		_ = store.Close()
		closeSSHTestBackend(backend)
		upstream.Close()
		t.Skipf("loopback HTTP listener unavailable: %v", err)
	}
	fixture := &sshIntegrationFixture{
		workload: "ip:127.0.0.1", privateKey: privateKey,
		grants:   append([]tokens.Grant(nil), compiled.Roles["infra-agent"]...),
		upstream: upstream, store: store, backend: backend, gateway: gateway, audit: auditOutput,
	}
	httpServer := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		fixture.requestProtocol.Store(int32(request.ProtoMajor))
		gateway.ServeHTTP(writer, request)
	}))
	httpServer.Listener = listener
	if options.tlsHTTP2 {
		httpServer.EnableHTTP2 = true
		httpServer.StartTLS()
	} else {
		httpServer.Start()
	}
	fixture.endpoint = httpServer.URL + "/infra"
	fixture.httpServer = httpServer
	t.Cleanup(func() {
		httpServer.CloseClientConnections()
		httpServer.Close()
		upstream.Close()
		closeSSHTestBackend(backend)
		_ = store.Close()
	})
	return fixture
}

func (f *sshIntegrationFixture) mint(t *testing.T, workload string, ttl time.Duration) tokens.IssuedToken {
	t.Helper()
	issued, err := f.store.Mint(context.Background(), tokens.MintRequest{
		Workload: workload, Audience: "ssh-integration", ExpiresAt: time.Now().Add(ttl),
		Grants: append([]tokens.Grant(nil), f.grants...),
	})
	if err != nil {
		t.Fatal(err)
	}
	return issued
}
func (f *sshIntegrationFixture) dial(t *testing.T, bearer string) *ssh.Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	client, err := sshclient.Dial(ctx, sshclient.Options{
		Endpoint: f.endpoint, Bearer: bearer, Transport: f.httpServer.Client().Transport,
		HandshakeTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial Forcefield SSH stream: %v", err)
	}
	return client
}

type outerSSHResult struct {
	response *http.Response
	err      error
}

func (f *sshIntegrationFixture) startOuterSSHStream(t *testing.T, bearer string) (*io.PipeWriter, context.CancelFunc, <-chan outerSSHResult) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	reader, writer := io.Pipe()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, f.endpoint, reader)
	if err != nil {
		cancel()
		_ = writer.Close()
		t.Fatal(err)
	}
	request.ContentLength = -1
	request.Header.Set("Authorization", "Bearer "+bearer)
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set(config.SSHStreamProtocolHeader, config.SSHStreamProtocol)
	result := make(chan outerSSHResult, 1)
	go func() {
		response, err := f.httpServer.Client().Do(request)
		result <- outerSSHResult{response: response, err: err}
	}()
	return writer, cancel, result
}

func (f *sshIntegrationFixture) openOuterSSHStream(t *testing.T, bearer string) (*http.Response, *io.PipeWriter, context.CancelFunc) {
	t.Helper()
	writer, cancel, result := f.startOuterSSHStream(t, bearer)
	select {
	case outcome := <-result:
		if outcome.err != nil {
			cancel()
			_ = writer.Close()
			t.Fatalf("open outer SSH stream: %v", outcome.err)
		}
		if outcome.response.StatusCode != http.StatusOK {
			cancel()
			_ = writer.Close()
			_ = outcome.response.Body.Close()
			t.Fatalf("outer SSH status = %d, want 200", outcome.response.StatusCode)
		}
		return outcome.response, writer, cancel
	case <-time.After(3 * time.Second):
		cancel()
		_ = writer.Close()
		t.Fatal("outer SSH stream did not return response headers")
		return nil, nil, nil
	}
}

func (f *sshIntegrationFixture) waitForSSHCleanup(t *testing.T, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		f.gateway.sshConcurrency.mu.Lock()
		concurrent := f.gateway.sshConcurrency.total
		f.gateway.sshConcurrency.mu.Unlock()
		if concurrent == 0 && f.upstream.snapshot().activeTCPConnections == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	f.gateway.sshConcurrency.mu.Lock()
	concurrent := f.gateway.sshConcurrency.total
	f.gateway.sshConcurrency.mu.Unlock()
	t.Fatalf("SSH cleanup did not finish: concurrency=%d active_upstream=%d", concurrent, f.upstream.snapshot().activeTCPConnections)
}

type blockingSSHBackend struct {
	privateKey []byte
	entered    chan struct{}
	release    chan struct{}
	once       sync.Once
}

func newBlockingSSHBackend(privateKey []byte) *blockingSSHBackend {
	return &blockingSSHBackend{
		privateKey: append([]byte(nil), privateKey...),
		entered:    make(chan struct{}), release: make(chan struct{}),
	}
}

func (b *blockingSSHBackend) Get(ctx context.Context, _ string) (*secrets.Lease, error) {
	b.once.Do(func() { close(b.entered) })
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-b.release:
		return secrets.NewLease(b.privateKey), nil
	}
}

func (b *blockingSSHBackend) Close() error {
	for index := range b.privateKey {
		b.privateKey[index] = 0
	}
	b.privateKey = nil
	return nil
}

const sshTestUser = "forcefield-test"

type sshUpstreamStats struct {
	acceptedTCPConnections   int
	authenticatedConnections int
	activeTCPConnections     int
	sessionChannels          int
	events                   map[string]int
}

type sshTestUpstream struct {
	listener         net.Listener
	hostSigner       ssh.Signer
	clientPublicKey  ssh.PublicKey
	clientPrivateKey []byte
	legacyRSAOnly    bool

	mu    sync.Mutex
	stats sshUpstreamStats
	conns map[net.Conn]struct{}
	once  sync.Once
	wg    sync.WaitGroup
}

func newSSHTestUpstream(t *testing.T, options sshFixtureOptions) *sshTestUpstream {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback SSH listener unavailable: %v", err)
	}
	hostSigner, _ := newSSHSigner(t)
	if options.weakRSAHostKey {
		hostSigner, _ = newRSASSHSignerBits(t, 1024)
	}
	clientSigner, clientPrivateKey := newSSHSigner(t)
	if options.legacyRSAOnly {
		clientSigner, clientPrivateKey = newRSASSHSigner(t)
	}
	server := &sshTestUpstream{
		listener: listener, hostSigner: hostSigner, clientPublicKey: clientSigner.PublicKey(), clientPrivateKey: clientPrivateKey,
		legacyRSAOnly: options.legacyRSAOnly, stats: sshUpstreamStats{events: make(map[string]int)}, conns: make(map[net.Conn]struct{}),
	}
	server.wg.Add(1)
	go server.accept()
	return server
}

func newRSASSHSigner(t *testing.T) (ssh.Signer, []byte) {
	return newRSASSHSignerBits(t, 2048)
}

func newRSASSHSignerBits(t *testing.T, bits int) (ssh.Signer, []byte) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(privateKey, "forcefield RSA integration test")
	if err != nil {
		t.Fatal(err)
	}
	return signer, pem.EncodeToMemory(block)
}

func newSSHSigner(t *testing.T) (ssh.Signer, []byte) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(privateKey, "forcefield integration test")
	if err != nil {
		t.Fatal(err)
	}
	return signer, pem.EncodeToMemory(block)
}

func (s *sshTestUpstream) accept() {
	defer s.wg.Done()
	for {
		connection, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.track(connection, true)
		s.recordConnection(false)
		s.wg.Add(1)
		go s.serve(connection)
	}
}

func (s *sshTestUpstream) serve(connection net.Conn) {
	defer s.wg.Done()
	defer func() {
		s.track(connection, false)
		_ = connection.Close()
	}()
	configuration := &ssh.ServerConfig{
		PublicKeyCallback: func(metadata ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if metadata.User() != sshTestUser || !bytes.Equal(key.Marshal(), s.clientPublicKey.Marshal()) {
				return nil, errors.New("unexpected SSH client identity")
			}
			return nil, nil
		},
	}
	if s.legacyRSAOnly {
		configuration.PublicKeyAuthAlgorithms = []string{ssh.KeyAlgoRSA}
	}
	configuration.AddHostKey(s.hostSigner)
	server, channels, globalRequests, err := ssh.NewServerConn(connection, configuration)
	if err != nil {
		return
	}
	s.recordConnection(true)
	defer server.Close()
	go func() {
		for request := range globalRequests {
			s.recordEvent(request.Type)
			if request.WantReply {
				_ = request.Reply(false, nil)
			}
		}
	}()
	for requested := range channels {
		s.recordEvent(requested.ChannelType())
		if requested.ChannelType() != "session" || len(requested.ExtraData()) != 0 {
			_ = requested.Reject(ssh.Prohibited, "test server only accepts sessions")
			continue
		}
		channel, requests, err := requested.Accept()
		if err != nil {
			continue
		}
		s.recordSession()
		s.wg.Add(1)
		go s.serveSession(channel, requests)
	}
}

func (s *sshTestUpstream) serveSession(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer s.wg.Done()
	defer channel.Close()
	for request := range requests {
		s.recordEvent(request.Type)
		switch request.Type {
		case "exec":
			var value struct{ Command string }
			if ssh.Unmarshal(request.Payload, &value) != nil ||
				value.Command != "emit" && value.Command != "hold" && value.Command != "exit42" && value.Command != "signal" {
				_ = request.Reply(false, nil)
				continue
			}
			_ = request.Reply(true, nil)
			if value.Command == "hold" {
				for range requests {
				}
				return
			}
			if value.Command == "exit42" {
				_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: 42}))
				return
			}
			if value.Command == "signal" {
				_, _ = channel.SendRequest("exit-signal", false, ssh.Marshal(struct {
					Signal       string
					CoreDumped   bool
					ErrorMessage string
					LanguageTag  string
				}{Signal: "TERM"}))
				return
			}
			_, _ = io.WriteString(channel, "stdout from upstream\n")
			_, _ = io.WriteString(channel.Stderr(), "stderr from upstream\n")
			_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: 0}))
			return
		case "pty-req":
			_ = request.Reply(true, nil)
		case "shell":
			if len(request.Payload) != 0 {
				_ = request.Reply(false, nil)
				continue
			}
			_ = request.Reply(true, nil)
			_, _ = io.WriteString(channel, "shell from upstream\n")
			_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: 0}))
			return
		default:
			if request.WantReply {
				_ = request.Reply(false, nil)
			}
		}
	}
}

func (s *sshTestUpstream) recordConnection(authenticated bool) {
	s.mu.Lock()
	if authenticated {
		s.stats.authenticatedConnections++
	} else {
		s.stats.acceptedTCPConnections++
	}
	s.mu.Unlock()
}

func (s *sshTestUpstream) recordSession() {
	s.mu.Lock()
	s.stats.sessionChannels++
	s.mu.Unlock()
}

func (s *sshTestUpstream) recordEvent(event string) {
	s.mu.Lock()
	s.stats.events[event]++
	s.mu.Unlock()
}

func (s *sshTestUpstream) snapshot() sshUpstreamStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := s.stats
	result.activeTCPConnections = len(s.conns)
	result.events = make(map[string]int, len(s.stats.events))
	for key, value := range s.stats.events {
		result.events[key] = value
	}
	return result
}

func closeSSHTestBackend(backend secrets.Backend) {
	if closer, ok := backend.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
}

func (s *sshTestUpstream) Close() {
	s.once.Do(func() {
		_ = s.listener.Close()
		s.mu.Lock()
		connections := make([]net.Conn, 0, len(s.conns))
		for connection := range s.conns {
			connections = append(connections, connection)
		}
		s.mu.Unlock()
		for _, connection := range connections {
			_ = connection.Close()
		}
	})
	s.wg.Wait()
}

func (s *sshTestUpstream) track(connection net.Conn, add bool) {
	s.mu.Lock()
	if add {
		s.conns[connection] = struct{}{}
	} else {
		delete(s.conns, connection)
	}
	s.mu.Unlock()
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *lockedBuffer) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(value)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}
