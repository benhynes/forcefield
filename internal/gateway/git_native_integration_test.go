package gateway

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/benhynes/forcefield/internal/audit"
	"github.com/benhynes/forcefield/internal/config"
	"github.com/benhynes/forcefield/internal/gitadapter"
	"github.com/benhynes/forcefield/internal/secrets"
	"github.com/benhynes/forcefield/internal/tokens"
)

func TestNativeGitCloneAndRefAuthorizedPush(t *testing.T) {
	if testing.Short() {
		t.Skip("native Git interoperability test")
	}
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git executable is unavailable")
	}

	temp := t.TempDir()
	projectRoot := filepath.Join(temp, "projects")
	bareRepository := filepath.Join(projectRoot, "acme", "infrastructure.git")
	if err := os.MkdirAll(filepath.Dir(bareRepository), 0o700); err != nil {
		t.Fatal(err)
	}
	runGitCommand(t, git, temp, nil, "init", "--bare", bareRepository)
	runGitCommand(t, git, temp, nil, "--git-dir", bareRepository, "config", "http.receivepack", "true")

	seed := filepath.Join(temp, "seed")
	runGitCommand(t, git, temp, nil, "init", "-b", "main", seed)
	runGitCommand(t, git, seed, nil, "config", "user.name", "Forcefield Test")
	runGitCommand(t, git, seed, nil, "config", "user.email", "forcefield@example.invalid")
	if err := os.WriteFile(filepath.Join(seed, "README.md"), []byte("seed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGitCommand(t, git, seed, nil, "add", "README.md")
	runGitCommand(t, git, seed, nil, "commit", "-m", "seed")
	runGitCommand(t, git, seed, nil, "remote", "add", "origin", bareRepository)
	runGitCommand(t, git, seed, nil, "push", "origin", "main")
	runGitCommand(t, git, temp, nil, "--git-dir", bareRepository, "symbolic-ref", "HEAD", "refs/heads/main")

	var sawChunkedReceivePack atomic.Bool
	upstream := newLoopbackTestServer(t, gitHTTPBackendHandler(t, git, projectRoot, &sawChunkedReceivePack))
	defer upstream.Close()

	compiled := nativeGitConfig(t, temp, upstream.URL)
	store, err := tokens.Open(compiled.File.State.TokenFile, tokens.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	issued, err := store.Mint(context.Background(), tokens.MintRequest{
		Workload: "native-git-test", Audience: compiled.File.Server.Audience,
		ExpiresAt: time.Now().Add(time.Hour), Grants: compiled.Roles["git-agent"],
	})
	if err != nil {
		t.Fatal(err)
	}
	backend := secrets.NewFixedBackend([]byte("upstream-password"))
	defer backend.Close()
	var auditOutput bytes.Buffer
	auditor, err := audit.New(&auditOutput, audit.FailClosed)
	if err != nil {
		t.Fatal(err)
	}
	forcefield, err := New(compiled, store, backend, auditor, Options{
		ResolveWorkload: func(*http.Request) (string, error) { return "native-git-test", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	dataPlane := newLoopbackTestServer(t, forcefield)
	defer dataPlane.Close()

	clientHome := filepath.Join(temp, "client-home")
	if err := os.Mkdir(clientHome, 0o700); err != nil {
		t.Fatal(err)
	}
	credentialHelper := `!f() { test "$1" = get || exit 0; printf 'username=forcefield\npassword=%s\n\n' "$FORCEFIELD_TEST_TOKEN"; }; f`
	clientEnv := []string{
		"HOME=" + clientHome,
		"XDG_CONFIG_HOME=" + filepath.Join(clientHome, ".config"),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		"FORCEFIELD_TEST_TOKEN=" + issued.Bearer,
	}
	gitArgs := []string{
		"-c", "credential.helper=", "-c", "credential.helper=" + credentialHelper,
		"-c", "credential.useHttpPath=true", "-c", "protocol.version=2",
	}
	cloneURL := dataPlane.URL + "/git/acme/infrastructure.git"
	clone := filepath.Join(temp, "clone")
	runGitCommand(t, git, temp, clientEnv, append(gitArgs, "clone", cloneURL, clone)...)
	if value, err := os.ReadFile(filepath.Join(clone, "README.md")); err != nil || string(value) != "seed\n" {
		t.Fatalf("native clone contents = %q, %v", value, err)
	}

	runGitCommand(t, git, clone, clientEnv, "config", "user.name", "Forcefield Test")
	runGitCommand(t, git, clone, clientEnv, "config", "user.email", "forcefield@example.invalid")
	large := make([]byte, 64<<10)
	state := uint64(0x4d595df4d0f33173)
	for index := range large {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		large[index] = byte(state)
	}
	if err := os.WriteFile(filepath.Join(clone, "payload.bin"), large, 0o600); err != nil {
		t.Fatal(err)
	}
	runGitCommand(t, git, clone, clientEnv, "add", "payload.bin")
	runGitCommand(t, git, clone, clientEnv, "commit", "-m", "feature")
	pushArgs := append(append([]string(nil), gitArgs...), "-c", "http.postBuffer=1024")
	runGitCommand(t, git, clone, clientEnv, append(pushArgs, "push", "origin", "HEAD:refs/heads/feature")...)
	if !sawChunkedReceivePack.Load() {
		t.Fatal("native push did not exercise chunked receive-pack forwarding")
	}
	runGitCommand(t, git, temp, nil, "--git-dir", bareRepository, "show-ref", "--verify", "refs/heads/feature")

	output, pushErr := gitCommand(git, clone, clientEnv, append(pushArgs, "push", "origin", "HEAD:refs/heads/stable")...)
	if pushErr == nil {
		t.Fatalf("configured protected ref push succeeded: %s", output)
	}
	if _, err := gitCommand(git, temp, nil, "--git-dir", bareRepository, "show-ref", "--verify", "refs/heads/stable"); err == nil {
		t.Fatal("denied protected ref exists upstream")
	}
	if strings.Contains(auditOutput.String(), issued.Bearer) || strings.Contains(auditOutput.String(), "upstream-password") || strings.Contains(auditOutput.String(), "refs/heads/stable") {
		t.Fatal("native Git audit output exposed credential or ref material")
	}
}

func newLoopbackTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listeners are unavailable: %v", err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Listener = listener
	server.Start()
	return server
}

func nativeGitConfig(t *testing.T, temp, upstreamURL string) *config.Compiled {
	t.Helper()
	compiled, err := config.Compile(config.File{
		Version: 1,
		Server:  config.ServerConfig{Listen: "127.0.0.1:7902", Audience: "native-git", AdminSocket: filepath.Join(temp, "admin.sock")},
		State: config.StateConfig{
			TokenFile: filepath.Join(temp, "tokens.json"), AuditFile: filepath.Join(temp, "audit.jsonl"), AuditFailure: "closed",
		},
		Secrets: config.SecretBackendConfig{Type: "env", EnvPrefix: "FF_TEST_", MaxOutputBytes: 1024, MaxCacheEntries: 8},
		Services: map[string]config.ServiceConfig{
			"git": {
				Adapter: config.AdapterGitSmartHTTP, Upstream: upstreamURL, PathPrefix: "/git",
				Git:                   &config.GitServiceConfig{RepositoryCase: gitadapter.RepositoryCaseSensitive},
				AllowInsecureUpstream: true, AllowedCIDRs: []string{"127.0.0.0/8"},
				ClientAuth:     config.HeaderAuth{Header: "Authorization", Prefix: "Bearer "},
				ForwardHeaders: []string{"User-Agent"},
			},
		},
		Credentials: map[string]config.CredentialConfig{
			"git-user": {
				Service: "git", SecretRef: "GIT", Inject: config.HeaderAuth{Header: "Authorization"}, BasicUsername: "broker",
			},
		},
		Policies: map[string]config.PolicyConfig{
			"git-access": {
				Service: "git", Git: &config.GitPolicyConfig{Rules: []config.GitRuleConfig{
					{ID: "allow-fetch", Effect: gitadapter.EffectAllow, Operation: gitadapter.OperationFetch, Repositories: []string{"acme/infrastructure.git"}},
					{
						ID: "allow-branches", Effect: gitadapter.EffectAllow, Operation: gitadapter.OperationPush,
						Repositories: []string{"acme/infrastructure.git"}, Refs: []string{"refs/heads/**"},
						UpdateKinds: []gitadapter.UpdateKind{gitadapter.UpdateCreate, gitadapter.UpdateModify, gitadapter.UpdateDelete},
					},
					{
						ID: "deny-stable", Effect: gitadapter.EffectDeny, Operation: gitadapter.OperationPush,
						Repositories: []string{"acme/infrastructure.git"}, Refs: []string{"refs/heads/stable"},
					},
				}},
			},
		},
		Roles: map[string]config.RoleConfig{
			"git-agent": {Grants: []config.GrantConfig{{Service: "git", Credential: "git-user", Policy: "git-access"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

func gitHTTPBackendHandler(t *testing.T, git, projectRoot string, sawChunkedReceivePack *atomic.Bool) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, "/git-receive-pack") {
			for _, encoding := range request.TransferEncoding {
				if encoding == "chunked" {
					sawChunkedReceivePack.Store(true)
				}
			}
		}
		command := exec.CommandContext(request.Context(), git, "http-backend")
		command.Stdin = request.Body
		command.Env = append(os.Environ(),
			"GIT_PROJECT_ROOT="+projectRoot,
			"GIT_HTTP_EXPORT_ALL=1",
			"PATH_INFO="+request.URL.Path,
			"QUERY_STRING="+request.URL.RawQuery,
			"REQUEST_METHOD="+request.Method,
			"CONTENT_TYPE="+request.Header.Get("Content-Type"),
			"REMOTE_USER=broker",
			"REMOTE_ADDR=127.0.0.1",
			"GATEWAY_INTERFACE=CGI/1.1",
			"SERVER_PROTOCOL=HTTP/1.1",
			"SERVER_NAME=127.0.0.1",
			"SERVER_PORT=80",
			"HTTP_GIT_PROTOCOL="+request.Header.Get("Git-Protocol"),
		)
		if request.ContentLength >= 0 {
			command.Env = append(command.Env, "CONTENT_LENGTH="+strconv.FormatInt(request.ContentLength, 10))
		}
		output, err := command.Output()
		if err != nil {
			writer.WriteHeader(http.StatusBadGateway)
			return
		}
		writeCGIResponse(writer, output)
	})
}

func writeCGIResponse(writer http.ResponseWriter, output []byte) {
	separator := []byte("\r\n\r\n")
	index := bytes.Index(output, separator)
	if index < 0 {
		separator = []byte("\n\n")
		index = bytes.Index(output, separator)
	}
	if index < 0 {
		writer.WriteHeader(http.StatusBadGateway)
		return
	}
	status := http.StatusOK
	scanner := bufio.NewScanner(bytes.NewReader(output[:index]))
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		name, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		if strings.EqualFold(name, "Status") {
			if fields := strings.Fields(value); len(fields) != 0 {
				if parsed, err := strconv.Atoi(fields[0]); err == nil {
					status = parsed
				}
			}
			continue
		}
		writer.Header().Add(name, value)
	}
	writer.WriteHeader(status)
	_, _ = writer.Write(output[index+len(separator):])
}

func runGitCommand(t *testing.T, git, directory string, environment []string, args ...string) {
	t.Helper()
	if output, err := gitCommand(git, directory, environment, args...); err != nil {
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, output)
	}
}

func gitCommand(git, directory string, environment []string, args ...string) (string, error) {
	command := exec.Command(git, args...)
	command.Dir = directory
	command.Env = append(os.Environ(), environment...)
	output, err := command.CombinedOutput()
	return string(output), err
}
