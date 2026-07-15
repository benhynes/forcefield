package gateway

import (
	"bytes"
	"context"
	"crypto/rsa"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/benhynes/forcefield/internal/audit"
	"github.com/benhynes/forcefield/internal/config"
	"github.com/benhynes/forcefield/internal/tokens"
	"golang.org/x/crypto/ssh"
)

var (
	errSSHInputLimit    = errors.New("SSH input limit exhausted")
	errSSHProtocolLimit = errors.New("SSH protocol request limit exhausted")
)

const (
	sshRevalidationInterval          = time.Second
	defaultSSHGuestHandshakeTimeout  = 10 * time.Second
	maxSSHProtocolRequestsPerSession = 4096
	sshProtocolRequestsPerSecond     = 64
	sshProtocolRequestBurst          = 128
)

// serveSSH terminates an SSH connection carried inside one authenticated,
// full-duplex HTTPS request. The outer request supplies Forcefield workload
// identity and authorization; the inner SSH connection supplies native
// channel, PTY, signal, and exit-status semantics without ever receiving the
// upstream private key.
func (g *Gateway) serveSSH(w http.ResponseWriter, r *http.Request, canonical CanonicalURL, service *runtimeService, relativePath string, started time.Time, metadata auditMetadata) {
	controller := http.NewResponseController(w)
	if err := controller.EnableFullDuplex(); err != nil {
		g.recordDeny(started, metadata, serviceName(service), "", "", http.StatusNotFound, 0)
		g.deny(w)
		return
	}
	if service == nil || service.ssh == nil || service.sshDialer == nil || g.sshHostSigner == nil ||
		r.Method != http.MethodPost || relativePath != "/" || canonical.RawQuery != "" || r.URL.ForceQuery ||
		r.ContentLength != -1 || len(r.Header.Values("Content-Encoding")) != 0 ||
		len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Type") != "application/octet-stream" ||
		r.Header.Get(config.SSHStreamProtocolHeader) != config.SSHStreamProtocol ||
		len(r.Header.Values(config.SSHStreamProtocolHeader)) != 1 || !validSSHTransferEncoding(r) {
		g.recordDeny(started, metadata, serviceName(service), "", "", http.StatusNotFound, 0)
		g.deny(w)
		return
	}
	token, err := service.extractor.ExtractToken(r)
	if err != nil {
		g.recordDeny(started, metadata, service.name, "", "", http.StatusNotFound, 0)
		g.deny(w)
		return
	}
	workload, err := g.workload(r)
	if err != nil {
		g.recordDeny(started, metadata, service.name, "", "", http.StatusNotFound, 0)
		g.deny(w)
		return
	}
	claims, err := g.tokens.Validate(r.Context(), token, tokens.ValidationRequest{Workload: workload, Audience: g.config.File.Server.Audience})
	if err != nil {
		g.recordDeny(started, metadata, service.name, workload, "", http.StatusNotFound, 0)
		g.deny(w)
		return
	}
	metadata.TokenID, metadata.RootTokenID = claims.TokenID, claims.RootTokenID
	grant, ok := oneGrantForService(claims.Grants, service.name)
	grantID := config.GrantID(grant)
	credential := g.credentials[grant.CredentialRef]
	compiledPolicy, policyOK := g.config.ResolveGrant(grant)
	if !ok || credential == nil || credential.service != service.name || credential.bindingRevision == "" ||
		grant.BindingRevision != credential.bindingRevision || !policyOK || service.adapter != config.AdapterSSHSession ||
		compiledPolicy.Adapter != config.AdapterSSHSession || compiledPolicy.SSHPolicy == nil {
		g.recordDeny(started, metadata, service.name, workload, grantID, http.StatusNotFound, 0)
		g.deny(w)
		return
	}
	limitScopes, ok := claimLimitScopes(claims, grant)
	if !ok {
		g.recordDeny(started, metadata, service.name, workload, grantID, http.StatusNotFound, 0)
		g.deny(w)
		return
	}
	releaseConcurrency, ok := g.sshConcurrency.acquire(claims.TokenID, workload)
	if !ok {
		g.recordDeny(started, metadata, service.name, workload, grantID, http.StatusTooManyRequests, 0)
		g.writeGeneric(w, http.StatusTooManyRequests)
		return
	}
	defer releaseConcurrency()
	if !g.limits.allowRequest(limitScopes) {
		g.recordDeny(started, metadata, service.name, workload, grantID, http.StatusTooManyRequests, 0)
		g.writeGeneric(w, http.StatusTooManyRequests)
		return
	}
	deadline := started.Add(compiledPolicy.SSHPolicy.MaxSessionDuration.Value())
	if claims.ExpiresAt.Before(deadline) {
		deadline = claims.ExpiresAt
	}
	if !time.Now().Before(deadline) {
		g.recordDeny(started, metadata, service.name, workload, grantID, http.StatusNotFound, 0)
		g.deny(w)
		return
	}
	sessionContext, cancelSession := context.WithDeadline(r.Context(), deadline)
	defer cancelSession()
	if controller.SetReadDeadline(deadline) != nil || controller.SetWriteDeadline(deadline) != nil {
		g.recordError(started, metadata, service.name, workload, grantID, compiledPolicy.Revision, http.StatusInternalServerError, 0)
		g.writeGeneric(w, http.StatusInternalServerError)
		return
	}

	// The fail-closed authorization record precedes secret retrieval and any
	// upstream authentication, preserving the gateway-wide exercise boundary.
	if err := g.audit.Record(audit.Record{
		RequestID: metadata.RequestID, TokenID: metadata.TokenID, RootTokenID: metadata.RootTokenID,
		Method: metadata.Method, PathHash: metadata.PathHash, PolicyRevision: compiledPolicy.Revision,
		RuleID: "ssh-session", Reason: "authorized", WorkloadID: workload, GrantID: grantID,
		Service: service.name, Decision: audit.DecisionAllow, Latency: time.Since(started),
	}); err != nil {
		g.writeGeneric(w, http.StatusServiceUnavailable)
		return
	}
	if !g.tokenStillValid(sessionContext, token, workload, claims, grant) {
		g.recordDeny(started, metadata, service.name, workload, grantID, http.StatusNotFound, 0)
		g.deny(w)
		return
	}

	lease, err := g.secrets.Get(sessionContext, credential.ref)
	if err != nil {
		g.recordError(started, metadata, service.name, workload, grantID, compiledPolicy.Revision, http.StatusBadGateway, 0)
		g.writeGeneric(w, http.StatusBadGateway)
		return
	}
	privateKey, err := lease.Clone()
	lease.Release()
	if err != nil || len(privateKey) == 0 {
		zeroBytes(privateKey)
		g.recordError(started, metadata, service.name, workload, grantID, compiledPolicy.Revision, http.StatusBadGateway, 0)
		g.writeGeneric(w, http.StatusBadGateway)
		return
	}
	upstreamSigner, err := ssh.ParsePrivateKey(privateKey)
	zeroBytes(privateKey)
	if err != nil {
		g.recordError(started, metadata, service.name, workload, grantID, compiledPolicy.Revision, http.StatusBadGateway, 0)
		g.writeGeneric(w, http.StatusBadGateway)
		return
	}
	upstreamSigner, err = restrictedSSHSigner(upstreamSigner)
	if err != nil {
		g.recordError(started, metadata, service.name, workload, grantID, compiledPolicy.Revision, http.StatusBadGateway, 0)
		g.writeGeneric(w, http.StatusBadGateway)
		return
	}
	// Secret retrieval can be slow. Revalidate after the key has been parsed
	// and before any TCP connection or private-key authentication is attempted.
	if !g.tokenStillValid(sessionContext, token, workload, claims, grant) {
		g.recordDeny(started, metadata, service.name, workload, grantID, http.StatusNotFound, 0)
		g.deny(w)
		return
	}
	upstreamClient, upstreamNet, err := g.dialSSHUpstream(sessionContext, service, upstreamSigner, deadline)
	if err != nil {
		g.recordError(started, metadata, service.name, workload, grantID, compiledPolicy.Revision, http.StatusBadGateway, 0)
		g.writeGeneric(w, http.StatusBadGateway)
		return
	}
	var stream *httpSSHConn
	var inbound *ssh.ServerConn
	var abortOnce sync.Once
	abort := func() {
		abortOnce.Do(func() {
			_ = upstreamNet.Close()
			_ = upstreamClient.Close()
			if stream != nil {
				_ = stream.Close()
			}
		})
	}
	// Authority-side sockets always close first. Downstream close paths may
	// otherwise block behind an uncooperative client's response window.
	defer func() {
		abort()
		if inbound != nil {
			_ = inbound.Close()
		}
	}()
	if !g.tokenStillValid(sessionContext, token, workload, claims, grant) {
		g.recordDeny(started, metadata, service.name, workload, grantID, http.StatusNotFound, 0)
		g.deny(w)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set(config.SSHStreamProtocolHeader, config.SSHStreamProtocol)
	w.Header().Set(config.SSHStreamHostKeyHeader, ssh.FingerprintSHA256(g.sshHostSigner.PublicKey()))
	w.WriteHeader(http.StatusOK)
	if err := controller.Flush(); err != nil {
		g.recordSSHCompletion(started, metadata, service.name, workload, grantID, compiledPolicy.Revision, audit.DecisionError, "response_flush", 0, 0)
		return
	}

	stream = &httpSSHConn{
		body: r.Body, writer: w, controller: controller,
		local: stringAddr("forcefield-ssh"), remote: stringAddr(r.RemoteAddr),
	}
	var bytesIn, bytesOut atomic.Uint64
	revoked := make(chan struct{}, 1)
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		ticker := time.NewTicker(sshRevalidationInterval)
		defer ticker.Stop()
		for {
			select {
			case <-sessionContext.Done():
				return
			case <-ticker.C:
				validationContext, validationCancel := context.WithTimeout(context.Background(), sshRevalidationInterval)
				valid := g.tokenStillValid(validationContext, token, workload, claims, grant)
				validationCancel()
				if !valid {
					select {
					case revoked <- struct{}{}:
					default:
					}
					cancelSession()
					// Close the authority side before touching the HTTP stream.
					// httpSSHConn.Close first forces deadlines so Body.Close cannot
					// wait indefinitely behind a blocked request-body read.
					abort()
					return
				}
			}
		}
	}()
	defer func() {
		cancelSession()
		<-monitorDone
	}()

	guestHandshakeDeadline := time.Now().Add(g.sshHandshakeTimeout)
	if deadline.Before(guestHandshakeDeadline) {
		guestHandshakeDeadline = deadline
	}
	if err := stream.SetDeadline(guestHandshakeDeadline); err != nil {
		g.recordSSHCompletion(started, metadata, service.name, workload, grantID, compiledPolicy.Revision, audit.DecisionError, "ssh_handshake_deadline", 0, 0)
		return
	}
	algorithms := ssh.SupportedAlgorithms()
	inboundConfig := &ssh.ServerConfig{
		Config:       ssh.Config{Ciphers: algorithms.Ciphers, MACs: algorithms.MACs, KeyExchanges: algorithms.KeyExchanges},
		NoClientAuth: true, ServerVersion: "SSH-2.0-Forcefield",
		NoClientAuthCallback: func(metadata ssh.ConnMetadata) (*ssh.Permissions, error) {
			if metadata == nil || metadata.User() != "forcefield" {
				return nil, errors.New("invalid SSH stream user")
			}
			return nil, nil
		},
	}
	inboundConfig.AddHostKey(g.sshHostSigner)
	inboundConnection, channels, globalRequests, err := ssh.NewServerConn(stream, inboundConfig)
	if err != nil {
		decision, reason := audit.DecisionError, "ssh_handshake"
		select {
		case <-revoked:
			decision, reason = audit.DecisionDeny, "token_invalidated"
		default:
			if !time.Now().Before(guestHandshakeDeadline) {
				decision, reason = audit.DecisionDeny, "ssh_handshake_timeout"
			}
		}
		g.recordSSHCompletion(started, metadata, service.name, workload, grantID, compiledPolicy.Revision, decision, reason, 0, 0)
		return
	}
	inbound = inboundConnection
	if err := stream.SetDeadline(deadline); err != nil {
		g.recordSSHCompletion(started, metadata, service.name, workload, grantID, compiledPolicy.Revision, audit.DecisionError, "ssh_session_deadline", 0, 0)
		return
	}

	relayErr := g.relaySSHConnection(sessionContext, inbound, channels, globalRequests, upstreamClient, compiledPolicy.SSHPolicy, limitScopes, grant.Limits.MaxRequestBytes, &bytesIn, &bytesOut, abort)
	sessionContextErr := sessionContext.Err()
	cancelSession()
	<-monitorDone
	decision, reason := audit.DecisionAllow, "completed"
	select {
	case <-revoked:
		decision, reason = audit.DecisionDeny, "token_invalidated"
	default:
		if errors.Is(relayErr, errSSHInputLimit) || errors.Is(relayErr, errSSHProtocolLimit) {
			decision, reason = audit.DecisionDeny, "limit_exhausted"
		} else if errors.Is(relayErr, context.DeadlineExceeded) || errors.Is(sessionContextErr, context.DeadlineExceeded) {
			reason = "deadline"
		} else if relayErr != nil && !errors.Is(relayErr, io.EOF) && !errors.Is(relayErr, net.ErrClosed) && !errors.Is(relayErr, context.Canceled) {
			decision, reason = audit.DecisionError, "session_transport"
		}
	}
	g.recordSSHCompletion(started, metadata, service.name, workload, grantID, compiledPolicy.Revision, decision, reason, auditCount(bytesIn.Load()), auditCount(bytesOut.Load()))
}

func serviceName(service *runtimeService) string {
	if service == nil {
		return "ssh-session"
	}
	return service.name
}

func validSSHTransferEncoding(r *http.Request) bool {
	if len(r.TransferEncoding) == 0 {
		return r.ProtoMajor >= 2
	}
	return len(r.TransferEncoding) == 1 && strings.EqualFold(r.TransferEncoding[0], "chunked")
}

func (g *Gateway) dialSSHUpstream(ctx context.Context, service *runtimeService, signer ssh.Signer, deadline time.Time) (*ssh.Client, net.Conn, error) {
	port := service.upstream.Port()
	target := net.JoinHostPort(service.upstream.Hostname(), port)
	connection, err := service.sshDialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, nil, err
	}
	stopContextClose := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stopContextClose()
	closeOnError := func(err error) (*ssh.Client, net.Conn, error) {
		_ = connection.Close()
		return nil, nil, err
	}
	handshakeDeadline := time.Now().Add(service.ssh.ConnectTimeout.Value())
	if deadline.Before(handshakeDeadline) {
		handshakeDeadline = deadline
	}
	if err := connection.SetDeadline(handshakeDeadline); err != nil {
		return closeOnError(err)
	}
	pins := make(map[string]struct{}, len(service.ssh.HostKeySHA256))
	for _, pin := range service.ssh.HostKeySHA256 {
		pins[pin] = struct{}{}
	}
	clientConfig := &ssh.ClientConfig{
		Config: ssh.Config{Ciphers: ssh.SupportedAlgorithms().Ciphers, MACs: ssh.SupportedAlgorithms().MACs, KeyExchanges: ssh.SupportedAlgorithms().KeyExchanges},
		User:   service.ssh.User, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			if hostname != target || remote == nil {
				return errors.New("SSH upstream identity mismatch")
			}
			if err := validateSSHPublicKeyStrength(key); err != nil {
				return err
			}
			if _, ok := pins[ssh.FingerprintSHA256(key)]; !ok {
				return errors.New("SSH upstream host key mismatch")
			}
			return nil
		},
		HostKeyAlgorithms: supportedSSHHostKeyAlgorithms(),
		ClientVersion:     "SSH-2.0-Forcefield",
	}
	clientConnection, channels, requests, err := ssh.NewClientConn(connection, target, clientConfig)
	if err != nil {
		return closeOnError(err)
	}
	if err := connection.SetDeadline(deadline); err != nil {
		_ = clientConnection.Close()
		return closeOnError(err)
	}
	return ssh.NewClient(clientConnection, channels, requests), connection, nil
}

// restrictedSSHSigner makes the public-key signature allowlist explicit.
// In particular, an RSA key must never fall back to the legacy SHA-1
// "ssh-rsa" signature when an old server omits server-sig-algs.
func restrictedSSHSigner(signer ssh.Signer) (ssh.Signer, error) {
	if signer == nil || signer.PublicKey() == nil {
		return nil, errors.New("invalid SSH private key")
	}
	if err := validateSSHPublicKeyStrength(signer.PublicKey()); err != nil {
		return nil, err
	}
	algorithmSigner, ok := signer.(ssh.AlgorithmSigner)
	if !ok {
		return nil, errors.New("SSH private key does not support explicit signature algorithms")
	}
	var algorithms []string
	switch keyType := signer.PublicKey().Type(); keyType {
	case ssh.KeyAlgoRSA:
		algorithms = []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	default:
		if !slices.Contains(ssh.SupportedAlgorithms().PublicKeyAuths, keyType) {
			return nil, errors.New("unsupported SSH private-key algorithm")
		}
		algorithms = []string{keyType}
	}
	restricted, err := ssh.NewSignerWithAlgorithms(algorithmSigner, algorithms)
	if err != nil {
		return nil, errors.New("restrict SSH private-key algorithms")
	}
	return restricted, nil
}

func validateSSHPublicKeyStrength(key ssh.PublicKey) error {
	if key == nil {
		return errors.New("invalid SSH public key")
	}
	if _, ok := key.(*ssh.Certificate); ok {
		return errors.New("SSH host certificates are not supported")
	}
	if key.Type() != ssh.KeyAlgoRSA {
		return nil
	}
	cryptoKey, ok := key.(ssh.CryptoPublicKey)
	if !ok {
		return errors.New("SSH RSA key does not expose its public parameters")
	}
	publicKey, ok := cryptoKey.CryptoPublicKey().(*rsa.PublicKey)
	if !ok || publicKey.N == nil || publicKey.N.BitLen() < 2048 {
		return errors.New("SSH RSA key must be at least 2048 bits")
	}
	return nil
}

func supportedSSHHostKeyAlgorithms() []string {
	algorithms := ssh.SupportedAlgorithms().HostKeys
	result := make([]string, 0, len(algorithms))
	for _, algorithm := range algorithms {
		if strings.Contains(algorithm, "-cert-v01@openssh.com") {
			continue
		}
		result = append(result, algorithm)
	}
	return result
}

func (g *Gateway) relaySSHConnection(ctx context.Context, inbound *ssh.ServerConn, channels <-chan ssh.NewChannel, globalRequests <-chan *ssh.Request, upstream *ssh.Client, policy *config.SSHPolicyConfig, scopes []limitScope, maxInput uint64, bytesIn, bytesOut *atomic.Uint64, abort func()) error {
	var workers sync.WaitGroup
	defer func() {
		abort()
		workers.Wait()
	}()
	protocolLimiter := newSSHProtocolLimiter(time.Now)
	inputLimiter := &sshInputLimiter{
		maximum: maxInput,
		counted: bytesIn,
		allow: func(count uint64) bool {
			return g.limits.allowBytes(scopes, count)
		},
	}
	startSSHWorker(&workers, func() { rejectSSHRequests(globalRequests, protocolLimiter) })
	var requested ssh.NewChannel
	for requested == nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-protocolLimiter.exhausted:
			return errSSHProtocolLimit
		case next, ok := <-channels:
			if !ok {
				return io.EOF
			}
			if !protocolLimiter.allowRequest() {
				return errSSHProtocolLimit
			}
			if next.ChannelType() != "session" || len(next.ExtraData()) != 0 {
				_ = next.Reject(ssh.Prohibited, "only one session channel is available")
				continue
			}
			requested = next
		}
	}
	upstreamChannel, upstreamRequests, err := upstream.OpenChannel("session", nil)
	if err != nil {
		_ = requested.Reject(ssh.ConnectionFailed, "upstream session unavailable")
		return err
	}
	inboundChannel, inboundRequests, err := requested.Accept()
	if err != nil {
		return err
	}
	// The deferred abort closes the raw authority-side socket before joining
	// relay workers. Synchronous SSH channel closes can themselves block behind
	// a saturated peer and are therefore deliberately omitted here.
	fatal := make(chan error, 8)
	startSSHWorker(&workers, func() {
		for extra := range channels {
			if !protocolLimiter.allowRequest() {
				select {
				case fatal <- errSSHProtocolLimit:
				default:
				}
				return
			}
			_ = extra.Reject(ssh.Prohibited, "only one session channel is available")
		}
	})
	return g.relaySSHSession(ctx, inboundChannel, inboundRequests, upstreamChannel, upstreamRequests, policy, protocolLimiter, inputLimiter, fatal, bytesOut, &workers)
}

func startSSHWorker(workers *sync.WaitGroup, work func()) {
	workers.Add(1)
	go func() {
		defer workers.Done()
		work()
	}()
}

func rejectSSHRequests(requests <-chan *ssh.Request, limiter *sshProtocolLimiter) {
	for request := range requests {
		if !limiter.allowRequest() {
			return
		}
		if request == nil {
			continue
		}
		if request.WantReply {
			_ = request.Reply(false, nil)
		}
	}
}

func (g *Gateway) relaySSHSession(ctx context.Context, inbound ssh.Channel, inboundRequests <-chan *ssh.Request, upstream ssh.Channel, upstreamRequests <-chan *ssh.Request, policy *config.SSHPolicyConfig, protocolLimiter *sshProtocolLimiter, inputLimiter *sshInputLimiter, fatal chan error, bytesOut *atomic.Uint64, workers *sync.WaitGroup) error {
	outputDone := make(chan struct{})
	upstreamRequestsDone := make(chan struct{})
	startRequestReplied := make(chan bool, 1)
	var outputCopies sync.WaitGroup
	outputCopies.Add(2)
	startSSHWorker(workers, func() {
		writer := &sshLimitedWriter{destination: upstream, limiter: inputLimiter}
		_, err := io.Copy(writer, inbound)
		_ = upstream.CloseWrite()
		if err != nil {
			fatal <- err
		}
	})
	startSSHWorker(workers, func() {
		defer outputCopies.Done()
		_, err := io.Copy(&sshCountingWriter{destination: inbound, counted: bytesOut}, upstream)
		if err != nil {
			fatal <- err
		}
	})
	startSSHWorker(workers, func() {
		defer outputCopies.Done()
		_, err := io.Copy(&sshCountingWriter{destination: inbound.Stderr(), counted: bytesOut}, upstream.Stderr())
		if err != nil {
			fatal <- err
		}
	})
	startSSHWorker(workers, func() {
		outputCopies.Wait()
		close(outputDone)
	})
	startSSHWorker(workers, func() {
		if err := forwardClientSSHRequests(inboundRequests, upstream, policy, protocolLimiter, inputLimiter, startRequestReplied); err != nil {
			fatal <- err
		}
	})
	startSSHWorker(workers, func() {
		forwardUpstreamSSHRequests(upstreamRequests, inbound)
		close(upstreamRequestsDone)
	})

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-protocolLimiter.exhausted:
		return errSSHProtocolLimit
	case err := <-fatal:
		return err
	case <-outputDone:
	}
	// A fast command can emit EOF and exit-status immediately after accepting
	// shell/exec. Do not tear down the downstream channel until the acceptance
	// reply has crossed it, or Session.Shell/Start can race and observe EOF.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-protocolLimiter.exhausted:
		return errSSHProtocolLimit
	case err := <-fatal:
		return err
	case <-startRequestReplied:
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-protocolLimiter.exhausted:
		return errSSHProtocolLimit
	case err := <-fatal:
		return err
	case <-upstreamRequestsDone:
		return nil
	}
}

type sshRequestState struct {
	started bool
	pty     bool
}

func forwardClientSSHRequests(requests <-chan *ssh.Request, upstream ssh.Channel, policy *config.SSHPolicyConfig, protocolLimiter *sshProtocolLimiter, inputLimiter *sshInputLimiter, startRequestReplied chan<- bool) error {
	state := sshRequestState{}
	startNotified := false
	defer func() {
		if !startNotified {
			startRequestReplied <- false
		}
	}()
	for request := range requests {
		if !protocolLimiter.allowRequest() {
			return errSSHProtocolLimit
		}
		if request == nil {
			continue
		}
		allowed := validateClientSSHRequest(request, policy, state)
		accepted := false
		if allowed {
			if !inputLimiter.consume(uint64(len(request.Payload))) {
				if request.WantReply {
					_ = request.Reply(false, nil)
				}
				return errSSHInputLimit
			}
			ok, err := upstream.SendRequest(request.Type, request.WantReply, request.Payload)
			accepted = err == nil && (!request.WantReply || ok)
		}
		startRequest := false
		if accepted {
			switch request.Type {
			case "pty-req":
				state.pty = true
			case "shell", "exec":
				state.started = true
				startRequest = true
			}
		}
		replied := true
		if request.WantReply {
			replied = request.Reply(accepted, nil) == nil
		}
		if startRequest && replied && !startNotified {
			startRequestReplied <- true
			startNotified = true
		}
	}
	return nil
}

func validateClientSSHRequest(request *ssh.Request, policy *config.SSHPolicyConfig, state sshRequestState) bool {
	if request == nil || policy == nil {
		return false
	}
	switch request.Type {
	case "shell":
		return request.WantReply && policy.AllowShell && !state.started && len(request.Payload) == 0
	case "exec":
		var value struct{ Command string }
		return request.WantReply && policy.AllowExec && !state.started && exactSSHUnmarshal(request.Payload, &value) && len(value.Command) <= 32<<10 && !strings.ContainsRune(value.Command, 0)
	case "pty-req":
		var value struct {
			Term                      string
			Columns, Rows             uint32
			WidthPixels, HeightPixels uint32
			Modes                     string
		}
		return request.WantReply && policy.AllowPTY && !state.started && !state.pty && exactSSHUnmarshal(request.Payload, &value) &&
			validSSHTerm(value.Term) && len(value.Modes) <= 4<<10
	case "window-change":
		var value struct{ Columns, Rows, WidthPixels, HeightPixels uint32 }
		return !request.WantReply && state.pty && exactSSHUnmarshal(request.Payload, &value)
	case "signal":
		var value struct{ Signal string }
		return !request.WantReply && state.started && exactSSHUnmarshal(request.Payload, &value) && validSSHSignal(value.Signal)
	case "break":
		var value struct{ Length uint32 }
		return request.WantReply && state.started && exactSSHUnmarshal(request.Payload, &value)
	default:
		// env, subsystem, agent/X11 forwarding, and vendor extensions are
		// deliberately unavailable in adapter v1.
		return false
	}
}

func forwardUpstreamSSHRequests(requests <-chan *ssh.Request, inbound ssh.Channel) {
	for request := range requests {
		allowed := request != nil && !request.WantReply
		if request == nil {
			continue
		}
		switch request.Type {
		case "exit-status":
			var value struct{ Status uint32 }
			allowed = allowed && exactSSHUnmarshal(request.Payload, &value)
		case "exit-signal":
			var value struct {
				Signal       string
				CoreDumped   bool
				ErrorMessage string
				LanguageTag  string
			}
			allowed = allowed && exactSSHUnmarshal(request.Payload, &value) && validSSHSignal(value.Signal) && len(value.ErrorMessage) <= 4<<10 && len(value.LanguageTag) <= 128
		case "eow@openssh.com":
			allowed = allowed && len(request.Payload) == 0
		default:
			allowed = false
		}
		accepted := false
		if allowed {
			_, err := inbound.SendRequest(request.Type, false, request.Payload)
			accepted = err == nil
		}
		if request.WantReply {
			_ = request.Reply(accepted, nil)
		}
	}
}

func exactSSHUnmarshal(payload []byte, destination any) bool {
	if len(payload) > 64<<10 || ssh.Unmarshal(payload, destination) != nil {
		return false
	}
	return bytes.Equal(payload, ssh.Marshal(destination))
}

func validSSHTerm(value string) bool {
	if value == "" || len(value) > 128 || !utf8.ValidString(value) {
		return false
	}
	for _, current := range value {
		if unicode.IsControl(current) || unicode.IsSpace(current) || unicode.Is(unicode.Cf, current) {
			return false
		}
	}
	return true
}

func validSSHSignal(value string) bool {
	if value == "" || len(value) > 32 {
		return false
	}
	for _, current := range value {
		if current < 'A' || current > 'Z' {
			return false
		}
	}
	return true
}

type sshProtocolLimiter struct {
	mu        sync.Mutex
	now       func() time.Time
	last      time.Time
	tokens    float64
	total     int
	denied    bool
	exhausted chan struct{}
	once      sync.Once
}

func newSSHProtocolLimiter(now func() time.Time) *sshProtocolLimiter {
	if now == nil {
		now = time.Now
	}
	current := now()
	return &sshProtocolLimiter{
		now: now, last: current, tokens: sshProtocolRequestBurst,
		exhausted: make(chan struct{}),
	}
}

func (l *sshProtocolLimiter) allowRequest() bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	if l.denied || l.total >= maxSSHProtocolRequestsPerSession {
		l.denied = true
		l.mu.Unlock()
		l.once.Do(func() { close(l.exhausted) })
		return false
	}
	now := l.now()
	elapsed := now.Sub(l.last)
	if elapsed > 0 {
		l.tokens += elapsed.Seconds() * sshProtocolRequestsPerSecond
		if l.tokens > sshProtocolRequestBurst {
			l.tokens = sshProtocolRequestBurst
		}
		l.last = now
	}
	l.total++
	if l.tokens < 1 {
		l.denied = true
		l.mu.Unlock()
		l.once.Do(func() { close(l.exhausted) })
		return false
	}
	l.tokens--
	l.mu.Unlock()
	return true
}

// sshInputLimiter counts decoded channel data plus the raw payload of every
// client request that is actually forwarded upstream. SSH packet framing,
// encryption overhead, rejected requests, and Forcefield/upstream replies are
// intentionally outside the configured payload-byte budget; every request
// attempt is separately covered by sshProtocolLimiter.
type sshInputLimiter struct {
	mu      sync.Mutex
	maximum uint64
	counted *atomic.Uint64
	allow   func(uint64) bool
}

func (l *sshInputLimiter) consume(count uint64) bool {
	if l == nil || l.counted == nil {
		return false
	}
	if count == 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	current := l.counted.Load()
	if l.maximum != 0 && (current > l.maximum || count > l.maximum-current) || l.allow != nil && !l.allow(count) {
		return false
	}
	l.counted.Add(count)
	return true
}

type sshLimitedWriter struct {
	destination io.Writer
	limiter     *sshInputLimiter
}

func (w *sshLimitedWriter) Write(value []byte) (int, error) {
	if len(value) == 0 {
		return 0, nil
	}
	if !w.limiter.consume(uint64(len(value))) {
		return 0, errSSHInputLimit
	}
	written, err := w.destination.Write(value)
	if err == nil && written != len(value) {
		err = io.ErrShortWrite
	}
	return written, err
}

type sshCountingWriter struct {
	destination io.Writer
	counted     *atomic.Uint64
}

func (w *sshCountingWriter) Write(value []byte) (int, error) {
	written, err := w.destination.Write(value)
	if written > 0 {
		w.counted.Add(uint64(written))
	}
	return written, err
}

func (g *Gateway) recordSSHCompletion(started time.Time, metadata auditMetadata, service, workload, grant, revision string, decision audit.Decision, reason string, bytesIn, bytesOut int64) {
	_ = g.audit.Record(audit.Record{
		RequestID: metadata.RequestID, TokenID: metadata.TokenID, RootTokenID: metadata.RootTokenID,
		Method: metadata.Method, PathHash: metadata.PathHash, PolicyRevision: revision,
		RuleID: "ssh-session", Reason: reason, WorkloadID: workload, GrantID: grant,
		Service: service, Decision: decision, Status: http.StatusOK, Latency: time.Since(started),
		BytesIn: bytesIn, BytesOut: bytesOut,
	})
}

func auditCount(value uint64) int64 {
	if value > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(value)
}

// httpSSHConn adapts a full-duplex HTTP body/response pair to the stream
// interface expected by x/crypto/ssh. Writes are flushed so SSH handshake and
// interactive terminal packets do not wait for HTTP buffering.
type httpSSHConn struct {
	body       io.ReadCloser
	writer     http.ResponseWriter
	controller *http.ResponseController
	local      net.Addr
	remote     net.Addr
	writeMu    sync.Mutex
	closeOnce  sync.Once
}

func (c *httpSSHConn) Read(value []byte) (int, error) { return c.body.Read(value) }

func (c *httpSSHConn) Write(value []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	written, err := c.writer.Write(value)
	if err == nil {
		err = c.controller.Flush()
	}
	return written, err
}

func (c *httpSSHConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		// Body.Close alone can wait behind a concurrent blocking Body.Read in
		// net/http. Expire both directions first so revocation and deadlines do
		// not depend on client cooperation.
		err = errors.Join(c.SetDeadline(time.Now()), c.body.Close())
	})
	return err
}

func (c *httpSSHConn) LocalAddr() net.Addr  { return c.local }
func (c *httpSSHConn) RemoteAddr() net.Addr { return c.remote }
func (c *httpSSHConn) SetDeadline(value time.Time) error {
	return errors.Join(c.controller.SetReadDeadline(value), c.controller.SetWriteDeadline(value))
}
func (c *httpSSHConn) SetReadDeadline(value time.Time) error {
	return c.controller.SetReadDeadline(value)
}
func (c *httpSSHConn) SetWriteDeadline(value time.Time) error {
	return c.controller.SetWriteDeadline(value)
}

type stringAddr string

func (a stringAddr) Network() string { return "forcefield" }
func (a stringAddr) String() string  { return string(a) }
