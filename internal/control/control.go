// Package control implements Forcefield's same-user administrative API over a
// Unix domain socket. The public gateway never exposes token minting or
// revocation endpoints.
package control

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/benhynes/forcefield/internal/audit"
	"github.com/benhynes/forcefield/internal/config"
	"github.com/benhynes/forcefield/internal/tokens"
)

const (
	maxControlBody            = 64 << 10
	compensatingRevokeTimeout = 2 * time.Second
)

var (
	ErrControlRequest = errors.New("invalid control request")
	ErrControlAccess  = errors.New("control access denied")
)

type TokenStore interface {
	Mint(context.Context, tokens.MintRequest) (tokens.IssuedToken, error)
	Validate(context.Context, string, tokens.ValidationRequest) (tokens.Claims, error)
	Delegate(context.Context, string, tokens.DelegateRequest) (tokens.IssuedToken, error)
	RevokeTokenID(context.Context, string) error
}

type Server struct {
	config      *config.Compiled
	store       TokenStore
	maxTTL      time.Duration
	httpServer  *http.Server
	listener    net.Listener
	path        string
	closeOnce   sync.Once
	auditor     Auditor
	requestSeed string
	requestSeq  atomic.Uint64
}

type Auditor interface {
	Record(audit.Record) error
}

type MintRequest struct {
	Role            string `json:"role"`
	Workload        string `json:"workload"`
	TTLSeconds      int64  `json:"ttl_seconds"`
	AllowDelegation bool   `json:"allow_delegation,omitempty"`
}

type DelegateRequest struct {
	ParentToken     string   `json:"parent_token"`
	CallerWorkload  string   `json:"caller_workload"`
	Workload        string   `json:"workload"`
	Services        []string `json:"services"`
	TTLSeconds      int64    `json:"ttl_seconds"`
	AllowDelegation bool     `json:"allow_delegation,omitempty"`
}

type RevokeRequest struct {
	TokenID string `json:"token_id"`
}

type tokenResponse struct {
	Bearer string        `json:"bearer"`
	Claims tokens.Claims `json:"claims"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func NewServer(compiled *config.Compiled, store TokenStore, auditor Auditor) (*Server, error) {
	if compiled == nil || store == nil || auditor == nil {
		return nil, errors.New("control dependencies are required")
	}
	maxTTL := compiled.File.Server.MaxTokenTTL.Value()
	if maxTTL <= 0 {
		maxTTL = 24 * time.Hour
	}
	var seed [8]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, errors.New("initialize control request IDs")
	}
	server := &Server{
		config: compiled, store: store, auditor: auditor, maxTTL: maxTTL,
		path: compiled.File.Server.AdminSocket, requestSeed: hex.EncodeToString(seed[:]),
	}
	server.httpServer = &http.Server{
		Handler: server.handler(), ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second,
		MaxHeaderBytes: 16 << 10,
	}
	return server, nil
}

func (s *Server) Listen() error {
	if s.listener != nil {
		return errors.New("control server is already listening")
	}
	if err := prepareSocketPath(s.path); err != nil {
		return err
	}
	listener, err := net.Listen("unix", s.path)
	if err != nil {
		return fmt.Errorf("listen on control socket: %w", err)
	}
	if err := os.Chmod(s.path, 0o600); err != nil {
		listener.Close()
		return fmt.Errorf("secure control socket: %w", err)
	}
	s.listener = &peerListener{Listener: listener, uid: uint32(os.Geteuid()), require: runtime.GOOS == "linux"}
	return nil
}

func (s *Server) Serve() error {
	if s.listener == nil {
		if err := s.Listen(); err != nil {
			return err
		}
	}
	err := s.httpServer.Serve(s.listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) Shutdown(ctx context.Context) error {
	var result error
	s.closeOnce.Do(func() {
		result = s.httpServer.Shutdown(ctx)
		if s.listener != nil {
			if err := s.listener.Close(); result == nil && err != nil && !errors.Is(err, net.ErrClosed) {
				result = err
			}
		}
		if err := os.Remove(s.path); result == nil && err != nil && !errors.Is(err, os.ErrNotExist) {
			result = err
		}
	})
	return result
}

func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, _ *http.Request) {
		_ = writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /v1/tokens/mint", s.handleMint)
	mux.HandleFunc("POST /v1/tokens/delegate", s.handleDelegate)
	mux.HandleFunc("POST /v1/tokens/revoke", s.handleRevoke)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(w, r)
	})
}

func (s *Server) handleMint(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	requestID := s.nextRequestID()
	var request MintRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeControlError(w, http.StatusBadRequest)
		return
	}
	grants, ok := s.config.Roles[request.Role]
	if !ok || !validWorkloadID(request.Workload) || !s.validTTL(request.TTLSeconds) {
		writeControlError(w, http.StatusBadRequest)
		return
	}
	if err := s.recordControl(started, requestID, "mint", request.Workload, "", "", audit.DecisionAllow, 0, "authorized"); err != nil {
		writeControlError(w, http.StatusServiceUnavailable)
		return
	}
	issued, err := s.store.Mint(r.Context(), tokens.MintRequest{
		Workload: request.Workload, Audience: s.config.File.Server.Audience,
		ExpiresAt: time.Now().UTC().Add(time.Duration(request.TTLSeconds) * time.Second),
		Grants:    grants, AllowDelegation: request.AllowDelegation,
	})
	if err != nil {
		_ = s.recordControl(started, requestID, "mint", request.Workload, "", "", audit.DecisionError, http.StatusBadRequest, "failed")
		writeControlError(w, http.StatusBadRequest)
		return
	}
	if err := s.recordControl(started, requestID, "mint", request.Workload, issued.Claims.TokenID, issued.Claims.RootTokenID, audit.DecisionAllow, http.StatusCreated, "completed"); err != nil {
		s.revokeIssuedToken(issued.Claims.TokenID)
		writeControlError(w, http.StatusServiceUnavailable)
		return
	}
	if err := writeJSON(w, http.StatusCreated, tokenResponse{Bearer: issued.Bearer, Claims: issued.Claims}); err != nil {
		s.revokeIssuedToken(issued.Claims.TokenID)
	}
}

func (s *Server) handleDelegate(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	requestID := s.nextRequestID()
	var request DelegateRequest
	if err := decodeJSON(w, r, &request); err != nil || request.ParentToken == "" ||
		!validWorkloadID(request.CallerWorkload) || !validWorkloadID(request.Workload) || !s.validTTL(request.TTLSeconds) {
		writeControlError(w, http.StatusBadRequest)
		return
	}
	parent, err := s.store.Validate(r.Context(), request.ParentToken, tokens.ValidationRequest{
		Workload: request.CallerWorkload, Audience: s.config.File.Server.Audience,
	})
	if err != nil {
		writeControlError(w, http.StatusBadRequest)
		return
	}
	grants := filterGrants(parent.Grants, request.Services)
	if len(grants) == 0 {
		writeControlError(w, http.StatusBadRequest)
		return
	}
	if err := s.recordControl(started, requestID, "delegate", request.Workload, parent.TokenID, parent.RootTokenID, audit.DecisionAllow, 0, "authorized"); err != nil {
		writeControlError(w, http.StatusServiceUnavailable)
		return
	}
	issued, err := s.store.Delegate(r.Context(), request.ParentToken, tokens.DelegateRequest{
		CallerWorkload: request.CallerWorkload, Audience: s.config.File.Server.Audience,
		Workload: request.Workload, ExpiresAt: time.Now().UTC().Add(time.Duration(request.TTLSeconds) * time.Second),
		Grants: grants, AllowDelegation: request.AllowDelegation,
	})
	if err != nil {
		_ = s.recordControl(started, requestID, "delegate", request.Workload, parent.TokenID, parent.RootTokenID, audit.DecisionError, http.StatusBadRequest, "failed")
		writeControlError(w, http.StatusBadRequest)
		return
	}
	if err := s.recordControl(started, requestID, "delegate", request.Workload, issued.Claims.TokenID, issued.Claims.RootTokenID, audit.DecisionAllow, http.StatusCreated, "completed"); err != nil {
		s.revokeIssuedToken(issued.Claims.TokenID)
		writeControlError(w, http.StatusServiceUnavailable)
		return
	}
	if err := writeJSON(w, http.StatusCreated, tokenResponse{Bearer: issued.Bearer, Claims: issued.Claims}); err != nil {
		s.revokeIssuedToken(issued.Claims.TokenID)
	}
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	requestID := s.nextRequestID()
	var request RevokeRequest
	if err := decodeJSON(w, r, &request); err != nil || !validTokenID(request.TokenID) {
		writeControlError(w, http.StatusBadRequest)
		return
	}
	if err := s.recordControl(started, requestID, "revoke", "", request.TokenID, "", audit.DecisionAllow, 0, "authorized"); err != nil {
		writeControlError(w, http.StatusServiceUnavailable)
		return
	}
	if err := s.store.RevokeTokenID(r.Context(), request.TokenID); err != nil {
		_ = s.recordControl(started, requestID, "revoke", "", request.TokenID, "", audit.DecisionError, http.StatusNotFound, "failed")
		writeControlError(w, http.StatusNotFound)
		return
	}
	if err := s.recordControl(started, requestID, "revoke", "", request.TokenID, "", audit.DecisionAllow, http.StatusNoContent, "completed"); err != nil {
		writeControlError(w, http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) nextRequestID() string {
	return s.requestSeed + fmt.Sprintf("%016x", s.requestSeq.Add(1))
}

// revokeIssuedToken uses a fresh bounded context because the operation is a
// compensation for a failed response. The request context is commonly already
// canceled when a client disconnects while its bearer is being delivered.
func (s *Server) revokeIssuedToken(tokenID string) {
	ctx, cancel := context.WithTimeout(context.Background(), compensatingRevokeTimeout)
	defer cancel()
	_ = s.store.RevokeTokenID(ctx, tokenID)
}

func (s *Server) recordControl(started time.Time, requestID, operation, workload, tokenID, rootTokenID string, decision audit.Decision, status int, reason string) error {
	return s.auditor.Record(audit.Record{
		RequestID: requestID, TokenID: tokenID, RootTokenID: rootTokenID,
		RuleID: operation, Reason: reason, WorkloadID: workload, Service: "control",
		Decision: decision, Status: status, Latency: time.Since(started),
	})
}

func (s *Server) validTTL(seconds int64) bool {
	return seconds > 0 && seconds <= int64(s.maxTTL/time.Second)
}

func validTokenID(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validWorkloadID(value string) bool {
	if address, ok := strings.CutPrefix(value, "ip:"); ok {
		parsed, err := netip.ParseAddr(address)
		return err == nil && address == parsed.Unmap().String()
	}
	if digest, ok := strings.CutPrefix(value, "mtls-spki:"); ok {
		return validTokenID(digest)
	}
	return false
}

func filterGrants(parent []tokens.Grant, services []string) []tokens.Grant {
	if len(services) == 0 {
		return append([]tokens.Grant(nil), parent...)
	}
	requested := make(map[string]struct{}, len(services))
	for _, service := range services {
		if service == "" {
			return nil
		}
		requested[service] = struct{}{}
	}
	result := make([]tokens.Grant, 0, len(requested))
	for _, grant := range parent {
		if _, ok := requested[grant.Service]; ok {
			result = append(result, grant)
			delete(requested, grant.Service)
		}
	}
	if len(requested) != 0 {
		return nil
	}
	return result
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return ErrControlRequest
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxControlBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrControlRequest
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ErrControlRequest
	}
	return nil
}

func writeControlError(w http.ResponseWriter, status int) {
	_ = writeJSON(w, status, errorResponse{Error: "request rejected"})
}

func writeJSON(w http.ResponseWriter, status int, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		status = http.StatusInternalServerError
		encoded = []byte(`{"error":"internal error"}`)
	}
	encoded = append(encoded, '\n')
	owned := encoded
	defer clear(owned)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(encoded)))
	w.WriteHeader(status)
	for len(encoded) > 0 {
		written, writeErr := w.Write(encoded)
		if writeErr != nil {
			return writeErr
		}
		if written <= 0 || written > len(encoded) {
			return io.ErrShortWrite
		}
		encoded = encoded[written:]
	}
	return nil
}

func prepareSocketPath(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("control socket path must be absolute")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create control directory: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&0o077 != 0 || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("control directory must be a non-symlink 0700 directory")
	}
	info, err = os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		return errors.New("refusing to replace non-socket control path")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid != uint32(os.Geteuid()) {
		return errors.New("refusing to replace another user's socket")
	}
	if connection, dialErr := net.DialTimeout("unix", path, 250*time.Millisecond); dialErr == nil {
		_ = connection.Close()
		return errors.New("control socket is already active")
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale control socket: %w", err)
	}
	return nil
}

type peerListener struct {
	net.Listener
	uid     uint32
	require bool
}

func (l *peerListener) Accept() (net.Conn, error) {
	for {
		connection, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		uid, ok := peerUID(connection)
		if (!ok && l.require) || ok && uid != l.uid {
			_ = connection.Close()
			continue
		}
		return connection, nil
	}
}
