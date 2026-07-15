package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/benhynes/forcefield/internal/tokens"
)

type Client struct {
	http *http.Client
}

func NewClient(socketPath string) (*Client, error) {
	if err := validateClientSocket(socketPath); err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy: nil, DisableCompression: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			if err := validateClientSocket(socketPath); err != nil {
				return nil, err
			}
			connection, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", socketPath)
			if err != nil {
				return nil, err
			}
			uid, ok := peerUID(connection)
			if runtime.GOOS == "linux" && (!ok || uid != uint32(os.Geteuid())) || ok && uid != uint32(os.Geteuid()) {
				_ = connection.Close()
				return nil, ErrControlAccess
			}
			return connection, nil
		},
	}
	return &Client{http: &http.Client{Transport: transport, Timeout: 5 * time.Second}}, nil
}

func validateClientSocket(socketPath string) error {
	if socketPath == "" || !filepath.IsAbs(socketPath) {
		return errors.New("absolute control socket path is required")
	}
	directory := filepath.Dir(socketPath)
	directoryInfo, err := os.Lstat(directory)
	if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 || directoryInfo.Mode().Perm()&0o077 != 0 {
		return ErrControlAccess
	}
	if stat, ok := directoryInfo.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Geteuid()) {
		return ErrControlAccess
	}
	socketInfo, err := os.Lstat(socketPath)
	if err != nil || socketInfo.Mode()&os.ModeSymlink != 0 || socketInfo.Mode()&os.ModeSocket == 0 || socketInfo.Mode().Perm() != 0o600 {
		return ErrControlAccess
	}
	if stat, ok := socketInfo.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Geteuid()) {
		return ErrControlAccess
	}
	return nil
}

func (c *Client) Mint(ctx context.Context, request MintRequest) (tokens.IssuedToken, error) {
	var response tokenResponse
	if err := c.post(ctx, "/v1/tokens/mint", request, http.StatusCreated, &response); err != nil {
		return tokens.IssuedToken{}, err
	}
	return tokens.IssuedToken{Bearer: response.Bearer, Claims: response.Claims}, nil
}

func (c *Client) Delegate(ctx context.Context, request DelegateRequest) (tokens.IssuedToken, error) {
	var response tokenResponse
	if err := c.post(ctx, "/v1/tokens/delegate", request, http.StatusCreated, &response); err != nil {
		return tokens.IssuedToken{}, err
	}
	return tokens.IssuedToken{Bearer: response.Bearer, Claims: response.Claims}, nil
}

func (c *Client) Revoke(ctx context.Context, tokenID string) error {
	return c.post(ctx, "/v1/tokens/revoke", RevokeRequest{TokenID: tokenID}, http.StatusNoContent, nil)
}

func (c *Client) post(ctx context.Context, path string, request any, expected int, destination any) error {
	encoded, err := json.Marshal(request)
	if err != nil {
		return ErrControlRequest
	}
	defer clear(encoded)
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix"+path, bytes.NewReader(encoded))
	if err != nil {
		return ErrControlRequest
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(httpRequest)
	if err != nil {
		return fmt.Errorf("control request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != expected {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxControlBody))
		return ErrControlRequest
	}
	if destination == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxControlBody))
		return nil
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxControlBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrControlRequest
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrControlRequest
	}
	return nil
}
