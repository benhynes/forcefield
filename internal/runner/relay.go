package runner

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Relay exposes a fixed host-side broker socket on sandbox loopback. It has no
// credentials and cannot select another destination.
type Relay struct {
	listener net.Listener
	socket   string
	closed   chan struct{}
	once     sync.Once
	workers  sync.WaitGroup
}

func NewRelay(listenAddress, brokerSocket string) (*Relay, error) {
	if err := validateRelayAddress(listenAddress); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(brokerSocket) || filepath.Clean(brokerSocket) != brokerSocket ||
		brokerSocket == "/run/forcefield" || !strings.HasPrefix(brokerSocket, "/run/forcefield/") {
		return nil, errors.New("sandbox relay broker socket must be beneath /run/forcefield")
	}
	info, err := os.Lstat(brokerSocket)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return nil, errors.New("sandbox relay broker endpoint is not a Unix socket")
	}
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return nil, fmt.Errorf("listen on sandbox relay: %w", err)
	}
	return &Relay{listener: listener, socket: brokerSocket, closed: make(chan struct{})}, nil
}

func (r *Relay) Serve() error {
	if r == nil || r.listener == nil {
		return errors.New("sandbox relay is not initialized")
	}
	for {
		connection, err := r.listener.Accept()
		if err != nil {
			select {
			case <-r.closed:
				return nil
			default:
				return fmt.Errorf("accept sandbox relay connection: %w", err)
			}
		}
		r.workers.Add(1)
		go func() {
			defer r.workers.Done()
			r.forward(connection)
		}()
	}
}

func (r *Relay) Close() error {
	if r == nil {
		return nil
	}
	var result error
	r.once.Do(func() {
		close(r.closed)
		if r.listener != nil {
			result = r.listener.Close()
		}
	})
	done := make(chan struct{})
	go func() {
		r.workers.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
	}
	return result
}

func (r *Relay) Address() string {
	if r == nil || r.listener == nil {
		return ""
	}
	return r.listener.Addr().String()
}

func (r *Relay) forward(downstream net.Conn) {
	defer downstream.Close()
	upstream, err := (&net.Dialer{Timeout: 2 * time.Second}).Dial("unix", r.socket)
	if err != nil {
		return
	}
	defer upstream.Close()
	type closeWriter interface{ CloseWrite() error }
	done := make(chan struct{}, 2)
	copyStream := func(destination, source net.Conn) {
		_, _ = io.Copy(destination, source)
		if closer, ok := destination.(closeWriter); ok {
			_ = closer.CloseWrite()
		}
		done <- struct{}{}
	}
	go copyStream(upstream, downstream)
	go copyStream(downstream, upstream)
	<-done
	_ = downstream.SetDeadline(time.Now())
	_ = upstream.SetDeadline(time.Now())
	<-done
}

func validateRelayAddress(value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil || port == "" {
		return errors.New("sandbox relay listen address must be loopback host:port")
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	address := net.ParseIP(host)
	if address == nil || !address.IsLoopback() {
		return errors.New("sandbox relay listen address must be loopback host:port")
	}
	return nil
}
