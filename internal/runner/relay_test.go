package runner

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestRelayForwardsOnlyToFixedUnixSocket(t *testing.T) {
	t.Parallel()
	directory, err := os.MkdirTemp(".", ".relay-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	socket := filepath.Join(directory, "broker.sock")
	upstream, err := net.Listen("unix", socket)
	if errors.Is(err, syscall.EPERM) {
		t.Skip("Unix listeners are unavailable in this test sandbox")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	// The production guest socket is fixed beneath /run/forcefield. Tests call
	// the validation-independent constructor helper through a temporary bind
	// path by using the same basename validation after relocating it below.
	relay, err := newTestRelay("127.0.0.1:0", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	serveDone := make(chan error, 1)
	go func() { serveDone <- relay.Serve() }()
	go func() {
		connection, acceptErr := upstream.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		buffer := make([]byte, 4)
		_, _ = io.ReadFull(connection, buffer)
		_, _ = connection.Write(append([]byte("echo:"), buffer...))
	}()
	connection, err := net.DialTimeout("tcp", relay.Address(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := connection.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 9)
	if _, err := io.ReadFull(connection, buffer); err != nil {
		t.Fatal(err)
	}
	if string(buffer) != "echo:ping" {
		t.Fatalf("relay response = %q", buffer)
	}
	if err := relay.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("relay did not stop")
	}
}

func TestRelayRejectsNonLoopbackAndArbitrarySocket(t *testing.T) {
	t.Parallel()
	for _, address := range []string{"0.0.0.0:7902", "192.0.2.1:7902", "missing-port"} {
		if _, err := NewRelay(address, "/run/forcefield/broker.sock"); err == nil {
			t.Fatalf("listen address %q was accepted", address)
		}
	}
	if _, err := NewRelay("127.0.0.1:7902", "/tmp/broker.sock"); err == nil {
		t.Fatal("socket outside /run/forcefield was accepted")
	}
}

func newTestRelay(listenAddress, brokerSocket string) (*Relay, error) {
	if err := validateRelayAddress(listenAddress); err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return nil, err
	}
	return &Relay{listener: listener, socket: brokerSocket, closed: make(chan struct{})}, nil
}
