package runner

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestLimitedListenerDoesNotAcceptBeyondCap(t *testing.T) {
	underlying := newChannelListener()
	listener := newLimitedListener(underlying, 1)
	firstServer, firstClient := net.Pipe()
	underlying.connections <- firstServer
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer firstClient.Close()

	secondServer, secondClient := net.Pipe()
	defer secondClient.Close()
	underlying.connections <- secondServer
	result := make(chan net.Conn, 1)
	go func() {
		connection, _ := listener.Accept()
		result <- connection
	}()
	select {
	case connection := <-result:
		_ = connection.Close()
		t.Fatal("listener exceeded its connection cap")
	case <-time.After(20 * time.Millisecond):
	}
	if err := accepted.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case connection := <-result:
		if connection == nil {
			t.Fatal("second accept failed")
		}
		_ = connection.Close()
	case <-time.After(time.Second):
		t.Fatal("connection permit was not released")
	}
}

type channelListener struct {
	connections chan net.Conn
	closed      chan struct{}
}

func newChannelListener() *channelListener {
	return &channelListener{connections: make(chan net.Conn, 2), closed: make(chan struct{})}
}

func (listener *channelListener) Accept() (net.Conn, error) {
	select {
	case connection := <-listener.connections:
		return connection, nil
	case <-listener.closed:
		return nil, net.ErrClosed
	}
}

func (listener *channelListener) Close() error {
	select {
	case <-listener.closed:
		return errors.New("already closed")
	default:
		close(listener.closed)
		return nil
	}
}

func (listener *channelListener) Addr() net.Addr { return channelAddress("runner") }

type channelAddress string

func (address channelAddress) Network() string { return "test" }
func (address channelAddress) String() string  { return string(address) }
