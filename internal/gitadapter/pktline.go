package gitadapter

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
)

const maxPktLineBytes = 65520

type packetKind uint8

const (
	packetData packetKind = iota
	packetFlush
	packetDelimiter
	packetResponseEnd
)

type packet struct {
	kind    packetKind
	payload []byte
}

type prefixBuffer struct {
	bytes.Buffer
	max int
}

func (b *prefixBuffer) append(value []byte) error {
	if len(value) > b.max-b.Len() {
		return ErrLimitExceeded
	}
	_, _ = b.Write(value)
	return nil
}

func readPacket(reader *bufio.Reader, prefix *prefixBuffer) (packet, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return packet{}, fmt.Errorf("%w: truncated pkt-line header", ErrInvalidProtocol)
		}
		return packet{}, fmt.Errorf("%w: read pkt-line header: %v", ErrInvalidProtocol, err)
	}
	length := 0
	for _, b := range header {
		length <<= 4
		switch {
		case b >= '0' && b <= '9':
			length += int(b - '0')
		case b >= 'a' && b <= 'f':
			length += int(b-'a') + 10
		default:
			return packet{}, fmt.Errorf("%w: non-canonical pkt-line length", ErrInvalidProtocol)
		}
	}
	if err := prefix.append(header); err != nil {
		return packet{}, err
	}
	switch length {
	case 0:
		return packet{kind: packetFlush}, nil
	case 1:
		return packet{kind: packetDelimiter}, nil
	case 2:
		return packet{kind: packetResponseEnd}, nil
	case 3:
		return packet{}, fmt.Errorf("%w: reserved pkt-line length", ErrInvalidProtocol)
	}
	if length < 4 || length > maxPktLineBytes {
		return packet{}, fmt.Errorf("%w: pkt-line length out of range", ErrInvalidProtocol)
	}
	payload := make([]byte, length-4)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return packet{}, fmt.Errorf("%w: truncated pkt-line payload", ErrInvalidProtocol)
	}
	if err := prefix.append(payload); err != nil {
		return packet{}, err
	}
	return packet{kind: packetData, payload: payload}, nil
}

func newBytesReader(value []byte) *bytes.Reader { return bytes.NewReader(value) }
