//go:build !linux

package control

import "net"

// Socket-directory and socket modes remain enforced on platforms where the
// standard library does not expose peer credentials.
func peerUID(net.Conn) (uint32, bool) { return 0, false }
