//go:build linux

package control

import (
	"net"
	"syscall"
)

func peerUID(connection net.Conn) (uint32, bool) {
	unix, ok := connection.(*net.UnixConn)
	if !ok {
		return 0, false
	}
	raw, err := unix.SyscallConn()
	if err != nil {
		return 0, false
	}
	var uid uint32
	var controlErr error
	err = raw.Control(func(fd uintptr) {
		credential, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil {
			controlErr = err
			return
		}
		uid = credential.Uid
	})
	return uid, err == nil && controlErr == nil
}
