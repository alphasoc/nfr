package utils

import "net"

// LockSocket guarantees that only one instance of process is running.
// Also allows to check whether proces is already launched.
// It uses anonymous linux socket domain. See: man (7) unix
func LockSocket() (*net.UnixListener, error) {
	return net.ListenUnix("unix", &net.UnixAddr{"@/tmp/namescore", "unix"})
}
