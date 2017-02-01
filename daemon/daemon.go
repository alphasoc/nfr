package daemon

import "net"
import "os"

// LockSocket guarantees that only one instance of process is running.
// Also allows to check whether proces is already launched.
// It uses anonymous linux socket domain. See: man (7) unix
func LockSocket() error {
	_, err := net.Listen("unix", "@namescore")
	if err != nil {
		return err
	}
	return nil
}

func IsRoot() bool {
	return os.Getuid() == 0
}
