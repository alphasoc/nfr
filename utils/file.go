package utils

import "os"

// OpenFile uses os.OpenFile for opening file. It also
// support two special file: stdout and stderr and then returns
// os.Stdout and os.Stderr. For stdout and stderr flag and perm
// are ignored
func OpenFile(file string, flag int, perm os.FileMode) (*os.File, error) {
	if file == "stdout" {
		return os.Stdout, nil
	}
	if file == "stderr" {
		return os.Stderr, nil
	}

	return os.OpenFile(file, flag, perm)
}
