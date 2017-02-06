package utils

import (
	"os"
	"path/filepath"
)

//FileExists checks whether file exists or not.
func FileExists(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}
	return true
}

// CreateDirForFile creates proper directory structure for file
// For example for file: /var/test/dir/file this function
// will create /var/test/dir directory.
func CreateDirForFile(file string) error {
	dir, _ := filepath.Split(file)
	if FileExists(dir) == false {
		return os.MkdirAll(dir, 0750)
	}
	return nil
}
