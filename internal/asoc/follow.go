package asoc

import (
	"io/ioutil"
	"os"
)

// WriteFollow writes follow-id to file.
// It writes follow to temporary file first, then renames it.
// ( Renaming is atomic operation on linux )
func WriteFollow(file, follow string) error {
	tmpFile := file + ".tmp"
	if err := ioutil.WriteFile(tmpFile, []byte(follow), 0660); err != nil {
		return err
	}

	return os.Rename(tmpFile, file)
}

// ReadFollow returns follow ID.
// If follow ID is not set empty string is returned
func ReadFollow(path string) string {
	follow, err := ioutil.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(follow)
}
