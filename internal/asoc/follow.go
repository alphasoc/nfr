package asoc

import (
	"io/ioutil"
	"os"

	"github.com/alphasoc/namescore/internal/utils"
)

func WriteFollow(file, follow string) error {
	if exist, err := utils.FileExists(file); err != nil {
		return err
	} else if exist == false {
		if err := utils.CreateDirForFile(file); err != nil {
			return err
		}
	}

	var (
		tmpFile = file + ".tmp"
	)

	if err := ioutil.WriteFile(tmpFile, []byte(follow), 0660); err != nil {
		return err
	}

	return os.Rename(tmpFile, file)
}

func ReadFollow(path string) string {
	follow, err := ioutil.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(follow)
}
