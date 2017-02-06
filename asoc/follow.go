package asoc

import (
	"io/ioutil"
	"namescore/utils"
	"os"
)

func WriteFollow(file, follow string) error {
	if utils.FileExists(file) == false {
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
