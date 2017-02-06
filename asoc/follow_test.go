package asoc

import "testing"
import "os"
import "namescore/utils"

func TestFollowNonExist(t *testing.T) {
	var (
		followFile = "/tmp/namescore_follow.test"
	)

	if f := ReadFollow(followFile); f != "" {
		t.Fatalf("ReadFollow(%q), expected empty string, got %q", followFile, f)
	}
}

func TestFollow(t *testing.T) {
	var (
		followFile    = "/tmp/namescore_follow.test"
		followFileTmp = "/tmp/namescore_follow.test.tmp"
		follow        = "content_of_follow"
	)

	defer os.Remove(followFile)
	if err := WriteFollow(followFile, follow); err != nil {
		t.Fatalf("WriteFollow(%q, %q) failed: %v", followFile, follow, err)
	}

	if f := ReadFollow(followFile); f != follow {
		t.Fatalf("ReadFollow(%q), expected %q, got %q", followFile, follow, f)
	}

	if utils.FileExists(followFileTmp) {
		os.Remove(followFileTmp)
		t.Fatalf("Temporary file %q shouldn't exist", followFileTmp)
	}
}
