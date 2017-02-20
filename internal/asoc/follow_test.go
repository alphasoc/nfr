package asoc

import "testing"
import "os"
import "github.com/alphasoc/namescore/internal/utils"
import "io/ioutil"
import "bytes"

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

	if exist, err := utils.FileExists(followFileTmp); err != nil {
		t.Fatalf("FileExists(%q), unexpected error=%v", followFileTmp, err)
	} else if exist == true {
		os.Remove(followFileTmp)
		t.Fatalf("Temporary file %q shouldn't exist", followFileTmp)
	}
}

func TestFollowOverride(t *testing.T) {
	var (
		followFile      = "/tmp/namescore_follow.test"
		content         = "content_of_follow"
		contentOverride = "overridden_follow"
	)

	defer os.Remove(followFile)

	if err := WriteFollow(followFile, content); err != nil {
		t.Fatalf("WriteFollow(%q, %q) failed: %v", followFile, content, err)
	}

	if c, err := ioutil.ReadFile(followFile); err != nil {
		t.Fatalf("ReadFile(%q) enexpected error=%v", followFile, err)
	} else if bytes.Compare([]byte(content), c) != 0 {
		t.Fatalf("%q file content mismatch %s != %s", followFile, content, c)
	}

	if err := WriteFollow(followFile, contentOverride); err != nil {
		t.Fatalf("WriteFollow(%q, %q) failed: %v", followFile, contentOverride, err)
	}

	if c, err := ioutil.ReadFile(followFile); err != nil {
		t.Fatalf("ReadFile(%q) enexpected error=%v", followFile, err)
	} else if bytes.Compare([]byte(contentOverride), c) != 0 {
		t.Fatalf("%q file content mismatch %s != %s", followFile, contentOverride, c)
	}

}