package utils

import "testing"
import "os"

func TestDirectoryCreate(t *testing.T) {
	var (
		realFile = "/tmp/namescore_test.file"
	)

	if exist, err := FileExists(realFile); err != nil {
		t.Fatalf("FileExists(%q) unexpected error.", realFile)
	} else if exist {
		t.Fatalf("FileExists(%q) unexpected true return.", realFile)
	}

	f, errf := os.Create(realFile)
	if errf != nil {
		t.Fatalf("Create(%q) unexpected error %v", realFile, errf)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Fatalf("Close(%q) unexpected error=%v", realFile, err)
		}
	}()
	defer func() {
		if err := os.Remove(realFile); err != nil {
			t.Fatalf("Remove(%q) unexpected error=%v", realFile, err)
		}
	}()

	if exist, err := FileExists(realFile); err != nil {
		t.Fatalf("FileExists(%q) unexpected error.", realFile)

	} else if !exist {
		t.Fatalf("FileExists(%q) unexpected false return.", realFile)
	}
}
