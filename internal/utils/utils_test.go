package utils

import "testing"
import "os"

func TestDirectoryCreate(t *testing.T) {
	var (
		realFile = "/tmp/namescore_test.file"
	)

	if exist, err := FileExists(realFile); err != nil {
		t.Fatalf("FileExists(%q) unexpected error.", realFile)
	} else if exist == true {
		t.Fatalf("FileExists(%q) unexpected true return.", realFile)
	}

	f, errf := os.Create(realFile)
	if errf != nil {
		t.Fatalf("Create(%q) unexpected error %v", realFile, errf)
	}
	defer f.Close()
	defer os.Remove(realFile)

	if exist, err := FileExists(realFile); err != nil {
		t.Fatalf("FileExists(%q) unexpected error.", realFile)

	} else if exist == false {
		t.Fatalf("FileExists(%q) unexpected false return.", realFile)
	}
}
