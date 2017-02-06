package utils

import "testing"
import "os"

func TestDirectoryCreate(t *testing.T) {
	var (
		realFile        = "/tmp/namescore_test.file"
		realFileDir     = "/tmp/"
		nonExistFile    = "/tmp/namescore_test_dir/file.file"
		nonExistFileDir = "/tmp/namescore_test_dir/"
	)

	if FileExists(realFile) {
		t.Fatalf("FileExists(%q) unexpected true return.", realFile)
	}

	if FileExists(nonExistFile) {
		t.Fatalf("FileExists(%q) unexpected true return.", nonExistFile)
	}

	if FileExists(nonExistFileDir) {
		t.Fatalf("FileExists(%q) unexpected true return.", nonExistFileDir)
	}

	if FileExists(realFileDir) == false {
		t.Fatalf("FileExists(%q) unexpected false return.", realFileDir)
	}

	f, errf := os.Create(realFile)
	if errf != nil {
		t.Fatalf("Create(%q) unexpected error %v", realFile, errf)
	}
	defer f.Close()
	defer os.Remove(realFile)

	if FileExists(realFile) == false {
		t.Fatalf("FileExists(%q) unexpected false return.", realFile)
	}

	if err := CreateDirForFile(realFile); err != nil {
		t.Fatalf("FileExists(%q) unexpected false return.", realFile)
	}

	if err := CreateDirForFile(nonExistFile); err != nil {
		t.Fatalf("FileExists(%q) unexpected false return.", nonExistFile)
	}
	defer os.Remove(nonExistFileDir)

	if FileExists(nonExistFileDir) == false {
		t.Fatalf("FileExists(%q) unexpected false return after calling CreateDirForFile().", nonExistFileDir)
	}

	if FileExists(nonExistFile) {
		os.Remove(nonExistFile)
		t.Fatalf("FileExists(%q) unexpected true return after calling CreateDirForFile()..", nonExistFile)
	}

}
