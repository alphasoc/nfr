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

	if exist, err := FileExists(realFile); err != nil {
		t.Fatalf("FileExists(%q) unexpected error.", realFile)

	} else if exist == true {
		t.Fatalf("FileExists(%q) unexpected true return.", realFile)
	}

	if exist, err := FileExists(nonExistFile); err != nil {
		t.Fatalf("FileExists(%q) unexpected error.", nonExistFile)
	} else if exist == true {
		t.Fatalf("FileExists(%q) unexpected true return.", nonExistFile)
	}

	if exist, err := FileExists(nonExistFileDir); err != nil {
		t.Fatalf("FileExists(%q) unexpected error.", nonExistFileDir)
	} else if exist == true {
		t.Fatalf("FileExists(%q) unexpected true return.", nonExistFileDir)
	}

	if exist, err := FileExists(realFileDir); err != nil {
		t.Fatalf("FileExists(%q) unexpected error.", realFileDir)
	} else if exist == false {
		t.Fatalf("FileExists(%q) unexpected false return.", realFileDir)
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

	if err := CreateDirForFile(realFile); err != nil {
		t.Fatalf("FileExists(%q) unexpected false return.", realFile)
	}

	if err := CreateDirForFile(nonExistFile); err != nil {
		t.Fatalf("FileExists(%q) unexpected false return.", nonExistFile)
	}
	defer os.Remove(nonExistFileDir)

	if exist, err := FileExists(nonExistFileDir); err != nil {
		t.Fatalf("FileExists(%q) unexpected error.", nonExistFileDir)
	} else if exist == false {
		t.Fatalf("FileExists(%q) unexpected false return after calling CreateDirForFile().", nonExistFileDir)
	}

	if exist, err := FileExists(nonExistFile); err != nil {
		t.Fatalf("FileExists(%q) unexpected error.", nonExistFileDir)
	} else if exist == true {
		os.Remove(nonExistFile)
		t.Fatalf("FileExists(%q) unexpected true return after calling CreateDirForFile()..", nonExistFile)
	}

}
