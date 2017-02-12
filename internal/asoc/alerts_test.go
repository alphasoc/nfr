package asoc

import (
	"bufio"
	"fmt"
	"os"
	"testing"

	"github.com/alphasoc/namescore/internal/utils"
)

func TestNoExistFile(t *testing.T) {
	file := "/tmp/namescore_test_alerts"

	defer os.Remove(file)
	store, err := OpenAlerts(file)

	if err != nil {
		t.Fatalf("OpenAlerts(%q), unexpected error %v", file, err)
	}

	if store == nil {
		t.Fatalf("Open(%q), unexpected AlertStore=nil", file)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close(), unexpected error %v", err)
	}

	if exist, err := utils.FileExists(file); err != nil {
		t.Fatalf("FileExists(%q), unexpected error %v", file, err)
	} else if exist == false {
		t.Fatalf("File %q was not created.", file)
	}
}

func TestContent(t *testing.T) {
	var (
		file        = "/tmp/namescore_test_alerts"
		linesWrite  = []string{"one", "two", "three"}
		linesAppend = []string{"four", "five", "six"}
	)
	defer os.Remove(file)
	store, err := OpenAlerts(file)
	if err != nil {
		t.Fatalf("Open(%q), unexpected error %v", file, err)
	}

	store.Write(linesWrite)
	if err := store.Close(); err != nil {
		t.Fatalf("Close(), unexpected error %v", err)
	}

	if err := compareFileContent(file, linesWrite); err != nil {
		t.Fatalf("Unexpected file content err=%v", err)
	}

	store, err = OpenAlerts(file)
	if err != nil {
		t.Fatalf("Open(%q), unexpected error %v", file, err)
	}

	store.Write(linesAppend)
	if err := store.Close(); err != nil {
		t.Fatalf("Close(), unexpected error %v", err)
	}

	if err := compareFileContent(file, append(linesWrite, linesAppend...)); err != nil {
		t.Fatalf("Unexpected file content err=%v", err)
	}

}

func compareFileContent(file string, content []string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	var i int

	for s.Scan() {
		line := s.Text()
		if line != content[i] {
			return fmt.Errorf("Line: %d File: %q != Expected: %q", i, line, content[i])
		}
		i++
	}
	return nil
}
