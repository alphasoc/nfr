package asoc

import (
	"bufio"
	"fmt"
	"os"
	"testing"
)

func TestContent(t *testing.T) {
	var (
		file        = "/tmp/namescore_test_alerts"
		linesWrite  = []string{"one", "two", "three"}
		linesAppend = []string{"four", "five", "six"}
	)
	defer os.Remove(file)

	if err := StoreAlerts(file, linesWrite); err != nil {
		t.Fatalf("Open(%q), unexpected error %v", file, err)
	}

	if err := compareFileContent(file, linesWrite); err != nil {
		t.Fatalf("Unexpected file content err=%v", err)
	}

	if err := StoreAlerts(file, linesAppend); err != nil {
		t.Fatalf("Open(%q), unexpected error %v", file, err)
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
