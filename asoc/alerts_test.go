package asoc

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

func TestContent(t *testing.T) {
	var (
		linesWrite  = []string{"one", "two", "three"}
		linesAppend = []string{"four", "five", "six"}
	)

	file, err := ioutil.TempFile("", "namescore_alert")
	if err != nil {
		t.Fatalf("TempFile(), unexpected error %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close(%q), unexpected error %v", file.Name(), err)
	}

	defer func() {
		if err := os.Remove(file.Name()); err != nil {
			t.Fatalf("Remove(%q), unexpected error %v", file, err)
		}
	}()

	if err := StoreAlerts(file.Name(), linesWrite); err != nil {
		t.Fatalf("Open(%q), unexpected error %v", file, err)
	}

	if err := compareFileContent(file.Name(), linesWrite); err != nil {
		t.Fatalf("Unexpected file %q content err=%v", file.Name(), err)
	}

	if err := StoreAlerts(file.Name(), linesAppend); err != nil {
		t.Fatalf("Open(%q), unexpected error %v", file.Name(), err)
	}

	if err := compareFileContent(file.Name(), append(linesWrite, linesAppend...)); err != nil {
		t.Fatalf("Unexpected file %q content err=%v", file.Name(), err)
	}

}

func compareFileContent(file string, content []string) (err error) {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer func() {
		if errClose := f.Close(); errClose != nil && err == nil {
			err = errClose
		}
	}()

	s := bufio.NewScanner(f)
	var i int

	for s.Scan() {
		line := s.Text()
		if line != content[i] {
			return fmt.Errorf("Line: %d File: %q != Expected: %q", i, line, content[i])
		}
		i++
	}
	return err
}
