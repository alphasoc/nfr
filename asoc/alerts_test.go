package asoc

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
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

func compareFileContent(file string, content []string) error {
	read, err := ioutil.ReadFile(file)
	if err != nil {
		return fmt.Errorf("ReadFile(%q) unexpected err=%v", file, err)
	}

	if !bytes.Equal(read, []byte(strings.Join(content, "\n")+"\n")) {
		return fmt.Errorf("%q content is invalid", file)
	}
	return nil
}
