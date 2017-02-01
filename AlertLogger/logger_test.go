package AlertLogger

import "testing"
import "os"
import "bufio"

func TestOpenEmptyPath(t *testing.T) {
	l, err := Open("")
	if err == nil {
		t.Errorf("expected error when opening empty path")
	}

	if l != nil {
		t.Errorf("instance of logger returned when opening empty path")
	}
}

func TestNoExistFileAppend(t *testing.T) {
	file := "/tmp/namescore_test_logger"
	line1 := "line1"
	line2 := "line2"
	defer os.Remove(file)

	err := writeToFile(file, line1)
	if err != nil {
		t.Errorf("Failed to write %q to file %q, err=%v", line1, file, err)
	}

	if false == isLineInFile(file, line1) {
		t.Errorf("Line %q was not found in file %q", line1, file)
	}

	err = writeToFile(file, line2)
	if err != nil {
		t.Errorf("Failed to write %q to file %q, err=%v", line2, file, err)
	}

	if false == isLineInFile(file, line1) {
		t.Errorf("Line %q was not found in file %q after appending", line1, file)
	}

	if false == isLineInFile(file, line2) {
		t.Errorf("Line %q was not found in file %q after appending", line2, file)
	}
}

func writeToFile(path, line string) (err error) {
	l, oerr := Open(path)
	if oerr != nil {
		return oerr
	}

	defer func() {
		if cerr := l.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	l.Write(line)
	return nil
}

func isLineInFile(file, line string) bool {
	f, err := os.Open(file)
	if err != nil {
		return false
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		read := s.Text()
		if read == line {
			return true
		}
	}
	return false
}
