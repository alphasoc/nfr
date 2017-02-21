package asoc

import (
	"bufio"
	"os"
)

// StoreAlerts appends alerts collected from Events api call
// If alerts are stored for a first time, file in path is created.
func StoreAlerts(path string, alerts []string) (err error) {
	file, errOpen := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if errOpen != nil {
		return errOpen
	}
	defer func() {
		if errClose := file.Close(); errClose != nil {
			err = errClose
		}
	}()

	buf := bufio.NewWriter(file)
	for _, line := range alerts {
		if _, errWriteS := buf.WriteString(line); errWriteS != nil {
			return errWriteS
		}
		if errWriteB := buf.WriteByte('\n'); errWriteB != nil {
			return errWriteB
		}
	}

	if errFlush := buf.Flush(); errFlush != nil {
		return errFlush
	}
	return err
}
