package asoc

import (
	"bufio"
	"os"
)

// StoreAlerts appends alerts collected from Events api call
// If alerts are stored for a first time, file in path is created.
func StoreAlerts(path string, alerts []string) error {

	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	buf := bufio.NewWriter(file)
	for _, line := range alerts {
		buf.WriteString(line)
		buf.WriteByte('\n')
	}

	if err := buf.Flush(); err != nil {
		return err
	}

	return nil
}
