package asoc

import (
	"os"
	"strings"
)

// StoreAlerts appends alerts collected from Events api call
// If alerts are stored for a first time, file in path is created.
func StoreAlerts(path string, alerts []string) (err error) {
	if len(alerts) == 0 {
		return
	}

	file, errOpen := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if errOpen != nil {
		return errOpen
	}
	defer func() {
		if errClose := file.Close(); errClose != nil {
			err = errClose
		}
	}()

	if _, errWrite := file.WriteString(strings.Join(alerts, "\n") + "\n"); errWrite != nil {
		return errWrite
	}
	return err
}
