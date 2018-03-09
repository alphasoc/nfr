package alerts

import (
	"encoding/json"
	"os"

	"github.com/alphasoc/nfr/client"
)

// JSONFileWriter implements Writer interface and writes alerts in json format.
type JSONFileWriter struct {
	f *os.File
}

// NewJSONFileWriter creates new json file writer.
func NewJSONFileWriter(file string) (*JSONFileWriter, error) {
	switch file {
	case "stdout":
		return &JSONFileWriter{os.Stdout}, nil
	case "stderr":
		return &JSONFileWriter{os.Stderr}, nil
	default:
		f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			return nil, err
		}
		return &JSONFileWriter{f}, nil
	}
}

// Write writes alerts response to the file in json format.
func (l *JSONFileWriter) Write(e *client.AlertsResponse) error {
	// do not log if there is no alerts
	if len(e.Alerts) == 0 {
		return nil
	}

	b, err := json.Marshal(e)
	if err != nil {
		return err
	}

	if _, err = l.f.Write(b); err != nil {
		return err
	}
	_, err = l.f.Write([]byte("\n"))
	return err
}

// Close closes the file.
func (l *JSONFileWriter) Close() error {
	return l.f.Close()
}
