package events

import (
	"encoding/json"
	"os"

	"github.com/alphasoc/namescore/client"
)

type Logger interface {
	Log(*client.EventsResponse) error
}

type JSONFileLogger struct {
	f *os.File
}

func NewJSONFileLogger(file string) (*JSONFileLogger, error) {
	switch file {
	case "stdout":
		return &JSONFileLogger{os.Stdout}, nil
	case "stderr":
		return &JSONFileLogger{os.Stderr}, nil
	default:
		f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			return nil, err
		}
		return &JSONFileLogger{f}, nil
	}
}

func (l *JSONFileLogger) Log(e *client.EventsResponse) error {
	// do not log if there is no events
	if len(e.Events) == 0 {
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

// Close closes the File. It returns an error, if any.
func (l *JSONFileLogger) Close() error {
	return l.f.Close()
}
