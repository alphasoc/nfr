package events

import (
	"encoding/json"
	"os"

	"github.com/alphasoc/namescore/client"
	"github.com/alphasoc/namescore/utils"
)

type Logger interface {
	Log(*client.EventsResponse) error
}

type JSONFileLogger struct {
	f *os.File
}

func NewJSONFileLogger(file string) (*JSONFileLogger, error) {
	f, err := utils.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}

	return &JSONFileLogger{f}, nil
}

func (l *JSONFileLogger) Log(e *client.EventsResponse) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}

	_, err = l.f.Write(b)
	return err
}

// Close closes the File. It returns an error, if any.
func (l *JSONFileLogger) Close() error {
	return l.f.Close()
}
