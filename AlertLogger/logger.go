package AlertLogger

import (
	"fmt"
	"os"
)

type Logger struct {
	path string
	file *os.File
}

//todo use bufio
func Open(path string) (l *Logger, err error) {
	if path == "" {
		return nil, fmt.Errorf("Logger.Open: empty path given")
	}

	l = &Logger{}

	l.file, err = os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	return l, nil
}

func (l *Logger) Close() error {
	if l.file == nil {
		return fmt.Errorf("not opened")
	}
	return nil
}

func (l *Logger) Write(alert string) {
	l.file.WriteString(alert + "\n")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	return false
}
