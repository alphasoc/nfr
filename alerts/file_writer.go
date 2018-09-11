package alerts

import (
	"os"
)

// JSONFileWriter implements Writer interface and writes alerts in json format.
type FileWriter struct {
	f      *os.File
	format Formatter
}

// NewJSONFileWriter creates new json file writer.
func NewFileWriter(file string, format Formatter) (*FileWriter, error) {
	switch file {
	case "stdout":
		return &FileWriter{os.Stdout, format}, nil
	case "stderr":
		return &FileWriter{os.Stderr, format}, nil
	default:
		f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			return nil, err
		}
		return &FileWriter{f, format}, nil
	}
}

// Write writes alerts response to the file in json format.
func (l *FileWriter) Write(event *Event) error {
	bs, err := l.format.Format(event)
	if err != nil {
		return err
	}

	for n := range bs {
		if _, err = l.f.Write(append(bs[n], '\n')); err != nil {
			return err
		}
	}

	return nil
}

// Close closes the file.
func (l *FileWriter) Close() error {
	return l.f.Close()
}
