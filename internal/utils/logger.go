package utils

import (
	"fmt"
	"log/syslog"
)

// Logger is wrapper to "log/syslog"
// The purpose of this is to avoid crashes when connecting
// to system syslog fails.
type Logger struct {
	writer *syslog.Writer
}

// Newlog returns logging handler.
func Newlog() *Logger {
	l := Logger{}
	if w, err := syslog.New(syslog.LOG_USER|syslog.LOG_ERR, "namescore"); err == nil {
		l.writer = w
	}
	return &l
}

// Close close connection to syslog.
func (l *Logger) Close() {
	if l.writer != nil {
		l.writer.Close()
	}
}

// Info prints msg to syslog with INFO severity.
func (l *Logger) Info(msg string) {
	if l.writer != nil {
		l.writer.Info(msg)
	}
}

// Warning prints msg to syslog with WARNING severity.
func (l *Logger) Warning(msg string) {
	if l.writer != nil {
		l.writer.Warning(msg)
	}
}

// Warningv prints msg with err to syslog with WARNING severity.
// It also prints msg to stdout.
func (l *Logger) Warningv(msg string, err error) {
	if l.writer != nil {
		l.writer.Warning(msg + " " + err.Error())
	}
	fmt.Println(msg)
}

// Infov prints msg with err to syslog with INFO severity.
// It also prints msg to stdout.
func (l *Logger) Infov(msg string) {
	if l.writer != nil {
		l.writer.Info(msg)
	}
	fmt.Println(msg)
}
