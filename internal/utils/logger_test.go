package utils

import "testing"

func TestLoggerNilSyslog(t *testing.T) {
	l := Logger{}
	l.Close()

	l.Info("test")
	l.Warning("test")
}
