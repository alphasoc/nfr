package alerts

import (
	"encoding/json"
	"fmt"
	"log/syslog"
)

// SyslogWriter implements Writer interface and write
// api alerts to syslog server.
type SyslogWriter struct {
	w *syslog.Writer
}

// NewSyslogWriter creates new syslog writer.
func NewSyslogWriter(raddr string) (*SyslogWriter, error) {
	w, err := syslog.Dial("tcp", raddr, logalert, tag)
	if err != nil {
		return nil, fmt.Errorf("connect to syslog input failed: %s", err)
	}

	return &SyslogWriter{w: w}, nil
}

// Write writes alert response to the syslog input.
func (w *SyslogWriter) Write(alert *Alert) error {
	b, err := json.Marshal(alert)
	if err != nil {
		return err
	}

	return w.w.Alert(string(b))
}

// Close closes a connecion to the syslog server.
func (w *SyslogWriter) Close() error {
	return w.w.Close()
}
