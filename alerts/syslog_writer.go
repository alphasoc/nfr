// +build !windows,!nacl,!plan9

package alerts

import (
	"fmt"
	"log/syslog"
)

// SyslogWriter implements Writer interface and write
// api alerts to syslog server.
type SyslogWriter struct {
	w *syslog.Writer
	f Formatter
}

// NewSyslogWriter creates new syslog writer.
func NewSyslogWriter(proto, raddr string, format Formatter) (*SyslogWriter, error) {
	if proto == "" {
		proto = "tcp"
	}

	w, err := syslog.Dial(proto, raddr, logalert, tag)
	if err != nil {
		return nil, fmt.Errorf("connect to syslog input failed: %s", err)
	}

	return &SyslogWriter{w: w, f: format}, nil
}

// Write writes alert response to the syslog input.
func (w *SyslogWriter) Write(event *Event) error {
	bs, err := w.f.Format(event)
	if err != nil {
		return err
	}

	for n := range bs {
		if err := w.w.Alert(string(bs[n])); err != nil {
			return err
		}
	}

	return nil
}

// Close closes a connecion to the syslog server.
func (w *SyslogWriter) Close() error {
	return w.w.Close()
}
