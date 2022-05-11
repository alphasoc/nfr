// +build !windows,!nacl,!plan9

package alerts

import (
	"fmt"
	"log/syslog"
	"net"
)

// SyslogWriter implements Writer interface and write
// api alerts to syslog server.
type SyslogWriter struct {
	w     *syslog.Writer
	f     Formatter
	proto string
	raddr string
}

// NewSyslogWriter creates new syslog writer.
func NewSyslogWriter(proto, raddr string, format Formatter) (*SyslogWriter, error) {
	if proto == "" {
		proto = "tcp"
	}
	// NOTE: The actual syslog writer instance, w, is nil until Connect().
	w := SyslogWriter{w: nil, f: format, proto: proto, raddr: raddr}
	if err := w.Connect(); err != nil {
		return nil, err
	}
	return &w, nil
}

// writeAndRetry will attempt to log s to the syslog instance.  On a network error,
// reconnect and logging will be attempted.  Returns error.
func (w *SyslogWriter) writeAndRetry(s string) error {
	// We _appear_ to have an active syslog connection.  Let's try logging.
	if w.w != nil {
		// If we encounter a network error, try a reconnect.
		if err := w.w.Alert(s); err == nil {
			// Success!
			return nil
		} else if _, ok := err.(net.Error); !ok {
			return err
		} else {
			// We have a network error.  Keep going.
		}
	}
	// Either w.w == nil, or Alert() attempt yielded a network error.  Try a reconnect
	// and attempt another Alert().
	if err := w.Connect(); err != nil {
		return err
	}
	return w.w.Alert(s)
}

// Write writes alert response to the syslog input.
func (w *SyslogWriter) Write(event *Event) error {
	b, err := w.f.Format(event)
	if err != nil {
		return err
	}
	for n := range b {
		if err := w.writeAndRetry(string(b[n])); err != nil {
			return err
		}
	}
	return nil
}

// Connect creates syslog server connection, assigning it in w and returns an error.
func (w *SyslogWriter) Connect() error {
	// Close out previous connection; disregard error.
	w.Close()
	sw, err := syslog.Dial(w.proto, w.raddr, logalert, tag)
	if err != nil {
		return fmt.Errorf("connect to syslog input failed: %v", err)
	}
	// Set our syslog writer.
	w.w = sw
	return nil
}

// Close closes a connecion to the syslog server.
func (w *SyslogWriter) Close() error {
	if w.w != nil {
		return w.w.Close()
	}
	return nil
}
