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
	// sw.w set in Connect()
	sw := SyslogWriter{f: format, proto: proto, raddr: raddr}
	if err := sw.Connect(); err != nil {
		return nil, err
	}
	return &sw, nil
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
func (w *SyslogWriter) Connect() error {
	newW, err := syslog.Dial(w.proto, w.raddr, logalert, tag)
	if err != nil {
		var addr net.Addr
		// Disregard the error; it's a best effort case for logging.
		if w.proto == "tcp" {
			addr, _ = net.ResolveTCPAddr(w.proto, w.raddr)
		} else if w.proto == "udp" {
			addr, _ = net.ResolveUDPAddr(w.proto, w.raddr)
		} else {
			// Leave addr unitialized.
		}
		return &net.OpError{
			Op:     "dial",
			Net:    w.proto,
			Source: nil,
			Addr:   addr,
			Err:    fmt.Errorf("connect to syslog input failed: %v", err)}
	}
	w.w = newW
	return nil
}

// Close closes a connecion to the syslog server.
func (w *SyslogWriter) Close() error {
	if w.w != nil {
		return w.w.Close()
	}
	return nil
}
