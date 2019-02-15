// +build !windows,!nacl,!plan9

package alerts

import (
	"fmt"
	"log/syslog"
	"strings"

	"github.com/alphasoc/nfr/leef"
	"github.com/alphasoc/nfr/version"
)

const (
	logalert syslog.Priority = 14
	tag                      = "NFR"
)

// QRadarWriter implements Writer interface and write
// api alerts to syslog server.
type QRadarWriter struct {
	w *syslog.Writer
}

// NewQRadarWriter creates new syslog writer.
func NewQRadarWriter(raddr string) (*QRadarWriter, error) {
	w, err := syslog.Dial("tcp", raddr, logalert, tag)
	if err != nil {
		return nil, fmt.Errorf("connect to qradar syslog input failed: %s", err)
	}

	return &QRadarWriter{w: w}, nil
}

// Write writes alert response to the qradar syslog input.
func (w *QRadarWriter) Write(event *Event) error {
	for tid, threat := range event.Threats {
		e := leef.NewEvent()
		e.SetHeader("AlphaSOC", tag, strings.TrimPrefix(version.Version, "v"), tid)

		e.SetSevAttr(threat.Severity * 2)
		if threat.Policy {
			e.SetPolicyAttr("1")
		} else {
			e.SetPolicyAttr("0")
		}
		e.SetAttr("flags", strings.Join(event.Flags, ","))
		e.SetAttr("description", threat.Description)

		e.SetDevTimeFormatAttr("MMM dd yyyy HH:mm:ss")
		e.SetDevTimeAttr(event.Timestamp.Format("Jan 02 2006 15:04:05"))
		e.SetProtoAttr(event.Proto)
		e.SetSrcAttr(event.SrcIP)
		e.SetSrcAttr(event.SrcIP)
		e.SetSrcPortAttr(int(event.SrcPort))
		e.SetDstAttr(event.DestIP)
		e.SetDstPortAttr(int(event.DestPort))
		e.SetSrcBytesAttr(int(event.BytesIn))
		e.SetDstBytesAttr(int(event.BytesOut))
		e.SetAttr("query", event.Query)
		e.SetAttr("recordType", event.QueryType)

		if err := w.w.Alert(e.String()); err != nil {
			return err
		}
	}
	return nil
}

// Close closes a connecion to the syslog server.
func (w *QRadarWriter) Close() error {
	return w.w.Close()
}
