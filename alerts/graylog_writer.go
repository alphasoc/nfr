package alerts

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/alphasoc/nfr/client"
	"github.com/alphasoc/nfr/gelf"
)

// GraylogWriter implements Writer interface and write
// api alerts to graylog server.
type GraylogWriter struct {
	g        *gelf.Gelf
	level    int
	hostname string
}

// NewGraylogWriter creates new graylog writer.
func NewGraylogWriter(uri string, level int) (*GraylogWriter, error) {
	g, err := gelf.New(uri)
	if err != nil {
		return nil, fmt.Errorf("failed creating graylog writer: %s", err)
	}

	hostname, _ := os.Hostname()
	return &GraylogWriter{
		g:        g,
		level:    level,
		hostname: hostname,
	}, nil
}

// Write writes alert response to graylog server.
func (w *GraylogWriter) Write(event *Event) error {
	for tid, threat := range event.Threats {
		m := &gelf.Message{
			Version:      "1.1",
			Host:         w.hostname,
			ShortMessage: threat.Description,
			Timestamp:    time.Now().Unix(),
			Level:        w.level,
			Extra: map[string]interface{}{
				"severity":     threat.Severity,
				"policy":       strconv.FormatBool(threat.Policy),
				"flags":        strings.Join(event.Flags, ","),
				"threat":       tid,
				"engine_agent": client.DefaultUserAgent,
			},
		}

		m.Extra["original_event"] = event.Timestamp.String()
		m.Extra["src_ip"] = event.SrcIP
		m.Extra["query"] = event.Query
		m.Extra["record_type"] = event.QueryType

		m.Extra["protocol"] = event.Proto
		m.Extra["src_port"] = event.SrcPort
		m.Extra["dest_ip"] = event.DestIP
		m.Extra["dest_port"] = event.DestPort
		m.Extra["bytes_in"] = event.BytesIn
		m.Extra["bytes_out"] = event.BytesOut
		m.Extra["ja3"] = event.Ja3
		if err := w.g.Send(m); err != nil {
			return err
		}
	}
	return nil
}

func (w *GraylogWriter) Connect() error {
	return w.g.Connect()
}

// Close closes a connecion with the graylog server.
func (w *GraylogWriter) Close() error {
	return w.g.Close()
}
