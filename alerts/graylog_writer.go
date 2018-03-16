package alerts

import (
	"fmt"
	"os"
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
		return nil, fmt.Errorf("connect to graylog send input failed: %s", err)
	}

	hostname, _ := os.Hostname()
	return &GraylogWriter{
		g:        g,
		level:    level,
		hostname: hostname,
	}, nil
}

// Write writes alert response to graylog server.
func (w *GraylogWriter) Write(resp *client.AlertsResponse) error {
	// do not log if there is no alerts
	if len(resp.Alerts) == 0 {
		return nil
	}

	// send each alert as separate message.
	for _, alert := range resp.Alerts {
		severity, threat := highestThreatsSeverity(resp, alert.Threats)
		m := &gelf.Message{
			Version:      "1.1",
			Host:         w.hostname,
			ShortMessage: resp.Threats[threat].Title,
			Timestamp:    time.Now().Unix(),
			Level:        w.level,
			Extra: map[string]interface{}{
				"severity":     severity,
				"flags":        strings.Join(alert.Wisdom.Flags, ","),
				"threats":      strings.Join(alert.Threats, ","),
				"engine_agent": client.DefaultUserAgent,
			},
		}
		switch alert.EventType {
		case "dns":
			m.Extra["ts"] = alert.DNSEvent.Timestamp.String()
			m.Extra["src_ip"] = alert.DNSEvent.SrcIP
			m.Extra["query"] = alert.DNSEvent.Query
			m.Extra["qtype"] = alert.DNSEvent.QType
		case "ip":
			m.Extra["ts"] = alert.IPEvent.Timestamp.String()
			m.Extra["protocol"] = alert.IPEvent.Protocol
			m.Extra["src_ip"] = alert.IPEvent.SrcIP
			m.Extra["src_port"] = alert.IPEvent.SrcPort
			m.Extra["dest_ip"] = alert.IPEvent.DstIP
			m.Extra["dest_port"] = alert.IPEvent.DstPort
			m.Extra["bytes_in"] = alert.IPEvent.BytesIn
			m.Extra["bytes_out"] = alert.IPEvent.BytesOut
		}
		if err := w.g.Send(m); err != nil {
			return err
		}
	}
	return nil
}

// Close closes the connecion with graylog server.
func (w *GraylogWriter) Close() error {
	return w.g.Close()
}

// find theats with highest severity.
func highestThreatsSeverity(resp *client.AlertsResponse, threats []string) (int, string) {
	severity := 1
	threat := ""

	for _, t := range threats {
		if _, ok := resp.Threats[t]; ok {
			if severity < resp.Threats[t].Severity {
				severity = resp.Threats[t].Severity
				threat = t
			}
		}
	}
	return severity, threat
}
