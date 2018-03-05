package alerts

import (
	"encoding/json"
	"os"
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
		return nil, err
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}

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

	b, err := json.Marshal(resp)
	if err != nil {
		return err
	}

	return w.g.Send(&gelf.Message{
		Version:      "1.1",
		Host:         w.hostname,
		ShortMessage: "Alert about suspicious traffic from AlphaSOC",
		FullMessage:  string(b),
		Timestamp:    time.Now().Unix(),
		Level:        w.level,
	})
}

// Close closes the File. It returns an error, if any.
func (w *GraylogWriter) Close() error {
	return w.g.Close()
}
