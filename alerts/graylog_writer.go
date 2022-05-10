package alerts

import (
	"fmt"
	"net"
	"net/url"
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
	g         *gelf.Gelf
	hostname  string
	level     int
	uriScheme string
	uriHost   string
}

// NewGraylogWriter creates new graylog writer.
func NewGraylogWriter(uri string, level int) (*GraylogWriter, error) {
	// ie. uri: tcp://localhost:12201 -> uriSchem==tcp, uriHost==localhost;12201
	parsedURI, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	// Check uri validity.
	if _, _, err = net.SplitHostPort(parsedURI.Host); err != nil {
		return nil, fmt.Errorf(
			"failed initializing graylog output: invalid uri '%v': %v",
			parsedURI.Host,
			err)
	}
	if parsedURI.Scheme != "udp" && parsedURI.Scheme != "tcp" {
		return nil, fmt.Errorf(
			"failed initializing graylog output: unsupported scheme: %s",
			parsedURI.Scheme)
	}
	hostname, _ := os.Hostname()
	// NOTE: The actual graylog/gelf writer instance, g, is nil until Connect().
	w := GraylogWriter{
		g:         nil,
		hostname:  hostname,
		level:     level,
		uriScheme: parsedURI.Scheme,
		uriHost:   parsedURI.Host,
	}
	if err := w.Connect(); err != nil {
		return nil, err
	}
	return &w, nil
}

// writeAndRetry will attempt to send m to the graylog instance.  On a network error,
// reconnect and re-send will be attempted.  Returns error.
func (w *GraylogWriter) writeAndRetry(m *gelf.Message) error {
	// We _appear_ to have an active graylog connection.  Let's try sending.
	if w.g != nil {
		// If we encounter a network error, try a reconnect.
		if err := w.g.Send(m); err == nil {
			// Success!
			return nil
		} else if _, ok := err.(net.Error); !ok {
			return err
		} else {
			// We have a network error.  Keep going.
		}
	}
	// Either w.g == nil, or Send() attempt yielded a network error.  Try a reconnect
	// and attempt another Send().
	if err := w.Connect(); err != nil {
		return err
	}
	return w.g.Send(m)
}

// Write writes alert response to graylog server.
func (w *GraylogWriter) Write(event *Event) error {
	for tid, threat := range event.Threats {
		m := gelf.Message{
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
		if err := w.writeAndRetry(&m); err != nil {
			return err
		}
	}
	return nil

}

// Connect creates a new and connected gelf client, assigning it to w.
// An error is returned.
func (w *GraylogWriter) Connect() error {
	// Be sure to disconnect the old client; disregard the error.
	w.Close()
	// Create a new Gelf client.
	g, err := gelf.NewConnected(w.uriScheme, w.uriHost)
	if err != nil {
		return fmt.Errorf("connect to graylog input failed: %v", err)
	}
	// Set our gelf client.
	w.g = g
	return nil
}

// Close closes a connecion with the graylog server.
func (w *GraylogWriter) Close() error {
	if w.g != nil {
		return w.g.Close()
	}
	return nil
}
