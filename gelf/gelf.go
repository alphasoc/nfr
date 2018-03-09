package gelf

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"

	"github.com/Jeffail/gabs"
)

// Gelf client.
type Gelf struct {
	conn net.Conn
}

// Message for graylog server.
type Message struct {
	Version      string `json:"version"`
	Host         string `json:"host"`
	ShortMessage string `json:"short_message"`
	FullMessage  string `json:"full_message"`
	Timestamp    int64  `json:"timestamp"`
	Level        int    `json:"level"`

	Extra map[string]interface{} `json:"-"`
}

// New returns GELF client.
func New(uri string) (*Gelf, error) {
	parsedURI, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	if _, _, err = net.SplitHostPort(parsedURI.Host); err != nil {
		return nil, err
	}

	if parsedURI.Scheme != "udp" && parsedURI.Scheme != "tcp" {
		return nil, fmt.Errorf("unsupported scheme %s", parsedURI.Scheme)
	}

	conn, err := net.Dial(parsedURI.Scheme, parsedURI.Host)
	if err != nil {
		return nil, err

	}
	return &Gelf{conn: conn}, nil
}

// Close the connection to the server.
func (g *Gelf) Close() error {
	return g.conn.Close()
}

// Send message to the server.
func (g *Gelf) Send(m *Message) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}

	c, err := gabs.ParseJSON(b)
	if err != nil {
		return err
	}

	for k, v := range m.Extra {
		_, err = c.Set(v, fmt.Sprintf("_%s", k))
		if err != nil {
			return err
		}
	}

	_, err = g.conn.Write(append(c.Bytes(), '\n', 0))
	return err
}
