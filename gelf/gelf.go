package gelf

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"

	"github.com/Jeffail/gabs"
)

// Gelf client.
type Gelf struct {
	// URI (ie tcp://127.0.0.1:12201) will get parsed into scheme and host.
	uriScheme string // ie. scheme == tcp
	uriHost   string // ie. 127.0.0.1:12201
	conn      net.Conn
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

	g := Gelf{conn: nil, uriScheme: parsedURI.Scheme, uriHost: parsedURI.Host}
	if err := g.Connect(); err != nil {
		return nil, err
	}
	return &g, nil
}

// Close the connection to the server.
func (g *Gelf) Close() error {
	if g.conn != nil {
		return g.conn.Close()
	}
	return nil
}

// Connect dials the graylog services, stores the connection instance and returns an error.
func (g *Gelf) Connect() error {
	var err error
	g.conn, err = net.Dial(g.uriScheme, g.uriHost)
	return err
}

// Send message to the server.
func (g *Gelf) Send(m *Message) error {
	if g.conn == nil {
		var addr net.Addr
		// Disregard the error; it's a best effort case for logging.
		if g.uriScheme == "tcp" {
			addr, _ = net.ResolveTCPAddr(g.uriScheme, g.uriHost)
		} else if g.uriScheme == "udp" {
			addr, _ = net.ResolveUDPAddr(g.uriScheme, g.uriHost)
		} else {
			// Leave addr unitialized.
		}
		return &net.OpError{
			Op:     "send",
			Net:    g.uriScheme,
			Source: nil,
			Addr:   addr,
			Err:    errors.New("not connected to graylog service")}
	}

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
