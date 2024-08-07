package client

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"time"
)

// HTTPEntry is single dns entry for analize.
type HTTPEntry struct {
	Timestamp time.Time `json:"ts"`
	SrcIP     net.IP    `json:"srcIP"`
	SrcPort   uint16    `json:"srcPort"`

	URL      string `json:"url"`
	Method   string `json:"method"`
	Status   int    `json:"status"`
	Action   string `json:"action"`
	BytesIn  int64  `json:"bytesIn"`
	BytesOut int64  `json:"bytesOut"`

	// headers
	ContentType string `json:"contentType"`
	Referrer    string `json:"referrer"`
	UserAgent   string `json:"userAgent"`
}

// EventsHTTPResponse represents response for /events/http call.
type EventsHTTPResponse struct {
	Received int            `json:"received"`
	Accepted int            `json:"accepted"`
	Rejected map[string]int `json:"rejected"`
}

// EventsHTTP sends http queries to AlphaSOC api for analize.
func (c *AlphaSOCClient) EventsHTTP(events []*HTTPEntry) (*EventsHTTPResponse, error) {
	if c.key == "" {
		return nil, ErrNoAPIKey
	}

	if len(events) == 0 {
		return nil, ErrNoRequest
	}

	var (
		buffer = &bytes.Buffer{}
		enc    = json.NewEncoder(buffer)
	)

	for _, entry := range events {
		if err := enc.Encode(entry); err != nil {
			return nil, err
		}
	}

	resp, err := c.post(context.Background(), "events/http", nil, buffer.Bytes())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var r EventsHTTPResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	return &r, nil
}
