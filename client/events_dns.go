package client

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"time"
)

// DNSEntry is single dns entry for analize.
type DNSEntry struct {
	Timestamp time.Time `json:"ts"`
	SrcIP     net.IP    `json:"srcIp"`
	Query     string    `json:"query"`
	QType     string    `json:"qtype"`
}

// EventsDNSRequest contains slice of ip events.
type EventsDNSRequest struct {
	Entries []*DNSEntry
}

// EventsDNSResponse represents response for /events/dns call.
type EventsDNSResponse struct {
	Received int            `json:"received"`
	Accepted int            `json:"accepted"`
	Rejected map[string]int `json:"rejected"`
}

// EventsDNS sends dns queries to AlphaSOC api for analize.
func (c *AlphaSOCClient) EventsDNS(req *EventsDNSRequest) (*EventsDNSResponse, error) {
	if c.key == "" {
		return nil, ErrNoAPIKey
	}

	if req == nil {
		return nil, ErrNoRequest
	}

	var (
		buffer = &bytes.Buffer{}
		enc    = json.NewEncoder(buffer)
	)

	for _, entry := range req.Entries {
		if err := enc.Encode(entry); err != nil {
			return nil, err
		}
	}

	resp, err := c.post(context.Background(), "events/dns", nil, buffer.Bytes())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var r EventsDNSResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	return &r, nil
}
