package client

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"time"
)

// IPEntry is single ip entry for analize.
type IPEntry struct {
	Timestamp time.Time `json:"ts"`
	SrcIP     net.IP    `json:"srcIp"`
	SrcPort   int       `json:"srcPort"`
	DstIP     net.IP    `json:"destIp"`
	DstPort   int       `json:"destPort"`
	Protocol  string    `json:"proto"`
	BytesIn   int       `json:"bytesIn"`
	BytesOut  int       `json:"bytesOut"`
}

// EventsIPRequest contains slice of ip events.
type EventsIPRequest struct {
	Entries []*IPEntry
}

// EventsIPResponse for logs/ip call.
type EventsIPResponse struct {
	Received int            `json:"received"`
	Accepted int            `json:"accepted"`
	Rejected map[string]int `json:"rejected"`
}

// EventsIP sends ip events to AlphaSOC engine for analize.
func (c *AlphaSOCClient) EventsIP(req *EventsIPRequest) (*EventsIPResponse, error) {
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

	resp, err := c.post(context.Background(), "events/ip", nil, buffer.Bytes())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var r EventsIPResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	return &r, nil
}
