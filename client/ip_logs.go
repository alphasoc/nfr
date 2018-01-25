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
	SrcIP     net.IP    `json:"src_ip"`
	SrcPort   int       `json:"src_port"`
	DestIP    net.IP    `json:"dest_ip"`
	DestPort  int       `json:"dest_port"`
	Protocol  string    `json:"protocol"`
	BytesIn   int       `json:"bytes_in"`
	BytesOut  int       `json:"bytes_out"`
}

// IPRequest contains slice of ip events for sending.
type IPRequest struct {
	Entries []*IPEntry
}

// IPResponse for logs/ip call.
type IPResponse struct {
	Received int            `json:"received"`
	Accepted int            `json:"accepted"`
	Rejected map[string]int `json:"rejected"`
}

// Ips sends ip logs to AlphaSOC api for analize.
func (c *AlphaSOCClient) Ips(req *IPRequest) (*IPResponse, error) {
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

	resp, err := c.post(context.Background(), "logs/ip", nil, buffer.Bytes(), true)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var r IPResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	return &r, nil
}
