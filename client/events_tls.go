package client

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"time"
)

// TLSEntry is single dns entry for analize.
type TLSEntry struct {
	Timestamp time.Time `json:"ts"`
	SrcIP     net.IP    `json:"srcIP"`
	SrcPort   uint16    `json:"srcPort"`

	DstIP   net.IP `json:"destIP,omitempty"`
	DstPort uint16 `json:"destPort,omitempty"`

	CertHash  string    `json:"certHash,omitempty"`
	Issuer    string    `json:"issuer,omitempty"`
	Subject   string    `json:"subject,omitempty"`
	ValidFrom time.Time `json:"validFrom,omitempty"`
	ValidTo   time.Time `json:"validTo,omitempty"`
	JA3       string    `json:"ja3,omitempty"`
	JA3s      string    `json:"ja3s,omitempty"`
}

// EventsHTTPResponse represents response for /events/http call.
type EventsTLSResponse struct {
	Received int            `json:"received"`
	Accepted int            `json:"accepted"`
	Rejected map[string]int `json:"rejected"`
}

// EventsHTTP sends tls events to AlphaSOC api for analize.
func (c *AlphaSOCClient) EventsTLS(events []*TLSEntry) (*EventsTLSResponse, error) {
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

	resp, err := c.post(context.Background(), "events/tls", nil, buffer.Bytes())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var r EventsTLSResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	return &r, nil
}
