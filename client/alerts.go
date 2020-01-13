package client

import (
	"context"
	"encoding/json"
	"net"
	"net/url"
	"time"
)

// AlertsResponse represents response for /events call.
type AlertsResponse struct {
	Follow string `json:"follow"`
	More   bool   `json:"more"`
	After  string `json:"after,omitempty"`
	Before string `json:"before,omitempty"`

	Alerts  []Alert           `json:"alerts,omitempty"`
	Threats map[string]Threat `json:"threats,omitempty"`
}

type EventUnified struct {
	// Header
	Timestamp time.Time `json:"ts"`
	SrcIP     net.IP    `json:"srcIP"`
	SrcPort   uint16    `json:"srcPort,omitempty"`
	SrcHost   string    `json:"srcHost,omitempty"`

	// Bytes transferred
	BytesIn  int64 `json:"bytesIn,omitempty"`
	BytesOut int64 `json:"bytesOut,omitempty"`

	// DNS fields
	Query     string `json:"query,omitempty"`
	QueryType string `json:"qtype,omitempty"`

	// IP fields
	DestIP   net.IP `json:"destIP,omitempty"`
	DestPort uint16 `json:"destPort,omitempty"`
	Proto    string `json:"proto,omitempty"`
	Ja3      string `json:"ja3,omitempty"`

	// HTTP fields
	URL         string `json:"url,omitempty"`
	Method      string `json:"method,omitempty"`
	Status      int32  `json:"status,omitempty"`
	Action      string `json:"action,omitempty"`
	ContentType string `json:"contentType,omitempty"`
	Referrer    string `json:"referrer,omitempty"`
	UserAgent   string `json:"userAgent,omitempty"`
}

// Alert provides result of AlphaSOC Engine analysis, which was found to be threat.
type Alert struct {
	EventType string       `json:"eventType"`
	Event     EventUnified `json:"event"`

	// IPEvent   IPEntry   `json:"-"`
	// DNSEvent  DNSEntry  `json:"-"`
	// HTTPEvent HTTPEntry `json:"-"`

	Threats []string `json:"threats"`
	Wisdom  struct {
		Flags  []string `json:"flags"`
		Labels []string `json:"labels"`
	} `json:"wisdom"`
}

// Threat provides more details about threat,
// like human-readable description.
type Threat struct {
	Title    string `json:"title"`
	Severity int    `json:"severity"`
	Policy   bool   `json:"policy"`
}

// Alerts returns AlphaSOC events that informs about potential risk.
func (c *AlphaSOCClient) Alerts(follow string) (*AlertsResponse, error) {
	if c.key == "" {
		return nil, ErrNoAPIKey
	}
	query := url.Values{}
	if follow != "" {
		query.Add("follow", follow)
	}
	resp, err := c.get(context.Background(), "alerts", query)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var r AlertsResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}

	return &r, nil
}
