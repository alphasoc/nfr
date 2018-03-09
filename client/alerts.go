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

// Alert provides result of AlphaSOC Engine analysis, which was found to be threat.
type Alert struct {
	Type  string `json:"type"`
	Event struct {
		Protocol  string    `json:"proto"`
		DestIP    net.IP    `json:"destIP"`
		DestPort  int       `json:"destPort"`
		SrcIP     net.IP    `json:"srcIP"`
		SrcPort   int       `json:"srcPort"`
		BytesIn   int       `json:"bytesIn"`
		BytesOut  int       `json:"bytesOut"`
		Timestamp time.Time `json:"ts"`
	} `json:"event"`
	Threats []string `json:"threats"`
	Wisdom  struct {
		Flags []string `json:"flags"`
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
