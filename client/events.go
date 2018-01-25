package client

import (
	"context"
	"encoding/json"
	"net/url"
)

// EventsResponse represents response for /events call.
type EventsResponse struct {
	Follow  string            `json:"follow"`
	More    bool              `json:"more"`
	Events  []Event           `json:"events,omitempty"`
	Threats map[string]Threat `json:"threats,omitempty"`
}

// Event provides result of analysis of DNS
// request, which was found to be threat.
type Event struct {
	Type       string   `json:"type"`
	Ts         []string `json:"ts"`
	IP         string   `json:"ip"`
	RecordType string   `json:"record_type"`
	FQDN       string   `json:"fqdn"`
	Risk       int      `json:"risk"`
	Flags      []string `json:"flags"`
	Threats    []string `json:"threats"`
}

// Threat provides more details about threat,
// like human-readable description.
type Threat struct {
	Title      string `json:"title"`
	Severity   int    `json:"severity"`
	Policy     bool   `json:"policy"`
	Deprecated bool   `json:"deprecated"`
}

// Events returns AlphaSOC events that informs about potential risk.
func (c *AlphaSOCClient) Events(follow string) (*EventsResponse, error) {
	if c.key == "" {
		return nil, ErrNoAPIKey
	}
	query := url.Values{}
	if follow != "" {
		query.Add("follow", follow)
	}
	resp, err := c.get(context.Background(), "events", query)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var r EventsResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	return &r, nil
}
