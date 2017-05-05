package client

import (
	"context"
	"encoding/json"
)

// AccountStatusResponse represents response for /account/status call.
type AccountStatusResponse struct {
	Registered bool `json:"registered"`
	Expired    bool `json:"expired"`
	Messages   []struct {
		Level int    `json:"level"`
		Body  string `json:"body"`
	} `json:"messages"`
}

// AccountStatus returns AlphaSOC account details status.
func (c *Client) AccountStatus() (*AccountStatusResponse, error) {
	resp, err := c.get(context.Background(), "account/status", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var r AccountStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	return &r, nil
}
