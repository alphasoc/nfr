package client

import (
	"context"
	"fmt"
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
	if c.key == "" {
		return nil, ErrNoAPIKey
	}
	resp, err := c.get(context.Background(), "account/status", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var r AccountStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, fmt.Errorf("json decoding error: %s", err)
	}
	return &r, nil
}
