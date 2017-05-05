package client

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
)

// KeyRequestResponse represents response  for /key/request call
type KeyRequestResponse struct {
	Key string `json:"key"`
}

// KeyRequestRequest contasin infromation needed for key registration.
type KeyRequestRequest struct {
	Platform struct {
		Name string `json:"name"`
	} `json:"platform"`
	Token string `json:"token"`
}

// KeyRequest returns new AlphaSOC account key.
func (c *Client) KeyRequest() (*KeyRequestResponse, error) {
	var req KeyRequestRequest
	req.Platform.Name = fmt.Sprintf("namescore-%s-%s", runtime.GOOS, runtime.GOARCH)
	resp, err := c.post(context.Background(), "key/request", nil, &req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var r KeyRequestResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	return &r, nil
}
