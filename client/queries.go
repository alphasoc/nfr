// Package client provides functions to handle AlphaSOC public API and manage API related files.
package client

import (
	"context"
	"encoding/json"
)

// QueriesRequest contains slice of queries for sending.
// Slice must contain as follows:
// [0] - timestamp in RFC3339 fromat
// [1] - host source ip address which send DNS question
// [2] - DNS record type
// [3] - FQDN (Fully Qualified Domain Name)
type QueriesRequest struct {
	Data [][4]string `json:"data"`
}

// QueriesResponse represents reponse for /quiery call.
type QueriesResponse struct {
	Received int            `json:"received"`
	Accepted int            `json:"accepted"`
	Rejected map[string]int `json:"rejected"`
}

// Queries pushs dns queries to AlphaSOC api for futher analize.
func (c *Client) Queries(req *QueriesRequest) (*QueriesResponse, error) {
	resp, err := c.post(context.Background(), "queries", nil, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var r QueriesResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	return &r, nil
}
