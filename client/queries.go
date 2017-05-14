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

// NewQueriesRequest creates and returns QueriesRequest.
func NewQueriesRequest() *QueriesRequest {
	return &QueriesRequest{Data: make([][4]string, 0)}
}

// AddQuery adds query to request.
func (q *QueriesRequest) AddQuery(query [4]string) {
	q.Data = append(q.Data, query)
}

// QueriesResponse represents response for /quiery call.
type QueriesResponse struct {
	Received int            `json:"received"`
	Accepted int            `json:"accepted"`
	Rejected map[string]int `json:"rejected"`
}

// Queries pushes dns queries to AlphaSOC api for analize.
func (c *AlphaSOCClient) Queries(req *QueriesRequest) (*QueriesResponse, error) {
	if c.key == "" {
		return nil, ErrNoAPIKey
	}

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
