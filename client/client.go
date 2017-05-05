// Package client provides functions to handle AlphaSOC public API.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/alphasoc/namescore/helpers"

	"golang.org/x/net/context/ctxhttp"
)

// ErrorResponse represents AlphaSOC API error response.
type ErrorResponse struct {
	Message string `json:"message"`
}

// Client handles connection to AlphaSOC server.
type Client struct {
	host      string
	version   string
	client    *http.Client
	key       string
	userAgent string
}

// ErrUnsupportedVersion is returned when Client is created with
// unssported version of AlphaSCO API.
var ErrUnsupportedVersion = errors.New("unsupported version")

// New creates new AlphaSOC client with given host.
// It also sets timeout to 30 seconds.
func New(host, version string) (*Client, error) {
	return NewWithKey(host, version, "")
}

// NewWithKey creates new AlphaSOC client with given host and key.
func NewWithKey(host, version, key string) (*Client, error) {
	if version != "v1" {
		return nil, ErrUnsupportedVersion
	}

	return &Client{
		client:    &http.Client{Timeout: 30 * time.Second},
		host:      strings.TrimSuffix(host, "/"),
		version:   version,
		key:       key,
		userAgent: fmt.Sprintf("AlphaSOC namescore/%s", helpers.Version),
	}, nil
}

// SetKey sets API key.
func (c *Client) SetKey(key string) {
	c.key = key
}

// CheckKey check if client has valid AlphaSOC key.
func (c *Client) CheckKey() error {
	_, err := c.AccountStatus()
	return err
}

// getAPIPath returns the versioned request path to call the api.
// It appends the query parameters to the path if they are not empty.
func (c *Client) getAPIPath(path string, query url.Values) string {
	return fmt.Sprintf("%s/%s/%s%s", c.host, c.version, path, query.Encode())
}

func (c *Client) get(ctx context.Context, path string, query url.Values) (*http.Response, error) {
	return c.do(ctx, http.MethodGet, path, query, nil, nil)
}

func (c *Client) post(ctx context.Context, path string, query url.Values, obj interface{}) (*http.Response, error) {
	var buffer bytes.Buffer
	headers := make(http.Header, 1)
	if obj != nil {
		if err := json.NewEncoder(&buffer).Encode(obj); err != nil {
			return nil, err
		}
		headers["Content-Type"] = []string{"application/json"}
	}
	return c.do(ctx, http.MethodPost, path, query, &buffer, headers)
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, body io.Reader, headers http.Header) (*http.Response, error) {
	req, err := http.NewRequest(method, c.getAPIPath(path, query), body)
	if err != nil {
		return nil, err
	}
	if c.key != "" {
		req.SetBasicAuth(c.key, "")
	}
	req.Header.Set("User-Agent", c.userAgent)
	for key, value := range headers {
		req.Header[key] = value
	}

	resp, err := ctxhttp.Do(ctx, c.client, req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		var errorResponse ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return nil, err
		}
		return nil, errors.New(errorResponse.Message)
	}
	return resp, nil
}
