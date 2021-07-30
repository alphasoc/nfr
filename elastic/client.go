package elastic

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/alphasoc/nfr/client"
	"github.com/cenkalti/backoff/v4"
	es7 "github.com/elastic/go-elasticsearch/v7"
	"github.com/pkg/errors"
)

// SupportedEventTypes is a list of event types supported by the module.
var SupportedEventTypes = []client.EventType{
	client.EventTypeDNS,
	client.EventTypeIP,
	client.EventTypeHTTP,
	client.EventTypeTLS,
}

// Client is an elasticsearch client capable of pulling telemetry data
// from and pushing alphasoc threats to an es instance. It also has all
// necessary methods to set up an index and field mappings for sending
// threats compatible with ECS.
type Client struct {
	opts *Config
	c    *es7.Client

	retryBackoff *backoff.ExponentialBackOff
}

// NewClient creates a new Client.
func NewClient(opts *Config) (*Client, error) {
	if opts == nil {
		return nil, errors.New("client options must not be null")
	}

	c := &Client{
		opts:         opts,
		retryBackoff: backoff.NewExponentialBackOff(),
	}
	c.retryBackoff.MaxElapsedTime = 0

	cfg := es7.Config{
		CloudID:   c.opts.CloudID,
		APIKey:    c.opts.APIKey,
		Addresses: c.opts.Hosts,
		Username:  c.opts.Username,
		Password:  c.opts.Password,
		Transport: &fastTransport{},

		// Retry on too many requests as well
		RetryOnStatus: []int{502, 503, 504, 429},

		RetryBackoff: func(i int) time.Duration {
			if i == 1 {
				c.retryBackoff.Reset()
			}
			return c.retryBackoff.NextBackOff()
		},

		// Retry up to 5 attempts
		MaxRetries: 5,
	}

	var err error
	c.c, err = es7.NewClient(cfg)
	if err != nil {
		return nil, errors.Wrap(err, "creating es client")
	}

	return c, nil
}

// Fetch opens a new Point-In-Time for given indices and returns a cursor
// used to retrieve events.
func (c *Client) Fetch(ctx context.Context, search *SearchConfig, from time.Time) (*EventsCursor, error) {
	if search == nil {
		return nil, errors.New("search config must not be null")
	}

	ec := &EventsCursor{client: c.c, search: search, newestIngested: from}
	return ec, nil
}

// OpenPIT opens a Point-in-time transaction for given indices.
func (c *Client) OpenPIT(ctx context.Context, indices []string, keepAlive time.Duration) (*PointInTime, error) {
	var ka int
	if keepAlive > 0 {
		ka = int(keepAlive.Seconds())
	} else {
		ka = int(DefaultPITKeepAlive.Seconds())
	}

	res, err := c.c.OpenPointInTime(
		c.c.OpenPointInTime.WithContext(ctx),
		c.c.OpenPointInTime.WithIndex(indices...),
		c.c.OpenPointInTime.WithKeepAlive(fmt.Sprintf("%vs", ka)),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if err := IsAPIError(res); err != nil {
		return nil, err
	}

	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	pit := PointInTime{client: c.c}
	err = json.Unmarshal(data, &pit)
	return &pit, err
}
