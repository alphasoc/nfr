package elastic

import (
	"fmt"
	"strings"
	"time"

	es7 "github.com/elastic/go-elasticsearch/v7"
)

// DefaultPITKeepAlive defines a default keepalive for point-in-time
// if the provided paramter is zero.
const DefaultPITKeepAlive = 3 * time.Minute // 3 minutes

// PointInTime is something like a SQL's transaction. It guarantees that
// returned documents are unchanged during the retrieval.
type PointInTime struct {
	client *es7.Client

	ID        string `json:"id"`
	KeepAlive string `json:"keep_alive,omitempty"`
}

// Close closes an open Point-in-time.
func (p *PointInTime) Close() error {
	res, err := p.client.ClosePointInTime(
		p.client.ClosePointInTime.WithBody(strings.NewReader(fmt.Sprintf(`{"id":"%v"}`, p.ID))),
	)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	err = IsAPIError(res)
	return err
}
