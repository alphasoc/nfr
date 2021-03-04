package elastic

import (
	"context"
	"encoding/json"
	"time"

	es7 "github.com/elastic/go-elasticsearch/v7"
	"github.com/pkg/errors"
)

// EventsCursor is an iterator which downloads paginated search results
// returned within an open Point-In-Time.
type EventsCursor struct {
	client         *es7.Client
	search         *SearchConfig
	searchAfter    []interface{}
	pit            *PointInTime
	newestIngested time.Time
}

// Next retrieves the next page of events. If (nil, nil) is returned,
// there are no new events.
func (ec *EventsCursor) Next(ctx context.Context) ([]Hit, error) {
	sq, err := ec.searchQuery()
	if err != nil {
		return nil, errors.Wrap(err, "creating search query")
	}

	res, err := ec.client.Search(
		ec.client.Search.WithContext(ctx),
		ec.client.Search.WithBody(sq),
	)
	if err != nil {
		return nil, errors.Wrap(err, "doing search")
	}
	defer res.Body.Close()

	if err := IsAPIError(res); err != nil {
		return nil, errors.Wrap(err, "search api error")
	}

	var answer SearchResult
	if err := json.NewDecoder(res.Body).Decode(&answer); err != nil {
		return nil, errors.Wrap(err, "decoding search response")
	}

	if answer.TimedOut {
		return nil, ErrQueryTimeout
	}

	hits := answer.Hits.Hits

	if len(hits) == 0 {
		// No more hits
		return nil, nil
	}

	lastHit := hits[len(hits)-1]

	// Update searchAfter for the next page.
	ec.searchAfter = lastHit.Sort

	// And save the timestamp of the most recent ingested event.
	ec.newestIngested, err = lastHit.timestamp(ec.search.FinalFieldNames().EventIngested)
	if err != nil {
		return nil, errors.Wrap(err, "get event.ingested")
	}

	return hits, nil
}

// NewestIngested returns a timestamp of the most recently ingested event
// retrieved by the search.
func (ec *EventsCursor) NewestIngested() time.Time {
	return ec.newestIngested
}

// Close closes the point-in-time transaction, if it was open.
func (ec *EventsCursor) Close() error {
	if ec.pit != nil {
		err := ec.pit.Close()
		ec.pit = nil
		return err
	}

	return nil
}
