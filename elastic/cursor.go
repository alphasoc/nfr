package elastic

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strconv"
	"time"

	es7 "github.com/elastic/go-elasticsearch/v7"
	"github.com/elastic/go-elasticsearch/v7/esapi"
	"github.com/pkg/errors"
)

// EventsCursor is an iterator which downloads paginated search results
// returned within an open Point-In-Time.
type EventsCursor struct {
	client         *es7.Client
	search         *SearchConfig
	searchAfter    []interface{}
	pit            *PointInTime // can be used from 7.10 with X-Pack instead of scrollID
	scrollCursor   []byte       // used for pagination
	newestIngested time.Time

	// Save search query for debug purposes
	lastSearchQuery []byte
}

// Next retrieves the next page of events. If (nil, nil) is returned,
// there are no new events.
func (ec *EventsCursor) Next(ctx context.Context) ([]Hit, error) {
	var res *esapi.Response
	var err error

	if ec.scrollCursor != nil {
		// Use scroll id to retrieve paginated results
		res, err = ec.client.Scroll(
			ec.client.Scroll.WithContext(ctx),
			ec.client.Scroll.WithBody(bytes.NewReader(ec.scrollCursor)))
	} else {
		// Scroll ID is empty, create a search with scroll.
		ec.lastSearchQuery, err = ec.searchQuery()
		if err != nil {
			return nil, errors.Wrap(err, "creating search query")
		}

		res, err = ec.client.Search(
			ec.client.Search.WithContext(ctx),
			ec.client.Search.WithIndex(ec.search.Indices...),
			ec.client.Search.WithBody(bytes.NewReader(ec.lastSearchQuery)),
			ec.client.Search.WithScroll(time.Duration(ec.search.PITKeepAlive)*time.Second))
	}

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

	if answer.ScrollID != "" {
		d := time.Duration(ec.search.PITKeepAlive) * time.Second

		var scroll string
		if d < time.Millisecond {
			scroll = strconv.FormatInt(int64(d), 10) + "nanos"
		} else {
			scroll = strconv.FormatInt(int64(d)/int64(time.Millisecond), 10) + "ms"
		}

		marshaled, _ := json.Marshal(ScrollSearch{Scroll: scroll, ScrollID: answer.ScrollID})
		ec.scrollCursor = marshaled
	}

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

// SearchConfig returns the underlying search config.
func (ec *EventsCursor) SearchConfig() *SearchConfig {
	return ec.search
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

func (ec *EventsCursor) DumpLastSearchQuery(fname string) error {
	f, err := os.Create(fname)
	if err != nil {
		return err
	}
	defer f.Close()

	var out bytes.Buffer
	json.Indent(&out, ec.lastSearchQuery, "", "  ")
	out.WriteTo(f)

	return nil
}
