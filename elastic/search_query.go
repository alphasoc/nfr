package elastic

import (
	"bytes"
	"encoding/json"
	"io"
	"time"
)

// DocRange is used in SearchQuery.
type DocRange struct {
	Range struct {
		Event struct {
			Gte string `json:"gte"`
		} `json:"event.ingested"`
	} `json:"range"`
}

// DocValueField as defined by the es Search API
type DocValueField struct {
	Field  string `json:"field"`
	Format string `json:"format"`
}

// SearchQuery is a JSON object passed to es instance
// when doing a search.
type SearchQuery struct {
	// Return timestamp in docvalue_fields, as we want to force their format
	DocValueFields []DocValueField `json:"docvalue_fields"`

	// Return other fields in _source
	Source []string `json:"_source"`
	Size   int      `json:"size"`
	Query  struct {
		Bool struct {
			Filter []json.RawMessage `json:"filter"`
		} `json:"bool"`
	} `json:"query"`
	Sort        []map[string]string `json:"sort"`
	PIT         *PointInTime        `json:"pit,omitempty"`
	SearchAfter []interface{}       `json:"search_after,omitempty"`
}

func (ec *EventsCursor) searchQuery() (io.Reader, error) {
	fn := ec.search.FinalFieldNames()

	sq := SearchQuery{}
	sq.Size = ec.search.BatchSize
	sq.Sort = []map[string]string{
		{fn.EventIngested: "asc"},
		{"_id": "asc"},
	}
	sq.PIT = ec.pit
	sq.SearchAfter = ec.searchAfter

	var err error

	sq.DocValueFields = []DocValueField{
		{Field: fn.Timestamp, Format: "strict_date_time"},
		{Field: fn.EventIngested, Format: "strict_date_time"},
	}

	// Get the document field names to retrieve (except ts and event.ingested)
	sq.Source, err = ec.search.EventFields()
	if err != nil {
		return nil, err
	}

	// Build a time range of events we want to retrieve. If no events where
	// retrieved ever, let's just ingest the last 10 minutes. Otherwise,
	// retrieve all events since NewestIngested from the pull job.
	docrange := DocRange{}

	if ec.newestIngested.IsZero() {
		docrange.Range.Event.Gte = "now-10m"
	} else {
		docrange.Range.Event.Gte = ec.newestIngested.Format(time.RFC3339Nano)
	}

	drjson, _ := json.Marshal(docrange)

	// Define search filter terms. Use defaults or custom, if available.
	terms := ec.search.FinalSearchTerm()

	// Wrap the terms into {"terms":<originalterms>} to prepare it to use
	// in query filter below.
	wrappedTerms := append([]byte(`{"terms":`), []byte(terms)...)
	wrappedTerms = json.RawMessage(append(wrappedTerms, []byte(`}`)...))

	sq.Query.Bool.Filter = []json.RawMessage{
		wrappedTerms,
		drjson,
	}

	data, _ := json.Marshal(sq)

	return bytes.NewReader(data), nil
}
