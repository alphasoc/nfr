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
			Must   []json.RawMessage `json:"must,omitempty"`
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
	if terms != "" {
		sq.Query.Bool.Filter = append(sq.Query.Bool.Filter, json.RawMessage(terms))
	}

	sq.Query.Bool.Filter = append(sq.Query.Bool.Filter, drjson)

	sq.Query.Bool.Must, err = mustExistFields(ec.search.FinalMustHaveFields())
	if err != nil {
		return nil, err
	}

	data, _ := json.Marshal(sq)

	// Debug: print resulting search query
	// pretty, _ := json.MarshalIndent(sq, "", "  ")
	// fmt.Println(string(pretty))

	return bytes.NewReader(data), nil
}

// mustExistFields constructs an Elastic Query DSL fragment used in the
// search query.
func mustExistFields(fields []string) ([]json.RawMessage, error) {
	type query struct {
		Exists struct {
			Field string `json:"field"`
		} `json:"exists"`
	}

	var ret []json.RawMessage
	for _, f := range fields {
		q := query{}
		q.Exists.Field = f
		data, err := json.Marshal(q)
		if err != nil {
			return nil, err
		}
		ret = append(ret, data)
	}

	return ret, nil
}
