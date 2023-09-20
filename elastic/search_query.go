package elastic

import (
	"encoding/json"
	"time"
)

// DocRangeField is used in DocRange
type DocRangeField struct {
	Gt     string `json:"gt"`
	Format string `json:"format,omitempty"`
}

// DocRange is used in SearchQuery.
type DocRange struct {
	Range map[string]DocRangeField `json:"range"`
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

func (ec *EventsCursor) searchQuery() ([]byte, error) {
	fn := ec.search.FinalFieldNames()

	sq := SearchQuery{}
	sq.Size = ec.search.BatchSize
	sq.Sort = []map[string]string{
		{fn.EventIngested: "asc"},
	}
	sq.PIT = ec.pit
	sq.SearchAfter = ec.searchAfter

	var err error

	sq.DocValueFields = []DocValueField{{Field: fn.Timestamp, Format: "strict_date_time"}}

	if fn.Timestamp != fn.EventIngested {
		sq.DocValueFields = append(sq.DocValueFields,
			DocValueField{Field: fn.EventIngested, Format: "strict_date_time"})
	}

	// Get the document field names to retrieve (except ts and event.ingested)
	sq.Source, err = ec.search.EventFields()
	if err != nil {
		return nil, err
	}

	// Build a time range of events we want to retrieve. If no events where
	// retrieved ever, let's just ingest the last 10 minutes. Otherwise,
	// retrieve all events since NewestIngested from the pull job.
	docrange := DocRange{Range: make(map[string]DocRangeField)}

	if ec.newestIngested.IsZero() {
		docrange.Range[fn.EventIngested] = DocRangeField{Gt: "now-5m"}
	} else {
		drf := DocRangeField{Gt: ec.newestIngested.Format(time.RFC3339Nano)}
		// Add a timestamp format to the query if configured.  Added in response to a
		// case where the ingested timestamp lacked milliseconds.  The search query,
		// to prevent a date field parse error, needed an explicitly set timestamp
		// format of 'strict_date_time_no_millis'.  Thus it was decided to make this
		// configurable.
		if ec.search.TimestampFormat != "" {
			drf.Format = ec.search.TimestampFormat
		}
		docrange.Range[fn.EventIngested] = drf
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

	return json.Marshal(sq)
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
