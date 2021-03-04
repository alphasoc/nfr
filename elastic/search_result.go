package elastic

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/alphasoc/nfr/client"
	"github.com/buger/jsonparser"
	"github.com/pkg/errors"
)

// Hit is a single document returned within an es search.
type Hit struct {
	ID     string              `json:"_id"`
	Source json.RawMessage     `json:"_source"`
	Fields map[string][]string `json:"fields"`
	Sort   []interface{}       `json:"sort"`
}

// SearchResult is a json dictionary returned by
// an es search.
type SearchResult struct {
	PitID    string `json:"pit_id"`
	Took     int    `json:"took"`
	TimedOut bool   `json:"timed_out"`
	Hits     struct {
		Hits []Hit `json:"hits"`
	} `json:"hits"`
}

func (h *Hit) timestamp(field string) (time.Time, error) {
	if h.Fields == nil {
		return time.Time{}, fmt.Errorf("missing timestamp field: %v", field)
	}

	tsslice, ok := h.Fields[field]
	if !ok || len(tsslice) < 1 {
		return time.Time{}, fmt.Errorf("missing timestamp field: %v", field)
	}

	ts, err := time.Parse(time.RFC3339Nano, tsslice[0])
	if err != nil {
		return time.Time{}, errors.Wrapf(err, "parse timestamp field (%v)", field)
	}

	return ts, nil
}

// DecodeDNS returns client.DNSEntry parsed from the Hit using provided field names.
func (h *Hit) DecodeDNS(cfg *SearchConfig) (*client.DNSEntry, error) {
	if cfg.EventType != client.EventTypeDNS {
		return nil, errors.New("invalid event type in DecodeDNS")
	}

	fn := cfg.FinalFieldNames()
	e := &client.DNSEntry{}

	var err error
	e.Timestamp, err = h.timestamp(fn.Timestamp)
	if err != nil {
		return nil, errors.Wrap(err, "parse timestamp")
	}

	srcip, err := jsonparser.GetString(h.Source, fn.SrcIP...)
	if err != nil {
		return nil, errors.Wrap(err, "get src ip field")
	}

	e.SrcIP = net.ParseIP(srcip)
	if e.SrcIP == nil {
		return nil, fmt.Errorf("invalid src ip: %v", srcip)
	}

	e.Query, err = jsonparser.GetString(h.Source, fn.Query...)
	if err != nil {
		return nil, errors.Wrap(err, "get dns query field")
	}

	e.QType, err = jsonparser.GetString(h.Source, fn.QType...)

	return e, nil
}
