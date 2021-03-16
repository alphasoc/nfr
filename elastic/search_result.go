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
	ScrollID string `json:"_scroll_id"`
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

// sourceString is a helper method used for non-required fields in DecodeDNS/IP/HTTP functions.
func (h *Hit) sourceString(path []string) string {
	if len(path) == 0 {
		return ""
	}

	val, err := jsonparser.GetString(h.Source, path...)
	if err != nil {
		return ""
	}

	return val
}

// sourceInt64 is a helper method used for non-required fields in DecodeDNS/IP/HTTP functions.
func (h *Hit) sourceInt64(path []string) int64 {
	if len(path) == 0 {
		return 0
	}

	val, err := jsonparser.GetInt(h.Source, path...)
	if err != nil {
		return 0
	}

	return val
}

// sourceUint16 is a helper method used for non-required fields in DecodeDNS/IP/HTTP functions.
func (h *Hit) sourceUint16(path []string) uint16 {
	if len(path) == 0 {
		return 0
	}

	val := h.sourceInt64(path)
	if val < 0 || val > 65535 {
		return 0
	}

	return uint16(val)
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

	// Non-required fields don't return errors
	e.QType = h.sourceString(fn.QType)

	return e, nil
}

// DecodeIP returns client.IPEntry parsed from the Hit using provided field names.
func (h *Hit) DecodeIP(cfg *SearchConfig) (*client.IPEntry, error) {
	if cfg.EventType != client.EventTypeIP {
		return nil, errors.New("invalid event type in DecodeIP")
	}

	fn := cfg.FinalFieldNames()
	e := &client.IPEntry{}

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

	dstip, err := jsonparser.GetString(h.Source, fn.DstIP...)
	if err != nil {
		return nil, errors.Wrap(err, "get dst ip field")
	}

	e.DstIP = net.ParseIP(dstip)
	if e.DstIP == nil {
		return nil, fmt.Errorf("invalid dst ip: %v", srcip)
	}

	// Non-required fields don't return errors
	e.SrcPort = int(h.sourceUint16(fn.SrcPort))
	e.DstPort = int(h.sourceUint16(fn.DstPort))
	e.Protocol = h.sourceString(fn.Protocol)
	e.BytesIn = int(h.sourceInt64(fn.BytesIn))
	e.BytesOut = int(h.sourceInt64(fn.BytesOut))

	return e, nil
}

// DecodeHTTP returns client.IPEntry parsed from the Hit using provided field names.
func (h *Hit) DecodeHTTP(cfg *SearchConfig) (*client.HTTPEntry, error) {
	if cfg.EventType != client.EventTypeHTTP {
		return nil, errors.New("invalid event type in DecodeHTTP")
	}

	fn := cfg.FinalFieldNames()
	e := &client.HTTPEntry{}

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

	e.URL, err = jsonparser.GetString(h.Source, fn.URL...)
	if err != nil {
		return nil, errors.Wrap(err, "get url field")
	}

	// Non-required fields don't return errors
	e.SrcPort = h.sourceUint16(fn.SrcPort)
	e.Method = h.sourceString(fn.Method)
	e.Status = int(h.sourceInt64(fn.StatusCode))
	e.BytesIn = h.sourceInt64(fn.BytesIn)
	e.BytesOut = h.sourceInt64(fn.BytesOut)
	e.UserAgent = h.sourceString(fn.UserAgent)
	e.ContentType = h.sourceString(fn.ContentType)
	e.Referrer = h.sourceString(fn.Referrer)

	return e, nil
}
