package elastic

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/alphasoc/nfr/client"
	"github.com/google/go-cmp/cmp"
	"github.com/imdario/mergo"
	"github.com/pkg/errors"
	"github.com/twmb/murmur3"
	"gopkg.in/yaml.v3"
)

// Default configuration values.
const (
	DefaultPollInterval = 30 // 30 seconds
	DefaultBatchSize    = 10000
)

// FieldPath is a field name path in a nested elasticsearch document.
type FieldPath []string

// IndexSchema is used to select a predefined field names
// configuration.
type IndexSchema string

// Supported field schemas
const (
	IndexSchemaCorelight IndexSchema = "corelight"
	IndexSchemaECS       IndexSchema = "ecs"
)

var defaultMustHaveFields = map[client.EventType]map[IndexSchema][]string{
	client.EventTypeDNS: {
		IndexSchemaECS: []string{"@timestamp", "event.ingested", "source.ip", "dns.question.name"},
	},
	client.EventTypeIP: {
		IndexSchemaECS: []string{"@timestamp", "event.ingested", "source.ip", "destination.ip"},
	},
	client.EventTypeHTTP: {
		IndexSchemaECS: []string{"@timestamp", "event.ingested", "source.ip", "url.original"},
	},
	client.EventTypeTLS: {
		IndexSchemaECS: []string{"@timestamp", "event.ingested", "source.ip"},
	},
}

var defaultSearchTerms = map[client.EventType]map[IndexSchema]string{
	client.EventTypeDNS: {
		IndexSchemaCorelight: `{"term": {"_path":"dns"}}`,
	},
	client.EventTypeIP: {
		IndexSchemaCorelight: `{"term": {"_path":"conn"}}`,
	},
	client.EventTypeHTTP: {
		IndexSchemaCorelight: `{"term": {"_path":"http"}}`,
	},
	client.EventTypeTLS: {
		IndexSchemaCorelight: `{"term": {"_path":"ssl"}}`,
	},
}

var defaultFieldNames = map[client.EventType]map[IndexSchema]FieldNamesConfig{
	client.EventTypeDNS: {
		IndexSchemaECS: {
			EventIngested: "event.ingested",
			Timestamp:     "@timestamp",
			SrcIP:         []string{"source", "ip"},
			SrcPort:       []string{"source", "port"},
			Query:         []string{"dns", "question", "name"},
			QType:         []string{"dns", "question", "type"},
		},
	},
	client.EventTypeIP: {
		IndexSchemaECS: {
			EventIngested: "event.ingested",
			Timestamp:     "@timestamp",
			SrcIP:         []string{"source", "ip"},
			SrcPort:       []string{"source", "port"},
			DstIP:         []string{"destination", "ip"},
			DstPort:       []string{"destination", "port"},
			Protocol:      []string{"network", "protocol"},
			BytesIn:       []string{"destination", "bytes"},
			BytesOut:      []string{"source", "bytes"},
		},
	},
	client.EventTypeHTTP: {
		IndexSchemaECS: {
			EventIngested: "event.ingested",
			Timestamp:     "@timestamp",
			SrcIP:         []string{"source", "ip"},
			SrcPort:       []string{"source", "port"},
			URL:           []string{"url", "original"},
			Method:        []string{"http", "request", "method"},
			StatusCode:    []string{"http", "response", "status_code"},
			BytesIn:       []string{"destination", "bytes"},
			BytesOut:      []string{"source", "bytes"},
			UserAgent:     []string{"user_agent", "original"},
			ContentType:   []string{"http", "response", "mime_type"},
			Referrer:      []string{"http", "request", "referrer"},
		},
	},
	client.EventTypeTLS: {
		IndexSchemaECS: {
			EventIngested: "event.ingested",
			Timestamp:     "@timestamp",
			SrcIP:         []string{"source", "ip"},
			SrcPort:       []string{"source", "port"},
			DstIP:         []string{"destination", "ip"},
			DstPort:       []string{"destination", "port"},
			CertHash:      []string{"tls", "server", "hash", "sha1"},
			Issuer:        []string{"tls", "server", "issuer"},
			Subject:       []string{"tls", "server", "subject"},
			ValidFrom:     []string{"tls", "server", "not_before"},
			ValidTo:       []string{"tls", "server", "not_after"},
			JA3:           []string{"tls", "client", "ja3"},
			JA3s:          []string{"tls", "server", "ja3s"},
		},
	},
}

// FieldNamesConfig is a list of elastic document field names.
type FieldNamesConfig struct {
	EventIngested string `yaml:"event_ingested"`

	// DNS, IP, HTTP, TLS
	Timestamp string    `yaml:"timestamp"`
	SrcIP     FieldPath `yaml:"src_ip"` // required
	SrcPort   FieldPath `yaml:"src_port"`

	// DNS
	Query FieldPath `yaml:"query"` // required
	QType FieldPath `yaml:"qtype"`

	// IP, TLS
	DstIP   FieldPath `yaml:"dest_ip"` // required for IP
	DstPort FieldPath `yaml:"dest_port"`

	// IP
	Protocol FieldPath `yaml:"proto"`
	BytesIn  FieldPath `yaml:"bytes_in"`
	BytesOut FieldPath `yaml:"bytes_out"`

	// HTTP
	URL         FieldPath `yaml:"url"`
	Method      FieldPath `yaml:"method"`
	StatusCode  FieldPath `yaml:"status_code"`
	UserAgent   FieldPath `yaml:"user_agent"`
	ContentType FieldPath `yaml:"content_type"`
	Referrer    FieldPath `yaml:"referrer"`

	// TLS
	CertHash  FieldPath `yaml:"cert_hash"`
	Issuer    FieldPath `yaml:"issuer"`
	Subject   FieldPath `yaml:"subject"`
	ValidFrom FieldPath `yaml:"valid_from"`
	ValidTo   FieldPath `yaml:"valid_to"`
	JA3       FieldPath `yaml:"ja3"`
	JA3s      FieldPath `yaml:"ja3s"`
}

// SearchConfig contains all necessary information for
// running a periodic search to retrieve telemetry,
// extract required fields and send data to AlphaSOC API.
type SearchConfig struct {
	EventType       client.EventType  `yaml:"event_type"`
	Indices         []string          `yaml:"indices"`
	IndexSchema     IndexSchema       `yaml:"index_schema"`
	PollInterval    float64           `yaml:"poll_interval"`
	BatchSize       int               `yaml:"batch_size"`
	PITKeepAlive    float64           `yaml:"pit_keep_alive"`
	MustHaveFields  []string          `yaml:"must_have_fields"`
	SearchTerm      string            `yaml:"search_term"`
	TimestampFormat string            `yaml:"timestamp_format"`
	FieldNames      *FieldNamesConfig `yaml:"field_names"`

	// Final field names, merged defaults with user-provided.
	finalFieldNames *FieldNamesConfig
}

// Config keeps the main config of elasticsearch input.
type Config struct {
	Enabled  bool     `yaml:"enabled"`
	CloudID  string   `yaml:"cloud_id"`
	Hosts    []string `yaml:"hosts"`
	APIKey   string   `yaml:"api_key"`
	Username string   `yaml:"username"`
	Password string   `yaml:"password"`

	Searches []*SearchConfig `yaml:"searches"`
}

// UnmarshalYAML unmarshals elasticsearch nested document field paths into slice.
func (fp *FieldPath) UnmarshalYAML(value *yaml.Node) error {
	if value.Value == "" {
		return nil
	}

	s := strings.Split(value.Value, ".")
	*fp = s
	return nil
}

// Join returns a path joined by dots.
func (fp *FieldPath) Join() string {
	return strings.Join(*fp, ".")
}

// Validate returns error if the provided field schema is not supported.
func (fs IndexSchema) Validate() error {
	if fs != "" && fs != IndexSchemaCorelight && fs != IndexSchemaECS {
		return errors.New("field_schema must be [ecs|graylog|custom] or empty")
	}

	return nil
}

// IsEmpty returns true if all struct fields contain empty strings.
func (fnc FieldNamesConfig) IsEmpty() bool {
	return cmp.Equal(fnc, FieldNamesConfig{})
}

// Validate returns an error if the config isn't valid.
func (cfg *Config) Validate() error {
	if !cfg.Enabled {
		return nil
	}

	emptyCloudID := cfg.CloudID == ""
	emptyHosts := len(cfg.Hosts) == 0

	if (emptyCloudID && emptyHosts) || (!emptyCloudID && !emptyHosts) {
		return errors.New("either cloud_id or hosts field must be set")
	}

	emptyAPIKey := cfg.APIKey == ""
	emptyUsername := cfg.Username == ""
	if !emptyAPIKey && !emptyUsername {
		return errors.New("either apikey or username field must be set")
	}

	if len(cfg.Searches) == 0 {
		return errors.New("at least one search must be defined")
	}

	for _, searchcfg := range cfg.Searches {
		if err := searchcfg.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// Validate returns an error if the config isn't valid.
func (sc *SearchConfig) Validate() error {
	if sc.EventType == "" {
		return errors.New("event_type must not be empty")
	}

	var supported bool
	for _, setype := range SupportedEventTypes {
		if sc.EventType == setype {
			supported = true
			break
		}
	}

	if sc.PollInterval == 0 {
		sc.PollInterval = DefaultPollInterval
	}

	if sc.BatchSize == 0 {
		sc.BatchSize = DefaultBatchSize
	}

	if sc.PITKeepAlive == 0 {
		sc.PITKeepAlive = DefaultPITKeepAlive.Seconds()
	}

	if !supported {
		return fmt.Errorf("unsupported event_type: %v", sc.EventType)
	}

	if len(sc.Indices) == 0 {
		return fmt.Errorf("at least one index name is required")
	}

	if err := sc.IndexSchema.Validate(); err != nil {
		return err
	}

	searchTerm := sc.FinalSearchTerm()
	haveFields := sc.FinalMustHaveFields()

	if searchTerm == "" && len(haveFields) == 0 {
		return errors.New("search_term and/or must_have_fields are required")
	}

	if searchTerm != "" && !json.Valid([]byte(sc.FinalSearchTerm())) {
		return errors.New("search term must be valid json")
	}

	if err := sc.evaluateFieldNames(); err != nil {
		return err
	}

	fn := sc.FinalFieldNames()

	if err := fn.Validate(sc.EventType); err != nil {
		return err
	}

	return nil
}

// FinalMustHaveFields returns fields required to be present in a document
// containing particular telemetry.
func (sc *SearchConfig) FinalMustHaveFields() []string {
	if len(sc.MustHaveFields) > 0 {
		return sc.MustHaveFields
	}

	fields, ok := defaultMustHaveFields[sc.EventType]
	if !ok {
		return nil
	}

	return fields[sc.IndexSchema]
}

// FinalSearchTerm returns the search term set by the user, or
// a default one if not provided explicitly.
func (sc *SearchConfig) FinalSearchTerm() string {
	if sc.SearchTerm != "" {
		return sc.SearchTerm
	}

	terms, ok := defaultSearchTerms[sc.EventType]
	if !ok {
		return ""
	}

	return terms[sc.IndexSchema]
}

func (sc *SearchConfig) evaluateFieldNames() error {
	defaultFnc := FieldNamesConfig{}

	// Use schema field names if applicable
	defaultFncList, ok := defaultFieldNames[sc.EventType]
	if ok {
		defaultFnc = defaultFncList[sc.IndexSchema]
	}

	sc.finalFieldNames = &FieldNamesConfig{}

	// Merge schema field names with those provided by user, without overriding
	// the provided ones.
	if sc.FieldNames != nil {
		if err := mergo.Merge(sc.finalFieldNames, sc.FieldNames); err != nil {
			return err
		}
	}

	if err := mergo.Merge(sc.finalFieldNames, defaultFnc); err != nil {
		return err
	}

	return nil
}

// FinalFieldNames merges the field name mappings provided by user with
// default ones (if schema is set).
func (sc *SearchConfig) FinalFieldNames() *FieldNamesConfig {
	return sc.finalFieldNames
}

// EventFields returns the list of _source fields for a configured event type.
func (sc *SearchConfig) EventFields() ([]string, error) {
	fn := sc.finalFieldNames
	fields := []string{
		fn.SrcIP.Join(),
		fn.SrcPort.Join()}

	switch sc.EventType {
	case client.EventTypeDNS:
		fields = append(fields, fn.Query.Join(), fn.QType.Join())
	case client.EventTypeIP:
		fields = append(fields,
			fn.DstIP.Join(), fn.DstPort.Join(), fn.Protocol.Join(), fn.BytesIn.Join(), fn.BytesOut.Join())
	case client.EventTypeHTTP:
		fields = append(fields,
			fn.URL.Join(), fn.Method.Join(), fn.StatusCode.Join(), fn.UserAgent.Join())
	case client.EventTypeTLS:
		fields = append(fields,
			fn.DstIP.Join(), fn.DstPort.Join(), fn.CertHash.Join(), fn.Issuer.Join(),
			fn.Subject.Join(), fn.ValidFrom.Join(), fn.ValidTo.Join(), fn.JA3.Join(), fn.JA3s.Join())
	default:
		return nil, fmt.Errorf("event type %s is not supported", sc.EventType)
	}

	// Remove empty strings
	ret := make([]string, 0, len(fields))
	for _, f := range fields {
		if f != "" {
			ret = append(ret, f)
		}
	}

	if len(ret) == 0 {
		return nil, fmt.Errorf("invalid field mappings for event type %v: no mapped fields", sc.EventType)
	}

	return ret, nil
}

// Validate returns an error when at least one required field is missing.
func (fnc *FieldNamesConfig) Validate(eventType client.EventType) error {
	if fnc.EventIngested == "" {
		return errors.New("event_ingested is required")
	}

	if fnc.Timestamp == "" {
		return errors.New("timestamp is required")
	}

	if len(fnc.SrcIP) == 0 {
		return errors.New("src_ip is required")
	}

	switch eventType {
	case client.EventTypeDNS:
		if len(fnc.Query) == 0 {
			return errors.New("query is required")
		}
	case client.EventTypeIP:
		if len(fnc.DstIP) == 0 {
			return errors.New("dest_ip is required")
		}
	case client.EventTypeHTTP:
		if len(fnc.URL) == 0 {
			return errors.New("url is required")
		}
	}

	return nil
}

// ConfigFingerprint returns a unique string to identify search config for
// a given instance. It uses Cloud ID (or hosts), index names and event
// type to calculate the fingerprint.
func ConfigFingerprint(c *Config, s *SearchConfig) string {
	items := []string{c.CloudID, string(s.EventType)}
	items = append(items, c.Hosts...)
	items = append(items, s.Indices...)
	return fmt.Sprintf("%x", murmur3.StringSum64(strings.Join(items, "|")))
}
