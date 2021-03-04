package elastic

import (
	"testing"

	"github.com/alphasoc/nfr/client"
	"github.com/stretchr/testify/require"
)

func TestEmptyFieldNamesConfig(t *testing.T) {
	fnc := FieldNamesConfig{}
	require.True(t, fnc.IsEmpty(), "expected fnc to be empty")

	fnc.QType = []string{"text"}
	require.False(t, fnc.IsEmpty(), "expected fnc to be not empty")
}

func TestInvalidConfig(t *testing.T) {
	searchcfg := &SearchConfig{
		EventType:   "dns",
		Indices:     []string{"filebeat-*"},
		SearchTerm:  "{}",
		IndexSchema: "ecs",
	}

	// Create valid config
	cfg := &Config{
		Enabled:  true,
		Searches: []*SearchConfig{searchcfg},
	}

	cfg.CloudID = "randomstring"
	cfg.APIKey = "foobar"

	require.NoError(t, cfg.Validate())

	// Remove elastic address and see if it fails
	cfg.CloudID = ""
	require.Error(t, cfg.Validate(), "empty cloud_id and hosts shouldn't validate")

	// Set hosts and it should validate. It doesn't matter it's not a valid FQDN --
	// this is taken care of by elasticsearch client.
	cfg.Hosts = []string{"randomstring"}
	require.NoError(t, cfg.Validate(), "host is set, expected valid config")

	cfg.APIKey = ""
	require.Error(t, cfg.Validate(), "both api key and username are empty, which should be invalid")

	cfg.Username = "bob"
	require.NoError(t, cfg.Validate(), "username is set, expected valid config")

	cfg.Searches = nil
	require.Error(t, cfg.Validate(), "no defined searches should be invalid")

	// Append invalid search config. It should not validate
	emptysc := &SearchConfig{}
	cfg.Searches = []*SearchConfig{emptysc}
	require.Error(t, cfg.Validate(), "it should not validate with an invalid search config")
}

func TestInvalidSearchConfig(t *testing.T) {
	cfg := SearchConfig{
		EventType:   "dns",
		Indices:     []string{"filebeat-*"},
		SearchTerm:  "",
		IndexSchema: "ecs",
	}

	require.NoError(t, cfg.Validate(), "it should validate")

	cfg.EventType = "fsdfkjsdf"
	require.Error(t, cfg.Validate(), "it should have invalid event type")

	cfg.EventType = ""
	require.Error(t, cfg.Validate(), "event type should be required")

	cfg.EventType = client.EventTypeDNS
	require.NoError(t, cfg.Validate(), "it should validate")

	cfg.Indices = nil
	require.Error(t, cfg.Validate(), "index name is required")

	cfg.Indices = []string{"filebeat-*"}
	cfg.IndexSchema = "sfhsdjfhwer"
	require.Error(t, cfg.Validate(), "invalid field schema")

	// Set index schema
	cfg.IndexSchema = IndexSchemaECS
	require.NoError(t, cfg.Validate(), "it should validate with correct schema")

	// It should use default search terms for zeek schema
	require.NotEmpty(t, cfg.FinalSearchTerm(), "it should have default search term for given schema")

	cfg.SearchTerm = "{}"
	require.Equal(t, cfg.SearchTerm, cfg.FinalSearchTerm(), "custom search term should override default")
	require.NoError(t, cfg.Validate(), "it should validate with correct schema")

	cfg.IndexSchema = IndexSchemaCustom
	cfg.SearchTerm = ""
	require.Empty(t, cfg.FinalSearchTerm(), "custom schema should have no default search term")
	require.Error(t, cfg.Validate(), "custom schema should have no default search term")

	cfg.SearchTerm = ":342==_-@!"
	require.Error(t, cfg.Validate(), "search term should be valid json")

	cfg.SearchTerm = ""
	cfg.IndexSchema = IndexSchemaECS
	require.NoError(t, cfg.Validate(), "it should validate")

	require.NoError(t, cfg.evaluateFieldNames())
	ffn := cfg.FinalFieldNames()
	require.Equal(t, defaultFieldNames[client.EventTypeDNS][IndexSchemaECS].SrcIP,
		ffn.SrcIP, "src_ip field name should be equal to the default one")

	// Override field name
	cfg.FieldNames = &FieldNamesConfig{SrcIP: []string{"foobar"}}
	require.NoError(t, cfg.evaluateFieldNames())
	ffn = cfg.FinalFieldNames()
	require.Equal(t, cfg.FieldNames.SrcIP,
		ffn.SrcIP, "src_ip field name should be equal to the overriden one")
}

func TestFieldNamesConfig(t *testing.T) {
	sc := &SearchConfig{EventType: client.EventTypeDNS, FieldNames: &FieldNamesConfig{}}

	require.NoError(t, sc.evaluateFieldNames())
	ffs := sc.FinalFieldNames()

	require.Error(t, ffs.Validate(sc.EventType), "required fields should be missing")

	// Add required fields one by one. Validation should fail until all required
	// fields are present.
	sc.FieldNames.EventIngested = "event.ingested"

	require.NoError(t, sc.evaluateFieldNames())
	ffs = sc.FinalFieldNames()
	require.Error(t, ffs.Validate(sc.EventType), "required fields should be missing")

	sc.FieldNames.Timestamp = "@timestamp"
	require.NoError(t, sc.evaluateFieldNames())
	ffs = sc.FinalFieldNames()
	require.Error(t, ffs.Validate(sc.EventType), "required fields should be missing")

	sc.FieldNames.SrcIP = []string{"src", "ip"}
	require.NoError(t, sc.evaluateFieldNames())
	ffs = sc.FinalFieldNames()
	require.Error(t, ffs.Validate(sc.EventType), "required fields should be missing")

	// This is the last remaining required fields for EventTypeDNS
	sc.FieldNames.Query = []string{"dns", "question", "name"}
	require.NoError(t, sc.evaluateFieldNames())
	ffs = sc.FinalFieldNames()
	require.NoError(t, ffs.Validate(sc.EventType), "final field names should return no error")

	sc.FieldNames.Query = nil
	require.NoError(t, sc.evaluateFieldNames())
	ffs = sc.FinalFieldNames()
	require.Error(t, ffs.Validate(sc.EventType), "a required field is missing")

	sc.EventType = client.EventTypeIP
	sc.FieldNames.DstIP = []string{"destination", "ip"}
	require.NoError(t, sc.evaluateFieldNames())
	ffs = sc.FinalFieldNames()
	require.NoError(t, ffs.Validate(sc.EventType), "final field names should return no error")
}
