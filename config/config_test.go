package config

import (
	"io/ioutil"
	"log"
	"os"
	"path"
	"testing"
	"time"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
)

func checkDefaults(t *testing.T, cfg *Config) {
	if cfg.Engine.Host != "https://api.alphasoc.net" {
		t.Fatalf("invalid alphasoc host - got %v; expected %v", cfg.Engine.Host, "https://api.alphasoc.net")
	}
	if !cfg.Engine.Analyze.DNS {
		t.Fatalf("analyze dns set to false")
	}
	if !cfg.Engine.Analyze.IP {
		t.Fatalf("analyze ip set to false")
	}
	if cfg.Inputs.Sniffer.Enabled {
		t.Fatalf("sniffer is enabled")
	}
	if cfg.Outputs.File != "stderr" {
		t.Fatalf("invalid output file - got %s; expected %s", cfg.Outputs.File, "stderr")
	}
	if cfg.Outputs.Syslog.Port != 514 {
		t.Fatalf("invalid output syslog port - got %d; expected %d", cfg.Outputs.Syslog.Port, 514)
	}
	if cfg.Engine.Alerts.PollInterval != 5*time.Minute {
		t.Fatalf("invalid events poll interval - got %s; expected %s", cfg.Engine.Alerts.PollInterval, 5*time.Minute)
	}
	if cfg.Log.File != "stdout" {
		t.Fatalf("invalid log file - got %s; expected %s", cfg.Log.File, "stdout")
	}
	if cfg.Log.Level != "info" {
		t.Fatalf("invalid log level - got %s; expected %s", cfg.Log.Level, "info")
	}
	if cfg.DNSEvents.BufferSize != 65535 {
		t.Fatalf("invalid dns queries buffer size - got %d; expected %d", cfg.DNSEvents.BufferSize, 65535)
	}
	if cfg.DNSEvents.FlushInterval != 30*time.Second {
		t.Fatalf("invalid dns queries flush interval - got %s; expected %s", cfg.DNSEvents.FlushInterval, 30*time.Second)
	}
	if cfg.IPEvents.BufferSize != 65535 {
		t.Fatalf("invalid ip events buffer size - got %d; expected %d", cfg.IPEvents.BufferSize, 65535)
	}
	if cfg.IPEvents.FlushInterval != 30*time.Second {
		t.Fatalf("invalid ip events flush interval - got %s; expected %s", cfg.IPEvents.FlushInterval, 30*time.Second)
	}
	if l := len(cfg.ScopeConfig.Groups); l != 1 {
		t.Fatalf("invalid number of scope groups - got %d; expected %d", l, 1)
	}
	group, ok := cfg.ScopeConfig.Groups["default"]
	if !ok {
		t.Fatalf("no default scope group")
	}
	if l := len(group.InScope); l != 4 {
		t.Fatalf("invalid number of source networks in default scope group - got %d; expected %d", l, 4)
	}
	if l := len(group.TrustedIps); l != 10 {
		t.Fatalf("invalid number of trusted ips in default scope group - got %d; expected %d", l, 10)
	}
	if l := len(group.TrustedDomains); l != 4 {
		t.Fatalf("invalid number of excluded domains in default scope group - got %d; expected %d", l, 4)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := NewDefault()
	cfg.loadScopeConfig()
	checkDefaults(t, cfg)
}

func TestReadConfig(t *testing.T) {
	var content = []byte(`
engine:
  host: https://api.alphasoc.net
  api_key: test-api-key
  alerts:
    poll_interval: 5m
log:
  file: stdout
  level: info
data:
  file: nfr.data
outputs:
  enabled: true
  file: stderr
dns_events:
  buffer_size: 65535
  flush_interval: 30s
  failed:
    file: nfr.pcap`)
	f, err := ioutil.TempFile("", "nfr-config")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()

	if _, err = f.Write(content); err != nil {
		log.Fatal(err)
	}

	cfg, err := New(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	checkDefaults(t, cfg)
	if cfg.Engine.APIKey != "test-api-key" {
		t.Fatalf("invalid alphasoc api key - got %s; expected %s", cfg.Engine.APIKey, "test-api-key")
	}
}

func TestReadConfigStrict(t *testing.T) {
	// apiKey instead of api_key
	var content = []byte(`
engine:
  host: https://api.alphasoc.net
  apiKey: test-api-key`)

	f, err := os.OpenFile(path.Join(t.TempDir(), "nfr-config"), os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if _, err := f.Write(content); err != nil {
		t.Fatal(err)
	}

	var want *yaml.TypeError
	if _, err := New(f.Name()); !errors.As(err, &want) {
		t.Errorf("invalid error type - got %T; expected %T", err, want)
	}
}

func TestReadScope(t *testing.T) {
	var content = []byte(`
groups:
  private:
    in_scope:
      - 10.0.0.0/8
    out_scope:
      - 10.1.0.0/16
    trusted_ips:
      - 11.0.0.0/8
    trusted_domains:
      - alphasoc.com
  public:
    in_scope:
      - 0.0.0.0/0
    trusted_domains:
      - "*.io"`)
	f, err := ioutil.TempFile("", "nfr-scope")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()

	if _, err := f.Write(content); err != nil {
		log.Fatal(err)
	}

	var cfg Config
	cfg.Scope.File = f.Name()
	if err := cfg.loadScopeConfig(); err != nil {
		t.Fatal(err)
	}

	groups := cfg.ScopeConfig.Groups
	if l := len(groups); l != 2 {
		t.Fatalf("invalid groups length - got %d; exptected %d", l, 2)
	}
	if _, ok := groups["private"]; !ok {
		t.Fatal("no private groups found")
	}
	if _, ok := groups["public"]; !ok {
		t.Fatal("no public groups found")
	}

	private := groups["private"]
	if len(private.InScope) != 1 {
		t.Fatal("invalid private group source network include")
	}
	if len(private.OutScope) != 1 {
		t.Fatal("invalid private group source network exclude")
	}
	if len(private.TrustedIps) != 1 {
		t.Fatal("invalid private group destination network include")
	}
	if len(private.TrustedDomains) != 1 {
		t.Fatal("invalid private group domains exclude")
	}
}

func TestReadScopeStrict(t *testing.T) {
	// group instead of groups
	var content = []byte(`
group:
  private:
    in_scope:
      - 10.0.0.0/8
    out_scope:
      - 10.1.0.0/16
    trusted_ips:
      - 11.0.0.0/8
    trusted_domains:
      - alphasoc.com
  public:
    in_scope:
      - 0.0.0.0/0
    trusted_domains:
      - "*.io"`)

	f, err := os.OpenFile(path.Join(t.TempDir(), "nfr-scope"), os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if _, err := f.Write(content); err != nil {
		t.Fatal(err)
	}

	var cfg Config
	cfg.Scope.File = f.Name()

	var want *yaml.TypeError
	if err := cfg.loadScopeConfig(); !errors.As(err, &want) {
		t.Errorf("invalid error type - got %T; expected %T", err, want)
	}
}
