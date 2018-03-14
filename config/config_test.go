package config

import (
	"io/ioutil"
	"log"
	"os"
	"testing"
	"time"
)

func checkDefaults(t *testing.T, cfg *Config) {
	if cfg.Alphasoc.Host != "https://api.alphasoc.net" {
		t.Fatalf("invalid alphasoc host - got %v; expected %v", cfg.Alphasoc.Host, "https://api.alphasoc.net")
	}
	if !cfg.Alphasoc.Analyze.DNS {
		t.Fatalf("analyze dns set to false")
	}
	if !cfg.Alphasoc.Analyze.IP {
		t.Fatalf("analyze ip set to false")
	}
	if len(cfg.Network.DNS.Protocols) != 1 && cfg.Network.DNS.Protocols[0] != "udp" {
		t.Fatalf("invalid network protocols - got %v; expected %v", cfg.Network.DNS.Protocols, []string{"udp"})
	}
	if cfg.Network.DNS.Port != 53 {
		t.Fatalf("invalid network port - got %d; expected %d", cfg.Network.DNS.Port, 53)
	}
	if cfg.Alerts.File != "stderr" {
		t.Fatalf("invalid events file - got %s; expected %s", cfg.Alerts.File, "stderr")
	}
	if cfg.Alerts.PollInterval != 5*time.Minute {
		t.Fatalf("invalid events poll interval - got %s; expected %s", cfg.Alerts.PollInterval, 5*time.Minute)
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

	if l := len(cfg.ScopeConfig.DNS.Groups); l != 1 {
		t.Fatalf("invalid number of scope groups - got %d; expected %d", l, 1)
	}
	group, ok := cfg.ScopeConfig.DNS.Groups["default"]
	if !ok {
		t.Fatalf("no default scope group")
	}

	if l := len(group.Networks.Source.Include); l != 4 {
		t.Fatalf("invalid number of source networks in default scope group - got %d; expected %d", l, 4)
	}
	if l := len(group.Networks.Destination.Include); l != 2 {
		t.Fatalf("invalid number of destination networks in default scope group - got %d; expected %d", l, 2)
	}
	if l := len(group.Domains.Exclude); l != 4 {
		t.Fatalf("invalid number of excluded domains in default scope group - got %d; expected %d", l, 4)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := newDefaultConfig()
	cfg.loadScopeConfig()
	checkDefaults(t, cfg)
}

func TestReadConfig(t *testing.T) {
	var content = []byte(`
alphasoc:
  host: https://api.alphasoc.net
  api_key: test-api-key
network:
  dns:
    protocols:
      - udp
    port: 53
log:
  file: stdout
  level: info
data:
  file: nfr.data
alerts:
  file: stderr
  poll_interval: 5m
dns_queries:
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
	if cfg.Alphasoc.APIKey != "test-api-key" {
		t.Fatalf("invalid alphasoc api key - got %s; expected %s", cfg.Alphasoc.APIKey, "test-api-key")
	}
}

func TestReadScope(t *testing.T) {
	var content = []byte(`
dns:
  groups:
    private:
      networks:
        source:
          include:
            - 10.0.0.0/8
          exclude:
            - 10.1.0.0/16
        destination:
          include:
            - 11.0.0.0/8
          exclude:
            - 11.1.0.0/16
      domains:
        exclude:
         - alphasoc.com
    public:
      networks:
        source:
          include:
            - 0.0.0.0/0
          exclude:
            - 120.0.0.0/8
            - 8.8.8.8
      domains:
        exclude:
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

	groups := cfg.ScopeConfig.DNS.Groups
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
	if len(private.Networks.Source.Include) != 1 {
		t.Fatal("invalid private group source network include")
	}
	if len(private.Networks.Source.Exclude) != 1 {
		t.Fatal("invalid private group source network exclude")
	}
	if len(private.Networks.Destination.Include) != 1 {
		t.Fatal("invalid private group destination network include")
	}
	if len(private.Networks.Destination.Exclude) != 1 {
		t.Fatal("invalid private group destinatio network exclude")
	}
	if len(private.Domains.Exclude) != 1 {
		t.Fatal("invalid private group domains exclude")
	}
}
