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
	if len(cfg.ScopeConfig.Groups) != 1 {
		t.Fatalf("invalid number of scope groups - got %d; expected %d", len(cfg.ScopeConfig.Groups), 1)
	}
	group, ok := cfg.ScopeConfig.Groups["default"]
	if !ok {
		t.Fatalf("no default scope group")
	}
	if len(group.Networks) != 4 {
		t.Fatalf("invalid number of networks in default scope group - got %d; expected %d", len(group.Networks), 4)
	}
	if len(group.Exclude.Domains) != 4 {
		t.Fatalf("invalid number of excluded domains in default scope group - got %d; expected %d", len(group.Exclude.Domains), 4)
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
events:
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
groups:
  private:
    networks:
    - 10.0.0.0/8
    exclude:
      networks:
       - 10.1.0.0/16
      domains:
       - "alphasoc.com"
  public:
    networks:
    - 0.0.0.0/0
    exclude:
      networks:
       - 120.0.0.0/8
       - 8.8.8.8
      domains:
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
	if len(groups) != 2 {
		t.Fatalf("invalid groups length - got %d; exptected %d", len(groups), 2)
	}
	if _, ok := groups["private"]; !ok {
		t.Fatal("no private groups found")
	}
	if _, ok := groups["public"]; !ok {
		t.Fatal("no public groups found")
	}

	private := groups["private"]
	if len(private.Networks) != 1 || len(private.Exclude.Networks) != 1 || len(private.Exclude.Domains) != 1 {
		t.Fatal("invalid private groups data")
	}

	public := groups["public"]
	if len(public.Networks) != 1 || len(public.Exclude.Networks) != 2 || len(public.Exclude.Domains) != 1 {
		t.Fatal("invalid public groups data")
	}
}
