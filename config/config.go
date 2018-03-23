package config

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/alphasoc/nfr/utils"
	yaml "gopkg.in/yaml.v2"
)

// Monitor is a config for monitoring files
type Monitor struct {
	Format string `yaml:"format"`
	Type   string `yaml:"type"`
	File   string `yaml:"file"`
}

type group struct {
	Label          string   `yaml:"label"`
	InScope        []string `yaml:"in_scope"`
	OutScope       []string `yaml:"out_scope"`
	TrustedDomains []string `yaml:"trusted_domains"`
	TrustedIps     []string `yaml:"trusted_ips"`
}

// Config for nfr
type Config struct {
	// AlphaSOC server configuration
	Engine struct {
		// AlphaSOC host server.
		// Default: https://api.alpahsoc.net
		Host string `yaml:"host,omitempty"`

		// AlphaSOC api key. Required for start sending dns queries.
		APIKey string `yaml:"api_key,omitempty"`

		// events to analize by AlphaSOC Engine.
		Analyze struct {
			// Enable (true) or disable (false) DNS event processing
			// Default: true
			DNS bool `yaml:"dns"`
			// Enable (true) or disable (false) IP event processing
			// Default: true
			IP bool `yaml:"ip"`
		} `yaml:"analyze"`

		// Alerts configuration (generated by Engine).
		Alerts struct {
			// Interval for polling alerts from AlphaSOC Engine.
			// Default: 5m
			PollInterval time.Duration `yaml:"poll_interval,omitempty"`
		} `yaml:"alerts,omitempty"`
	} `yaml:"engine"`

	// Inputs describes where collects network traffic to score from
	Inputs struct {
		// Sniffer configuration.
		Sniffer struct {
			// Enabled if set to true nfr will run sniffer.
			Enabled bool `yaml:"enabled"`
			// Interface on which nfr should listen.
			// Default: (none)
			Interface string `yaml:"interface,omitempty"`

			// Interface physical hardware address.
			HardwareAddr net.HardwareAddr `yaml:"-"`
		} `yaml:"sniffer,omitempty"`

		// Monitors keeps list of log files to monitor.
		Monitors []Monitor `yaml:"monitor"`
	} `yaml:"inputs"`

	// Outputs describes where should send the alerts generated by the Analytics Engine.
	Outputs struct {
		// Enabled if set to true nfr will gather alerts.
		Enabled bool `yaml:"enabled"`

		Graylog struct {
			URI   string `yaml:"uri"`
			Level int    `yaml:"level"`
		} `yaml:"graylog"`

		// File where to store alerts. If not set then none alerts will be retrieved.
		// To print alerts to console use two special outputs: stderr or stdout
		// Default: "stderr"
		File string `yaml:"file,omitempty"`
	} `yaml:"outputs"`

	// Log configuration.
	Log struct {
		// File to which nfr should log.
		// To print log to console use two special outputs: stderr or stdout
		// Default: stdout
		File string `yaml:"file,omitempty"`

		// Log level. Possibles values are: debug, info, warn, error
		// Default: info
		Level string `yaml:"level,omitempty"`
	} `yaml:"log,omitempty"`

	// Internal nfr data.
	Data struct {
		// File for internal data.
		// Default:
		// - linux /run/nfr.data
		// - win %AppData%/nfr.data
		File string `yaml:"file,omitempty"`
	} `yaml:"data,omitempty"`

	// Scope groups file.
	// The IP exclusion list is used to prune 'noisy' hosts, such as mail servers
	// or workstations within the IP ranges provided.
	// Finally, the domain scope is used to specify internal and trusted domains and
	// hostnames (supporting wildcards, e.g. *.google.com) to ignore.
	// If you do not scope domains, local DNS traffic will be forwarded to the AlphaSOC Engine for scoring.
	Scope struct {
		// File with scope groups . See ScopeConfig for more info.
		// Default: (none)
		File string `yaml:"file,omitempty"`
	} `yaml:"scope,omitempty"`

	// ScopeConfig is loaded when Scope.File is not empty or the default one is used.
	ScopeConfig struct {
		Groups map[string]group `yaml:"groups,omitempty"`
	} `yaml:"-"`

	// DNS queries configuration.
	DNSEvents struct {
		// Buffer size for dns queries queue. If the size will be exceded then
		// nfr send quries to AlphaSOC Engine. Default: 65535
		BufferSize int `yaml:"buffer_size,omitempty"`
		// Interval for flushing dns queries to AlphaSOC Engine. Default: 30s
		FlushInterval time.Duration `yaml:"flush_interval,omitempty"`

		// Queries that were unable to send to AlphaSOC Engine.
		// If file is set, then unsent queries will be saved on disk and send again.
		// Pcap format is used to store queries. You can view it in
		// programs like tcpdump or whireshark.
		Failed struct {
			// File to store DNS Queries. Default: (none)
			File string `yaml:"file,omitempty"`
		} `yaml:"failed,omitempty"`
	} `yaml:"dns_events,omitempty"`

	// IP events configuration.
	IPEvents struct {
		// Buffer size for ip events queue. If the size will be exceded then
		// nfr send quries to AlphaSOC Engine. Default: 65535
		BufferSize int `yaml:"buffer_size,omitempty"`
		// Interval for flushing ip events to AlphaSOC Engine. Default: 30s
		FlushInterval time.Duration `yaml:"flush_interval,omitempty"`

		// Events that were unable to send to AlphaSOC Engine.
		// If file is set, then unsent events will be saved on disk and send again.
		// Pcap format is used to store events. You can view it in
		// programs like tcpdump or whireshark.
		Failed struct {
			// File to store ip events. Default: (none)
			File string `yaml:"file,omitempty"`
		} `yaml:"failed,omitempty"`
	} `yaml:"ip_events,omitempty"`
}

// New reads the config from file location. If file is not set
// then it tries to read from default location, if this fails, then
// default config is returned.
func New(file ...string) (*Config, error) {
	var (
		cfg     = NewDefault()
		content []byte
		err     error
	)

	if len(file) > 1 {
		panic("config: too many files")
	}

	filename := ""
	if len(file) == 1 {
		filename = file[0]
	}

	if filename != "" {
		content, err = ioutil.ReadFile(file[0])
		if err != nil {
			return nil, fmt.Errorf("config: can't read file %s", err)
		}
	}

	if err := cfg.load(content); err != nil {
		return nil, fmt.Errorf("config: can't load file %s", err)
	}

	if err := cfg.loadScopeConfig(); err != nil {
		return nil, err
	}

	if filename == "" {
		// do not validate default config
		return cfg, nil
	}

	return cfg, cfg.validate()
}

// NewDefault returns config with set defaults.
func NewDefault() *Config {
	cfg := &Config{}
	cfg.Engine.Host = "https://api.alphasoc.net"
	cfg.Engine.Analyze.DNS = true
	cfg.Engine.Analyze.IP = true
	cfg.Engine.Alerts.PollInterval = 5 * time.Minute

	cfg.Inputs.Sniffer.Enabled = true
	cfg.Data.File = "/run/nfr.data"
	if runtime.GOOS == "windows" {
		cfg.Data.File = path.Join(os.Getenv("AppData"), "nfr.data")
	}

	cfg.Outputs.Enabled = true
	cfg.Outputs.Graylog.Level = 1
	cfg.Outputs.File = "stderr"
	cfg.Log.File = "stdout"
	cfg.Log.Level = "info"

	cfg.DNSEvents.BufferSize = 65535
	cfg.DNSEvents.FlushInterval = 30 * time.Second
	cfg.IPEvents.BufferSize = 65535
	cfg.IPEvents.FlushInterval = 30 * time.Second
	return cfg
}

// Save saves config to file.
func (cfg *Config) Save(file string) error {
	if err := os.MkdirAll(filepath.Dir(file), os.ModeDir); err != nil {
		return err
	}

	content, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(file, content, 0666)
}

// HasOutputs returns true if at least one output is configured and enabled.
func (cfg *Config) HasOutputs() bool {
	return cfg.Outputs.Enabled && (cfg.Outputs.File != "" || cfg.Outputs.Graylog.URI != "")
}

// HasInputs returns true if at least one input is configured and enabled.
func (cfg *Config) HasInputs() bool {
	return cfg.Inputs.Sniffer.Enabled || len(cfg.Inputs.Monitors) > 0
}

// load config from content.
func (cfg *Config) load(content []byte) error {
	return yaml.UnmarshalStrict(content, cfg)
}

func (cfg *Config) validate() error {
	if !(cfg.HasInputs() || cfg.HasOutputs()) {
		return fmt.Errorf("config: at least one input or output must be enabledt")
	}

	// special case if there are only inputs and analyze set to false.
	if !cfg.HasOutputs() && cfg.HasInputs() && !(cfg.Engine.Analyze.DNS || cfg.Engine.Analyze.IP) {
		return fmt.Errorf("config: only inputs is configured but all analyze events is not set to false")
	}

	if cfg.Inputs.Sniffer.Enabled {
		if cfg.Inputs.Sniffer.Interface != "" {
			iface, err := net.InterfaceByName(cfg.Inputs.Sniffer.Interface)
			if err != nil {
				return fmt.Errorf("config: can't open interface %s: %s", cfg.Inputs.Sniffer.Interface, err)
			}
			cfg.Inputs.Sniffer.HardwareAddr = iface.HardwareAddr
		} else {
			iface, err := utils.InterfaceWithPublicIP()
			if err != nil {
				return fmt.Errorf("config: can't find an interface for sniffing: %s", err)
			}
			cfg.Inputs.Sniffer.Interface = iface.Name
			cfg.Inputs.Sniffer.HardwareAddr = iface.HardwareAddr
		}
	}

	if err := validateFilename(cfg.Log.File, true); err != nil {
		return fmt.Errorf("config: %s", err)
	}
	if cfg.Log.Level != "debug" &&
		cfg.Log.Level != "info" &&
		cfg.Log.Level != "warn" &&
		cfg.Log.Level != "error" {
		return fmt.Errorf("config: invalid %s log level", cfg.Log.Level)
	}

	if err := validateFilename(cfg.Data.File, false); err != nil {
		return err
	}

	if cfg.Outputs.Graylog.URI != "" {
		parsedURI, err := url.Parse(cfg.Outputs.Graylog.URI)
		if err != nil {
			return fmt.Errorf("config: invalid graylog uri %s", err)
		}

		if _, _, err := net.SplitHostPort(parsedURI.Host); err != nil {
			return fmt.Errorf("config: missing port in graylog uri %s", cfg.Outputs.Graylog.URI)
		}
	}

	if cfg.Outputs.Graylog.Level < 0 || cfg.Outputs.Graylog.Level > 7 {
		return fmt.Errorf("config: invalid graylog alert level %d", cfg.Outputs.Graylog.Level)
	}

	if cfg.Outputs.File != "" {
		if err := validateFilename(cfg.Outputs.File, true); err != nil {
			return fmt.Errorf("config: %s", err)
		}
	}

	if cfg.Engine.Alerts.PollInterval < 5*time.Second {
		return fmt.Errorf("config: events poll interval must be at least 5s")
	}

	if cfg.DNSEvents.BufferSize < 64 {
		return fmt.Errorf("config: queries buffer size must be at least 64")
	}

	if cfg.DNSEvents.FlushInterval < 5*time.Second {
		return fmt.Errorf("config: queries flush interval must be at least 5s")
	}

	if cfg.DNSEvents.Failed.File != "" {
		if err := validateFilename(cfg.DNSEvents.Failed.File, false); err != nil {
			return fmt.Errorf("config: %s", err)
		}
	}

	if cfg.IPEvents.BufferSize < 64 {
		return fmt.Errorf("config: queries buffer size must be at least 64")
	}

	if cfg.IPEvents.FlushInterval < 5*time.Second {
		return fmt.Errorf("config: queries flush interval must be at least 5s")
	}

	if cfg.IPEvents.Failed.File != "" {
		if err := validateFilename(cfg.IPEvents.Failed.File, false); err != nil {
			return fmt.Errorf("config: %s", err)
		}
	}

	for _, monitor := range cfg.Inputs.Monitors {
		if monitor.Format != "bro" && monitor.Format != "suricata" && monitor.Format != "msdns" &&
			monitor.Format != "syslog-named" {
			return fmt.Errorf("config: unknown format %s for monitoring", monitor.Format)
		}
		if monitor.Type != "dns" && monitor.Type != "ip" {
			return fmt.Errorf("config: unknown type %s for monitoring", monitor.Type)
		}
		if monitor.Type == "ip" && monitor.Format != "bro" {
			return fmt.Errorf("config: unsupported type %s for %s format", monitor.Type, monitor.Format)
		}
	}

	return nil
}

// validateFilename checks if file can be created.
func validateFilename(file string, noFileOutput bool) error {
	if noFileOutput && (file == "stdout" || file == "stderr") {
		return nil
	}

	dir := path.Dir(file)
	stat, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("can't stat %s directory: %s", dir, err)
	}
	if !stat.IsDir() {
		return fmt.Errorf("%s is not directory", dir)
	}

	stat, err = os.Stat(file)
	if err == nil && !stat.Mode().IsRegular() {
		return fmt.Errorf("%s is not regular file", file)
	}
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("can't stat %s file: %s", file, err)
	}
	return nil
}

// load scope config from yaml file, or use default one.
func (cfg *Config) loadScopeConfig() (err error) {
	if cfg.Scope.File == "" {
		cfg.ScopeConfig.Groups = map[string]group{
			"default": {
				Label:          "Default",
				InScope:        []string{"10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12", "fc00::/7"},
				TrustedDomains: []string{"*.arpa", "*.lan", "*.local", "*.internal"},
				TrustedIps:     []string{"10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12", "fc00::/7"},
			},
		}
	} else {
		content, err := ioutil.ReadFile(cfg.Scope.File)
		if err != nil {
			return fmt.Errorf("scope config: %s ", err)
		}

		if err := yaml.UnmarshalStrict(content, &cfg.ScopeConfig); err != nil {
			return fmt.Errorf("parse scope config: %s ", err)
		}
	}

	return cfg.validateScopeConfig()
}

func (cfg *Config) validateScopeConfig() error {
	testCidr := func(cidrs []string) error {
		for _, cidr := range cidrs {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				return fmt.Errorf("parse scope config: %s is not cidr", cidr)
			}
		}
		return nil
	}

	for _, group := range cfg.ScopeConfig.Groups {
		if err := testCidr(group.InScope); err != nil {
			return err
		}
		if err := testCidr(group.OutScope); err != nil {
			return err
		}
		if err := testCidr(group.TrustedIps); err != nil {
			return err
		}

		for _, domain := range group.TrustedDomains {
			// TrimPrefix *. for multimatch domain
			if !utils.IsDomainName(domain) &&
				!utils.IsDomainName(strings.TrimPrefix(domain, "*.")) {
				return fmt.Errorf("parse scope config: %s is not valid domain name", domain)
			}
		}
	}

	return nil
}
