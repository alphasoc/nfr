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

// Config for nfr
type Config struct {
	// AlphaSOC server configuration
	Alphasoc struct {
		// AlphaSOC host server. Default: https://api.alpahsoc.net
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
	} `yaml:"alphasoc,omitempty"`

	// Network interface configuration.
	Network struct {
		// Interface on which nfr should listen.
		// Default: (none)
		Interface string `yaml:"interface"`

		// Interface physical hardware address.
		HardwareAddr net.HardwareAddr `yaml:"-"`

		// DNS network configuration
		DNS struct {
			// Protocols on which nfr should listen.
			// Possible values are udp and tcp.
			// Default: [udp]
			Protocols []string `yaml:"protocols,omitempty"`
			// Port on which nfr should listen.
			// Default: 53
			Port int `yaml:"port,omitempty"`
		} `yaml:"dns,omitempty"`
	} `yaml:"network,omitempty"`

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

	// ScopeConfig is loaded when Scope.File is not empty or the default one is used:
	// groups:
	//   default:
	//     networks:
	//     - 10.0.0.0/8
	//     - 192.168.0.0/16
	//     - 172.16.0.0/12
	//     exclude:
	//       domains:
	//        - "*.arpa"
	//        - "*.lan"
	//        - "*.local"
	//        - "*.internal"
	ScopeConfig struct {
		Groups map[string]struct {
			// If packet source ip match this network, then the packet will be send to analyze.
			Networks []string `yaml:"networks,omitempty"`
			Exclude  struct {
				// Exclueds is list of network address excludes from monitoring networks.
				// This list has higher priority then networks list
				Networks []string `yaml:"networks,omitempty"`
				// Domains is list of fqdn. If dns packet fqdn match any
				// of this domains , then the packet will not be send to analyze.
				Domains []string `yaml:"domains,omitempty"`
			} `yaml:"exclude,omitempty"`
		} `yaml:"groups,omitempty"`
	} `yaml:"-"`

	// AlphaSOC alerts configuration.
	Alerts struct {
		Graylog struct {
			URI   string `yaml:"uri"`
			Level int    `yaml:"level"`
		} `yaml:"graylog"`

		// File where to store alerts. If not set then none alerts will be retrieved.
		// To print alerts to console use two special outputs: stderr or stdout
		// Default: "stderr"
		File string `yaml:"file,omitempty"`

		// Interval for polling alerts from AlphaSOC Engine. Default: 5m
		PollInterval time.Duration `yaml:"poll_interval,omitempty"`
	} `yaml:"alerts,omitempty"`

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
	} `yaml:"dns_queries,omitempty"`

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

	Monitors []Monitor `yaml:"monitor"`
}

// New reads the config from file location. If file is not set
// then it tries to read from default location, if this fails, then
// default config is returned.
func New(file ...string) (*Config, error) {
	var (
		cfg     = newDefaultConfig()
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

// load config from content.
func (cfg *Config) load(content []byte) error {
	return yaml.UnmarshalStrict(content, cfg)
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

// newDefaultConfig returns config with set defaults.
func newDefaultConfig() *Config {
	cfg := &Config{}
	cfg.Alphasoc.Host = "https://api.alphasoc.net"
	cfg.Alphasoc.Analyze.DNS = true
	cfg.Alphasoc.Analyze.IP = true
	cfg.Network.DNS.Protocols = []string{"udp"}
	cfg.Network.DNS.Port = 53
	cfg.Data.File = "/run/nfr.data"
	if runtime.GOOS == "windows" {
		appData := os.Getenv("AppData")
		cfg.Data.File = path.Join(appData, "nfr.data")
	}
	cfg.Alerts.Graylog.Level = 1
	cfg.Alerts.File = "stderr"
	cfg.Alerts.PollInterval = 5 * time.Minute
	cfg.Log.File = "stdout"
	cfg.Log.Level = "info"
	cfg.DNSEvents.BufferSize = 65535
	cfg.DNSEvents.FlushInterval = 30 * time.Second
	cfg.IPEvents.BufferSize = 65535
	cfg.IPEvents.FlushInterval = 30 * time.Second
	return cfg
}

func (cfg *Config) validate() error {
	if cfg.Network.Interface != "" {
		iface, err := net.InterfaceByName(cfg.Network.Interface)
		if err != nil {
			return fmt.Errorf("config: can't open interface %s: %s", cfg.Network.Interface, err)
		}
		cfg.Network.HardwareAddr = iface.HardwareAddr
	}

	if len(cfg.Network.DNS.Protocols) == 0 {
		return fmt.Errorf("config: empty protocol list")
	}

	if len(cfg.Network.DNS.Protocols) > 2 {
		return fmt.Errorf("config: too many protocols in list (only tcp and udp are available)")
	}

	for _, proto := range cfg.Network.DNS.Protocols {
		if proto != "udp" && proto != "tcp" {
			return fmt.Errorf("config: invalid protocol %q name (only tcp and udp are available)", proto)
		}
	}

	if cfg.Network.DNS.Port <= 0 || cfg.Network.DNS.Port > 65535 {
		return fmt.Errorf("config: invalid %d port number", cfg.Network.DNS.Port)
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

	if cfg.Alerts.Graylog.URI != "" {
		parsedURI, err := url.Parse(cfg.Alerts.Graylog.URI)
		if err != nil {
			return fmt.Errorf("config: invalid graylog uri %s", err)
		}

		if _, _, err := net.SplitHostPort(parsedURI.Host); err != nil {
			return fmt.Errorf("config: missing port in graylog uri %s", cfg.Alerts.Graylog.URI)
		}
	}

	if cfg.Alerts.Graylog.Level < 0 || cfg.Alerts.Graylog.Level > 7 {
		return fmt.Errorf("config: invalid graylog alert level %d", cfg.Alerts.Graylog.Level)
	}

	if cfg.Alerts.File != "" {
		if err := validateFilename(cfg.Alerts.File, true); err != nil {
			return fmt.Errorf("config: %s", err)
		}
	}

	if cfg.Alerts.PollInterval < 5*time.Second {
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

	for _, monitor := range cfg.Monitors {
		if monitor.Format != "bro" && monitor.Format != "suricata" && monitor.Format != "msdns" {
			return fmt.Errorf("config: unknown format %s for monitoring", monitor.Format)
		}
		if monitor.Type != "dns" && monitor.Type != "ip" {
			return fmt.Errorf("config: unknown type %s for monitoring", monitor.Type)
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

const defaultScope = `
groups:
  default:
    networks:
    - 10.0.0.0/8
    - 192.168.0.0/16
    - 172.16.0.0/12
    - fc00::/7
    exclude:
      domains:
       - "*.arpa"
       - "*.lan"
       - "*.local"
       - "*.internal"
      networks:
`

// load scope config from yaml file, or use default one.
func (cfg *Config) loadScopeConfig() (err error) {
	var content = []byte(defaultScope)
	if cfg.Scope.File != "" {
		content, err = ioutil.ReadFile(cfg.Scope.File)
		if err != nil {
			return fmt.Errorf("scope config: %s ", err)
		}
	}

	if err := yaml.Unmarshal(content, &cfg.ScopeConfig); err != nil {
		return fmt.Errorf("parse scope config: %s ", err)
	}

	return cfg.validateScopeConfig()
}

func (cfg *Config) validateScopeConfig() error {
	for _, group := range cfg.ScopeConfig.Groups {
		for _, n := range group.Networks {
			if _, _, err := net.ParseCIDR(n); err != nil {
				return fmt.Errorf("parse scope config: %s is not cidr", n)
			}
		}

		for _, n := range group.Exclude.Networks {
			_, _, err := net.ParseCIDR(n)
			ip := net.ParseIP(n)
			if err != nil && ip == nil {
				return fmt.Errorf("parse scope config: %s is not cidr nor ip", n)
			}
		}

		for _, domain := range group.Exclude.Domains {
			// TrimPrefix *. for multimatch domain
			if !utils.IsDomainName(domain) &&
				!utils.IsDomainName(strings.TrimPrefix(domain, "*.")) {
				return fmt.Errorf("parse scope config: %s is not valid domain name", domain)
			}
		}
	}
	return nil
}
