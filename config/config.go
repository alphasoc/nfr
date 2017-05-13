package config

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"runtime"
	"strings"
	"time"

	"github.com/alphasoc/namescore/utils"
	yaml "gopkg.in/yaml.v2"
)

// DefaultLocation for config file.
const DefaultLocation = "/etc/namescore.yml"

// Config for namescore
type Config struct {
	// AlphaSOC server configuration
	Alphasoc struct {
		// AlphaSOC host server. Default: https://api.alpahsoc.net
		Host string `yaml:"host,omitempty"`
		// AlphaSOC api key. Required for start sending dns traffic.
		APIKey string `yaml:"api_key,omitempty"`
	} `yaml:"alphasoc,omitempty"`

	// Network interface configuration.
	Network struct {
		// Interface on which namescore should listen. Default: (none)
		Interface string `yaml:"interface,omitempty"`
		// Protocols on which namescore should listen. Default: [udp]
		Protocols []string `yaml:"protocols,omitempty"`
		// Protocols on which namescore should listen. Default: 53
		Port int `yaml:"port,omitempty"`
	} `yaml:"network,omitempty"`

	// Log configuration.
	Log struct {
		// File to which namescore should log. Default: stdout
		// To print log to console use two special outputs: stderr or stdout
		File string `yaml:"file,omitempty"`

		// Level for logger. Possibles values are: debug, info, warn, error
		// Default: info
		Level string `yaml:"level,omitempty"`
	} `yaml:"log,omitempty"`

	// Internal namescore data.
	Data struct {
		// File for internal data.
		// Default:
		// - linux /run/namescore.data
		// - win %AppData%/namescore.data
		File string `yaml:"file,omitempty"`
	} `yaml:"data,omitempty"`

	// Whitelist rules file.
	// The IP exclusion list is used to prune 'noisy' hosts, such as mail servers
	// or workstations within the IP ranges provided.
	// Finally, the domain whitelist is used to specify internal and trusted domains and
	// hostnames (supporting wildcards, e.g. *.google.com) to ignore.
	// If you do not whitelist domains, local DNS traffic will be forwarded to the AlphaSOC API for scoring.
	WhiteList struct {
		// File with whitelist rule. See WhiteListConfig for more info.
		// Default: (none)
		File string `yaml:"file,omitempty"`
	} `yaml:"whitelist,omitempty"`

	// WhiteListConfig is loaded when WhilteList.File is not empty.
	WhiteListConfig struct {
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

	// AlphaSOC events configuration.
	Events struct {
		// File where to store events. If not set then none events will be retrived.
		// To print events to console use two special outputs: stderr or stdout
		// Default: "stdout"
		File string `yaml:"file,omitempty"`
		// Interval for polling events from AlphaSOC server. Default: 30s
		PollInterval time.Duration `yaml:"poll_interval,omitempty"`
	} `yaml:"events,omitempty"`

	// DNS queries configuration.
	Queries struct {
		// Buffer size for dns queries queue. If the size will be exceded then
		// namescore send quries to AlphaSOC server. Default: 2048
		BufferSize int `yaml:"buffer_size,omitempty"`
		// Interval for flushing queries to AlphaSOC server. Default: 30s
		FlushInterval time.Duration `yaml:"flush_interval,omitempty"`

		// Queries that were unable to send to AlphaSOC server.
		// If file is set, then unsent queries will be saved on disk
		// and then send again.
		// Pcap format is used to store queries. You can view it in
		// programs like tcpdump or whireshark.
		Failed struct {
			// File to store DNS Queries. Default: (none)
			File string `yaml:"file,omitempty"`
		} `yaml:"failed,omitempty"`
	} `yaml:"queries,omitempty"`
}

// New reads the config from file location. If file is not set
// then it tries to read from default location, if this fails, then
// default config is returned.
func New(file string) (*Config, error) {
	cfg := Config{}

	if file != "" {
		return Read(file)
	}
	if _, err := os.Stat(DefaultLocation); err == nil {
		return Read(DefaultLocation)
	}
	return cfg.setDefaults(), nil
}

// Read reads config from the given file.
func Read(file string) (*Config, error) {
	cfg := Config{}

	content, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	if err := yaml.Unmarshal(content, &cfg); err != nil {
		return nil, err
	}

	if err := cfg.loadWhiteListConfig(); err != nil {
		return nil, err
	}
	cfg.setDefaults()
	return &cfg, cfg.validate()
}

// Save saves config to file.
func (cfg *Config) Save(file string) error {
	content, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(file, content, 0666)
}

// SaveDefault saves config to default file.
func (cfg *Config) SaveDefault() error {
	return cfg.Save(DefaultLocation)
}

func (cfg *Config) setDefaults() *Config {
	if cfg.Alphasoc.Host == "" {
		cfg.Alphasoc.Host = "https://api.alphasoc.net"
	}

	if len(cfg.Network.Protocols) == 0 {
		cfg.Network.Protocols = []string{"udp"}
	}

	if cfg.Network.Port == 0 {
		cfg.Network.Port = 53
	}

	if cfg.Events.File == "" {
		cfg.Events.File = "stdout"
	}

	if cfg.Log.File == "" {
		cfg.Log.File = "stdout"
	}
	if cfg.Log.Level == "" {
		cfg.Log.Level = "info"
	}

	if cfg.Data.File == "" {
		if runtime.GOOS == "windows" {
			cfg.Data.File = path.Join(os.Getenv("APPDATA"), "namescore.data")
		} else {
			cfg.Data.File = path.Join("/run", "namescore.data")
		}
	}

	if cfg.Events.PollInterval == 0 {
		cfg.Events.PollInterval = 30 * time.Second
	}

	if cfg.Queries.BufferSize == 0 {
		cfg.Queries.BufferSize = 2048
	}
	if cfg.Queries.FlushInterval == 0 {
		cfg.Queries.FlushInterval = 30 * time.Second
	}

	return cfg
}

func (cfg *Config) validate() error {
	if len(cfg.Network.Protocols) == 0 {
		return fmt.Errorf("empty protocol list")
	}

	if len(cfg.Network.Protocols) > 2 {
		return fmt.Errorf("too many protocols in list (only tcp and udp are available)")
	}

	for _, proto := range cfg.Network.Protocols {
		if proto != "udp" && proto != "tcp" {
			return fmt.Errorf("invalid protocol %q name (only tcp and udp are available)", proto)
		}
	}

	if cfg.Network.Port < 0 || cfg.Network.Port > 65355 {
		return fmt.Errorf("invalid %d port number", cfg.Network.Port)
	}

	if err := validateFilename(cfg.Log.File, true); err != nil {
		return err
	}
	if cfg.Log.Level != "debug" &&
		cfg.Log.Level != "info" &&
		cfg.Log.Level != "warn" &&
		cfg.Log.Level != "error" {
		return fmt.Errorf("invalid %s log level", cfg.Log.Level)
	}

	if err := validateFilename(cfg.Data.File, false); err != nil {
		return err
	}

	if cfg.Events.File != "" {
		if err := validateFilename(cfg.Events.File, true); err != nil {
			return err
		}
	}

	if cfg.Events.PollInterval < 5*time.Second {
		return fmt.Errorf("events poll interval must be at least 5s")
	}

	if cfg.Queries.BufferSize < 64 {
		return fmt.Errorf("queries buffer size must be at least 64")
	}

	if cfg.Queries.FlushInterval < 5*time.Second {
		return fmt.Errorf("queries flush interval must be at least 5s")
	}

	if cfg.Queries.Failed.File != "" {
		if err := validateFilename(cfg.Queries.Failed.File, false); err != nil {
			return err
		}
	}

	return nil
}

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

func (cfg *Config) loadWhiteListConfig() error {
	if cfg.WhiteList.File == "" {
		return nil
	}

	content, err := ioutil.ReadFile(cfg.WhiteList.File)
	if err != nil {
		return err
	}

	if err := yaml.Unmarshal(content, &cfg.WhiteListConfig); err != nil {
		return err
	}

	return cfg.validateWhiteListConfig()
}

func (cfg *Config) validateWhiteListConfig() error {
	for _, group := range cfg.WhiteListConfig.Groups {
		for _, n := range group.Networks {
			if _, _, err := net.ParseCIDR(n); err != nil {
				return fmt.Errorf("%s is not cidr", n)
			}
		}

		for _, n := range group.Exclude.Networks {
			_, _, err := net.ParseCIDR(n)
			ip := net.ParseIP(n)
			if err != nil && ip == nil {
				return fmt.Errorf("%s is not cidr nor ip", n)
			}
		}

		for _, domain := range group.Exclude.Domains {
			// TrimPrefix *. for multimatch domain
			if !utils.IsDomainName(domain) &&
				!utils.IsDomainName(strings.TrimPrefix(domain, "*.")) {
				return fmt.Errorf("%s is not valid domain name", domain)
			}
		}
	}
	return nil
}
