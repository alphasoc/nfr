package config

import (
	"fmt"
	"path"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"time"

	yaml "gopkg.in/yaml.v2"
	"github.com/alphasoc/namescore/client"
)

// DefaultLocation for config file.
const DefaultLocation = "/etc/namescore.yml"

// Config for namescore
type Config struct {
	// AlphaSOC server configuration
	Alphasoc struct {
		// AlphaSOC host server. Default: https://api.alpahsoc.net
		Host string `yaml:"host,omitempty"`
		// AlphaSOC api version (only v1 supported now).
		APIVersion string `yaml:"api_version,omitempty"`
		// AlphaSOC api key. Required for start sending dns traffic.
		APIKey string `yaml:"api_key,omitempty"`
	} `yaml:"alphasoc,omitempty"`

	// Network interface configuration.
	Network struct {
		// Interface on which namescore should listen. Default: eth0
		Interface string `yaml:"interface,omitempty"`
		// Protocols on which namescore should listen. Default: ["udp", "tcp"]
		Protocols []string `yaml:"protocols,omitempty"`
		// Protocols on which namescore should listen. Default: 53
		Port int `yaml:"port,omitempty"`
	} `yaml:"network,omitempty"`

	// Log configuration.
	Log struct {
		// File to which namescore should log. Default: stdout
		// To print log to console use two special outputs: stderr or stdout
		File  string `yaml:"file,omitempty"`
		Level string `yaml:"level,omitempty"`
	} `yaml:"log,omitempty"`

	// Internal namescore data.
	Data struct {
		// File for internal data. Default: /run/namescore.data
		File string `yaml:"file,omitempty"`
	} `yaml:"data,omitempty"`

	// Whitelist rules file.
	WhiteList struct {
		// File with whitelist rule. See WhiteListConfig for more info.
		// Default: (none)
		File string `yaml:"file,omitempty"`
	} `yaml:"whitelist,omitempty"`

	// WhiteListConfig is loaded when WhilteList.File is not empty.
	WhiteListConfig struct {
		GroupName map[string]struct {
			// Networks is list of network address. If packet source ip match any 
			// of this network, then the packet will not be send to analyze.
			Networks []string `json:"networks"`
			// Domains is list of fqdn. If dns packet fqdn match any 
			// of this domains , then the packet will not be send to analyze.
			Domains  []string `json:"domains"`
			// Exclueds is list of network address excludes from networks.
			// This list has higher priority then networks list
			Excludes []string `json:"excludes"`
		}
	}

	// AlphaSOC events configuration.
	Events struct {
		// File where to store events. If not set then now events will be retrived.
		// Default: (none)
		File string `yaml:"file,omitempty"`
		// Interval for polling events from AlphaSOC server. Default: 30s
		PollInterval time.Duration `yaml:"pool_interval,omitempty"`
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
	if cfg.Alphasoc.APIVersion == "" {
		cfg.Alphasoc.APIVersion = "v1"
	}

	if cfg.Network.Interface == "" {
		cfg.Network.Interface = "eth0"
	}
	if len(cfg.Network.Protocols) == 0 {
		cfg.Network.Protocols = []string{"udp", "tcp"}
	}
	if cfg.Network.Port == 0 {
		cfg.Network.Port = 53
	}

	if cfg.Log.File == "" {
		cfg.Log.File = "stdout"
	}
	if cfg.Log.Level == "" {
		cfg.Log.Level = "info"
	}

	if cfg.Data.File == "" {
		cfg.Data.File = "/run/namescore.data"
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
	if _, err := http.Get(cfg.Alphasoc.Host); err != nil {
		return fmt.Errorf("can't connect to alphasoc %q server: %s", cfg.Alphasoc.Host, err)
	}

	if cfg.Alphasoc.APIVersion != client.DefaultVersion {
		return fmt.Errorf("alphasoc api version %q invalid (only version '%s' is supported)", cfg.Alphasoc.APIVersion, client.DefaultVersion)
	}

	if cfg.Network.Interface == "" {
		return fmt.Errorf("empty network interface name")
	}

	if _, err := net.InterfaceByName(cfg.Network.Interface); err != nil {
		return fmt.Errorf("invalid %q network interface: %s", cfg.Network.Interface, err)
	}

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

	if err := validateFilename(cfg.Log.File); err != nil {
		return err
	}
	if cfg.Log.Level != "debug" &&
		cfg.Log.Level != "info" &&
		cfg.Log.Level != "warn" &&
		cfg.Log.Level != "fatal" {
		return fmt.Errorf("invalid %q log level", cfg.Log.Level)
	}

	if err := validateFilename(cfg.Data.File); err != nil {
		return err
	}

	if cfg.Events.File != "" {
		if err := validateFilename(cfg.Events.File); err != nil {
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
		if err := validateFilename(cfg.Queries.Failed.File); err != nil {
			return err
		}
	}

	return nil
}

func validateFilename(file string) error {
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

func (cfg *Config) loadWhiteListConfig() (error) {
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
        for _, group := range cfg.WhiteListConfig.GroupName {

                for _, network := range group.Networks {
                        _, _, errCIDR := net.ParseCIDR(network)
                        ip := net.ParseIP(network)
                        if errCIDR != nil && ip != nil {
                                return fmt.Errorf("%s is not cidr nor ip", network)
                        }
                }

                for _, exclude := range group.Excludes {
                        _, _, errCIDR := net.ParseCIDR(exclude)
                        ip := net.ParseIP(exclude)
                        if errCIDR != nil && ip != nil {
                                return fmt.Errorf("%s is not cidr nor ip", exclude)
                        }
                }
        }

        return nil
}
