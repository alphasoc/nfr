package config

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/alphasoc/namescore/utils"
)

// Config is a structure containing internal
// configuration parameters.
type Config struct {
	APIKey               string
	NetworkInterface     string
	FollowFilePath       string
	AlertFilePath        string
	ConfigFilePath       string
	AlphaSOCAddress      string
	SendIntervalTime     time.Duration
	SendIntervalAmount   int
	AlertRequestInterval time.Duration
	LocalQueriesInterval time.Duration
	WhitelistFilePath    string
	FailedQueriesDir     string
	FailedQueriesLimit   int
}

// AsocFileConfig represents configuration parameters
// stored persistently in file.
type AsocFileConfig struct {
	Iface string `toml:"interface"`
	Key   string `toml:"key"`
}

// Get functions sets values of Config with the consts
// from this package.
func Get() *Config {
	return &Config{
		FollowFilePath:       followFilePath,
		AlertFilePath:        alertFilePath,
		ConfigFilePath:       configFilePath,
		AlphaSOCAddress:      alphaSOCAddress,
		SendIntervalTime:     sendIntervalTime,
		SendIntervalAmount:   sendIntervalAmount,
		AlertRequestInterval: alertRequestInterval,
		WhitelistFilePath:    whitelistFilePath,
		FailedQueriesDir:     failedQueriesDir,
		FailedQueriesLimit:   failedQueriesLimit,
		LocalQueriesInterval: localQueriesInterval,
	}
}

// ReadFromFile reads parameters from configFilePath.
func (c *Config) ReadFromFile() error {
	cfg := AsocFileConfig{}
	if _, err := toml.DecodeFile(c.ConfigFilePath, &cfg); err != nil {
		return err
	}
	c.APIKey = cfg.Key
	c.NetworkInterface = cfg.Iface

	return nil
}

// ConfigFileExists checks whether config file exists.
func (c *Config) ConfigFileExists() (bool, error) {
	return utils.FileExists(c.ConfigFilePath)
}

// SaveToFile stores API key and network interface name to configuration file
func (c *Config) SaveToFile() error {
	content := AsocFileConfig{Iface: c.NetworkInterface, Key: c.APIKey}

	buf := &bytes.Buffer{}
	if err := toml.NewEncoder(buf).Encode(content); err != nil {
		return err
	}

	if err := ioutil.WriteFile(c.ConfigFilePath, buf.Bytes(), 0640); err != nil {
		return err
	}
	return nil
}

// InitialDirsCreate creates proper directory structure for all files created by namescore
// For example for file: /var/test/dir/file this function
// will create /var/test/dir directory if it does not exist.
func (c *Config) InitialDirsCreate() error {
	files := []string{
		c.AlertFilePath,
		c.ConfigFilePath,
		c.FollowFilePath,
		c.WhitelistFilePath,
	}

	for _, file := range files {
		dir, _ := filepath.Split(file)

		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	return os.MkdirAll(c.FailedQueriesDir, 0700)
}
