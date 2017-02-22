// Package config stores namescore internal configuration
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

const (
	followFilePath       = "/home/phob0s/alphasoc/follow"
	alertFilePath        = "/home/phob0s/alphasoc/namescore.log"
	configFilePath       = "/home/phob0s/alphasoc/namescore.toml"
	failedQueriesDir     = "/home/phob0s/alphasoc/backup"
	whitelistFilePath    = "/home/phob0s/alphasoc/whitelist.toml"
	alphaSOCAddress      = "http://127.0.0.1:8080"
	sendIntervalTime     = 10 * time.Second
	alertRequestInterval = 20 * time.Second
	localQueriesInterval = 20 * time.Second
	failedQueriesLimit   = 100
	sendIntervalAmount   = 100
)

// Config is a structure containing internal
// configuration parameters.
type Config struct {
	// APIKey represents client unique key retrieved from AlphaSOC.
	APIKey string
	// NetworkInterface determines which network interface is used
	// to sniff DNS packets.
	NetworkInterface string
	// FollowFilePath File where follow ID after each response is stored
	FollowFilePath string
	// AlertFilePath is a file where alerts are stored
	// Format of alerts is:
	// timestamp;ip;record_type;domain;severity;threat_definition;flags
	AlertFilePath string
	// ConfigFilePath is a file where are stored informations about:
	// - API key
	// - Network interface which should namescore bind to
	ConfigFilePath string
	// AlphaSOCAddress is AlphaSOC server address to communicate with.
	AlphaSOCAddress string
	// SendIntervalTime is time interval in seconds which determines
	// how often queries are sent to AlphaSOC cloud.
	SendIntervalTime time.Duration
	// SendIntervalAmount determines how many DNS requests are needed
	// to be collected to send data to AlphaSOC.
	// It has higher priority than time interval parameter.
	SendIntervalAmount int
	// AlertRequestInterval determines how often alerts are collected from
	// AlphaSOC cloud. It is represented in seconds.
	AlertRequestInterval time.Duration
	// Time interval determining how often failedQueriesDir is scanned for
	// queries saved in file.
	LocalQueriesInterval time.Duration
	// WhitelistFilePath stores information about:
	// - which subnetworks should not be taken into account
	// - which domains should not been taken into account
	WhitelistFilePath string
	// FailedQueriesDir is a dir where are stored queries which sending failed.
	FailedQueriesDir string
	// FailedQueriesLimit is number of chunks of failed queries which are stored locally
	// Total amout of possible stored queries on disk can be calculated with:
	// failedQueriesCountLimit * querySendAmount
	FailedQueriesLimit int
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
