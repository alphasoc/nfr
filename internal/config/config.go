package config

import (
	"bufio"
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/alphasoc/namescore/internal/utils"
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
	FailedQueriesLimit   uint
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
		SendIntervalTime:     sendIntervalTime * time.Second,
		SendIntervalAmount:   sendIntervalAmount,
		AlertRequestInterval: alertRequestInterval * time.Second,
		WhitelistFilePath:    whitelistFilePath,
		FailedQueriesDir:     failedQueriesDir,
		FailedQueriesLimit:   failedQueriesLimit,
		LocalQueriesInterval: localQueriesInterval * time.Second,
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

func (c *Config) ConfigFileExists() (bool, error) {
	return utils.FileExists(c.ConfigFilePath)
}

func (c *Config) SaveToFile() error {
	content := AsocFileConfig{Iface: c.NetworkInterface, Key: c.APIKey}

	buf := new(bytes.Buffer)
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
		exist, err := utils.FileExists(dir)
		if err != nil {
			return err
		}
		if exist == false {
			if err := os.MkdirAll(dir, 0750); err != nil {
				return err
			}
		}
	}
	if err := os.MkdirAll(c.FailedQueriesDir, 0750); err != nil {
		return err
	}

	return nil
}

// ReadInterface reads Config.NetworkInterface from stdin
func (c *Config) ReadInterface(rd io.Reader) {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	c.NetworkInterface = scanner.Text()
}
