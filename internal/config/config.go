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

type Config struct {
	APIKey               string
	NetworkInterface     string
	followFilePath       string
	alertFilePath        string
	configFilePath       string
	alphaSOCAddress      string
	sendIntervalTime     time.Duration
	sendIntervalAmount   int
	alertRequestInterval time.Duration
	whitelistFile        string
}

type AsocFileConfig struct {
	Iface string `toml:"interface"`
	Key   string `toml:"key"`
}

func Get() *Config {
	return &Config{
		followFilePath:       followFile,
		alertFilePath:        alertFile,
		configFilePath:       configFile,
		alphaSOCAddress:      alphaSOCCloud,
		sendIntervalTime:     sendIntervalSecond,
		sendIntervalAmount:   querySendAmount,
		alertRequestInterval: alertRequestIntervalSecond,
		whitelistFile:        whitelistFile,
	}
}

func (c *Config) ReadFromFile() error {
	cfg := AsocFileConfig{}
	if _, err := toml.DecodeFile(c.configFilePath, &cfg); err != nil {
		return err
	}
	c.APIKey = cfg.Key
	c.NetworkInterface = cfg.Iface

	return nil
}

func (c *Config) ConfigFileExists() (bool, error) {
	return utils.FileExists(c.configFilePath)
}

func (c *Config) SaveToFile() error {
	content := AsocFileConfig{Iface: c.NetworkInterface, Key: c.APIKey}

	buf := new(bytes.Buffer)
	if err := toml.NewEncoder(buf).Encode(content); err != nil {
		return err
	}

	if err := ioutil.WriteFile(c.configFilePath, buf.Bytes(), 0640); err != nil {
		return err
	}
	return nil
}

// InitialDirsCreate creates proper directory structure for all files created by namescore
// For example for file: /var/test/dir/file this function
// will create /var/test/dir directory if it does not exist.
func (c *Config) InitialDirsCreate() error {
	files := []string{c.alertFilePath, c.configFilePath, c.followFilePath, c.whitelistFile}

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
	return nil
}

func (c *Config) ReadInterface(rd io.Reader) {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	c.NetworkInterface = scanner.Text()
}

func (c *Config) GetFollowFilePath() string {
	return c.followFilePath
}

func (c *Config) GetAlphaSOCAddress() string {
	return c.alphaSOCAddress
}

func (c *Config) GetAlertFilePath() string {
	return c.alertFilePath
}

func (c *Config) GetConfigFilePath() string {
	return c.configFilePath
}

func (c *Config) GetSendIntervalTime() time.Duration {
	return c.sendIntervalTime
}

func (c *Config) GetSendIntervalAmount() int {
	return c.sendIntervalAmount
}

func (c *Config) GetAlertRequestInterval() time.Duration {
	return c.alertRequestInterval
}

func (c *Config) GetWhitelistFilePath() string {
	return c.whitelistFile
}
