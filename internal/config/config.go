package config

import (
	"bufio"
	"bytes"
	"io"
	"io/ioutil"
	"os"
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
	alphaSocAddress      string
	sendIntervalTime     time.Duration
	sendIntervalAmount   int
	alertRequestInterval time.Duration
}

type AsocFileConfig struct {
	Iface string `toml:"interface"`
	Key   string `toml:"key"`
}

func Get() *Config {
	return &Config{
		followFilePath:       FollowFilePath,
		alertFilePath:        AlertFilePath,
		configFilePath:       ConfigFilePath,
		alphaSocAddress:      AlphaSocAddress,
		sendIntervalTime:     SendIntervalTime,
		sendIntervalAmount:   SendIntervalAmount,
		alertRequestInterval: AlertRequestInterval,
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

	if exist, err := utils.FileExists(c.configFilePath); err != nil {
		return err
	} else if exist == false {
		if err := utils.CreateDirForFile(c.configFilePath); err != nil {
			return err
		}
	}

	if err := ioutil.WriteFile(c.configFilePath, buf.Bytes(), 0640); err != nil {
		return err
	}
	return nil
}

func (c *Config) InitialDirsCreate() error {
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

func (c *Config) GetAlphaSocAddress() string {
	return c.alphaSocAddress
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
