package config

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"

	"io/ioutil"

	"github.com/BurntSushi/toml"
)

type Config struct {
	APIKey               string
	NetworkInterface     string
	followFilePath       string
	alertFilePath        string
	configFilePath       string
	alphaSocAddress      string
	sendIntervalTime     uint
	sendIntervalAmount   uint
	alertRequestInterval uint
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
		return fmt.Errorf("ReadFromFile() %v", err)
	}
	c.APIKey = cfg.Key
	c.NetworkInterface = cfg.Iface

	return nil
}

func (c *Config) ConfigFileExists() bool {
	if _, err := os.Stat(c.configFilePath); err == nil {
		return true
	}
	return false
}

func (c *Config) SaveToFile() error {
	content := AsocFileConfig{Iface: c.NetworkInterface, Key: c.APIKey}

	buf := new(bytes.Buffer)
	if err := toml.NewEncoder(buf).Encode(content); err != nil {
		return fmt.Errorf("SaveToFile() encoding %v", err)
	}

	//todo bug check if dir exists if not -> "mkdir -p"
	if err := ioutil.WriteFile(c.configFilePath, buf.Bytes(), 0640); err != nil {
		return fmt.Errorf("SaveToFile() saving %v", err)
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

func (c *Config) GetAlphaSocAddress() string {
	return c.alphaSocAddress
}

func (c *Config) GetAlertFilePath() string {
	return c.alertFilePath
}

func (c *Config) GetConfigFilePath() string {
	return c.configFilePath
}

func (c *Config) GetSendIntervalTime() uint {
	return c.sendIntervalTime
}

func (c *Config) GetSendIntervalAmount() uint {
	return c.sendIntervalAmount
}

func (c *Config) GetAlertRequestInterval() uint {
	return c.alertRequestInterval
}
