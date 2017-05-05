package config

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"

	yaml "gopkg.in/yaml.v2"
)

type WhiteListConfig struct {
	GroupName map[string]struct {
		Networks []string `json:"networks"`
		Domains  []string `json:"domains"`
		Excludes []string `json:"excludes"`
	}
}

func NewWhiteListConfig(file string) (*WhiteListConfig, error) {
	if file == "" {
		return &WhiteListConfig{}, nil
	}

	content, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	wlcfg := WhiteListConfig{}
	if err := yaml.Unmarshal(content, &wlcfg); err != nil {
		return nil, err
	}

	return &wlcfg, wlcfg.validate()
}

func (cfg *WhiteListConfig) validate() error {
	for _, group := range cfg.GroupName {

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

func validateFilename(filename string) error {
	dir := path.Dir(filename)
	stat, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("can't stat %s directory: %s", dir, err)
	}
	if !stat.IsDir() {
		return fmt.Errorf("%s is not directory", dir)
	}

	stat, err = os.Stat(filename)
	if err == nil && !stat.Mode().IsRegular() {
		return fmt.Errorf("%s is not regular file", filename)
	}
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("can't stat %s file: %s", filename, err)
	}
	return nil
}
