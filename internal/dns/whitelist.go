package dns

import "net"

import "github.com/BurntSushi/toml"
import "fmt"

type WhitelistContent struct {
	Networks []string `toml:"networks"`
	Domains  []string `toml:"domains"`
}

type Whitelist struct {
	networks []net.IPNet
	domains  []string
}

func NewWhitelist(path string) (*Whitelist, error) {
	content := &WhitelistContent{}

	if _, err := toml.DecodeFile(path, content); err != nil {
		return nil, err
	}

	fmt.Printf("\n%v\n", content)

	whitelist := &Whitelist{domains: content.Domains}
	for _, ip := range content.Networks {
		_, net, err := net.ParseCIDR(ip)
		if err != nil {
			return nil, err
		}
		whitelist.networks = append(whitelist.networks, *net)
	}

	return whitelist, nil
}

func (w *Whitelist) CheckFqdn(fqdn string) bool {
	for _, d := range w.domains {
		if d == fqdn {
			return true
		}
	}
	return false
}

func (w *Whitelist) CheckIP(ip net.IP) bool {
	for _, n := range w.networks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
