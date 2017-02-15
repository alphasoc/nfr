package dns

import "net"

import "github.com/BurntSushi/toml"

type WhitelistContent struct {
	Networks []string `toml:"networks"`
	Domains  []string `toml:"domains"`
}

type whitelist struct {
	networks []net.IPNet
	domains  []string
}

func newWhitelist(path string) (*whitelist, error) {
	content := &WhitelistContent{}

	if _, err := toml.DecodeFile(path, content); err != nil {
		return nil, err
	}

	whitelist := &whitelist{domains: content.Domains}
	for _, ip := range content.Networks {
		_, net, err := net.ParseCIDR(ip)
		if err != nil {
			return nil, err
		}
		whitelist.networks = append(whitelist.networks, *net)
	}

	return whitelist, nil
}

func (w *whitelist) checkFqdn(fqdn string) bool {
	for _, d := range w.domains {
		if d == fqdn {
			return true
		}
	}
	return false
}

func (w *whitelist) checkIP(ip net.IP) bool {
	for _, n := range w.networks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
