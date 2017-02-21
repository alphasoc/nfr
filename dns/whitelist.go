package dns

import "net"

import "github.com/BurntSushi/toml"

// WhitelistContent contains whitelisted domains and networks
type WhitelistContent struct {
	Networks []string `toml:"networks"`
	Domains  []string `toml:"domains"`
}

// Whitelist stores filters for whitelisting domains and IPs
type Whitelist struct {
	networks []net.IPNet
	domains  []string
}

// NewWhitelist reads and parses file in path.
// The file uses TOML format.
func NewWhitelist(path string) (*Whitelist, error) {
	content := &WhitelistContent{}

	if _, err := toml.DecodeFile(path, content); err != nil {
		return nil, err
	}

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

// CheckFqdn checks if domain is whitelisted
func (w *Whitelist) CheckFqdn(fqdn string) bool {
	for _, d := range w.domains {
		if d == fqdn {
			return true
		}
	}
	return false
}

// CheckIP checks if IP is whitelisted
func (w *Whitelist) CheckIP(ip net.IP) bool {
	for _, n := range w.networks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
