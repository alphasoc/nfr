package dns

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"strings"
)

const (
	networkSection = "[networks]"
	domainSection  = "[domains]"
)

// Whitelist stores filters for whitelisting domains and IPs
type Whitelist struct {
	addresses []net.IP
	networks  []net.IPNet
	// strictDomains contains domains which are literally compared
	strictDomains []string
	// multimatchDomains contains domains filters which
	// matches *.domains.com
	multimatchDomains []string
}

// NewWhitelist reads and parses file in path.
// The file uses TOML format.
func NewWhitelist(path string) (*Whitelist, error) {
	whitelist := &Whitelist{}
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(bytes.NewBuffer(content))
	parser := whitelist.discardParser
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == networkSection {
			parser = whitelist.networkParser
			continue
		} else if line == domainSection {
			parser = whitelist.domainParser
			continue
		}

		if err := parser(line); err != nil {
			return nil, err
		}
	}
	return whitelist, nil
}

func (w *Whitelist) discardParser(line string) error {
	return nil
}

func (w *Whitelist) domainParser(line string) error {
	if line == "" {
		return nil
	}
	if strings.HasPrefix(line, "*") {
		w.multimatchDomains = append(w.multimatchDomains, strings.TrimPrefix(line, "*"))
		w.strictDomains = append(w.strictDomains, strings.TrimPrefix(line, "*."))
		return nil
	}
	w.strictDomains = append(w.strictDomains, line)
	return nil
}

func (w *Whitelist) networkParser(line string) error {
	if line == "" {
		return nil
	}

	if _, network, err := net.ParseCIDR(line); err == nil {
		w.networks = append(w.networks, *network)
		return nil
	}

	if ip := net.ParseIP(line); ip != nil {
		w.addresses = append(w.addresses, ip)
		return nil
	}

	return fmt.Errorf("invalid address: %s", line)
}

// CheckFqdn checks if domain is whitelisted
func (w *Whitelist) CheckFqdn(fqdn string) bool {
	for _, d := range w.strictDomains {
		if d == fqdn {
			return true
		}
	}

	for _, m := range w.multimatchDomains {
		if strings.HasSuffix(fqdn, m) {
			return true
		}
	}

	return false
}

// CheckIP checks if IP is whitelisted
func (w *Whitelist) CheckIP(ip net.IP) bool {
	for _, a := range w.addresses {
		if a.Equal(ip) {
			return true
		}
	}

	for _, n := range w.networks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
