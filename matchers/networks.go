package matchers

import (
	"fmt"
	"net"
)

type Network struct {
	includes []*net.IPNet
	excludes []*net.IPNet
	ips      map[string]bool // compare ip as string, because net.IP is invalid map key
}

func NewNetwork(includes []string, excludes []string) (*Network, error) {
	m := &Network{ips: make(map[string]bool)}

	for i := range includes {
		_, ipnet, err := net.ParseCIDR(includes[i])
		if err != nil {
			return nil, err
		}

		m.includes = append(m.includes, ipnet)
	}

	for i := range excludes {
		ip := net.ParseIP(excludes[i])
		_, ipnet, err := net.ParseCIDR(excludes[i])
		if ip == nil && err != nil {
			return nil, fmt.Errorf("%s is not cidr nor ip", excludes[i])
		}

		if ip != nil {
			m.ips[excludes[i]] = true
		} else {
			m.excludes = append(m.excludes, ipnet)
		}
	}

	return m, nil
}

func (m *Network) Match(ip net.IP) bool {
	if ip == nil {
		return false
	}

	ok := false
	for _, n := range m.includes {
		if n.Contains(ip) {
			ok = true
			break
		}
	}

	if !ok {
		return false
	}

	if m.ips[ip.String()] {
		return false
	}

	for _, n := range m.excludes {
		if n.Contains(ip) {
			return false
		}
	}

	return true
}
