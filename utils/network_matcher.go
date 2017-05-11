package utils

import "net"

type NetworkMatcher struct {
	networks []*net.IPNet
	excluded []*net.IPNet
	ips      map[string]bool
}

func NewNetworkMatcher() *NetworkMatcher {
	return &NetworkMatcher{
		ips: make(map[string]bool),
	}
}

func (m *NetworkMatcher) AddNetwork(n *net.IPNet) {
	if n != nil {
		m.networks = append(m.networks, n)
	}
}

func (m *NetworkMatcher) ExcludeNetwork(n *net.IPNet) {
	if n != nil {
		m.excluded = append(m.excluded, n)
	}
}

func (m *NetworkMatcher) ExcludeIP(ip net.IP) {
	if ip != nil {
		m.ips[ip.String()] = true
	}
}

func (m *NetworkMatcher) Match(ip net.IP) bool {
	if ip == nil {
		return false
	}

	ok := false
	for _, n := range m.networks {
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

	for _, n := range m.excluded {
		if n.Contains(ip) {
			return false
		}
	}

	return true 
}
