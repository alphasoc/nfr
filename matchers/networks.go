package matchers

import (
	"errors"
	"fmt"
	"net"
)

// Network matches network on give list.
// Checks if the ip is included and not excluded from list
// at the same time.
type Network struct {
	includes []*net.IPNet
	excludes []*net.IPNet
	ips      map[string]bool // compare ip as string
}

// NewNetwork creates Network matcher for given includes and excludes netowrks.
// The excludes network acceptable format is cidr and ip.
func NewNetwork(includes []string, excludes []string) (*Network, error) {
	if len(includes) == 0 {
		return nil, errors.New("no includes network")
	}

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

			// check if ipnet is ipv4 with /32 or ipv6 with /128
			// if it is then put this into ips maps.
			if ipnet.IP.To4() != nil {
				if once, _ := ipnet.Mask.Size(); once == 32 {
					m.ips[ipnet.IP.String()] = true
					continue
				}
			} else {
				if once, _ := ipnet.Mask.Size(); once == 128 {
					m.ips[ipnet.IP.String()] = true
					continue
				}
			}
			m.excludes = append(m.excludes, ipnet)
		}
	}

	return m, nil
}

// Match matches ip and check if it's on networks included list
// at the same time checking if it's not in any excluded list.
// It returns if the ip was matched by this groups and if was matched
// by excluded networks
func (m *Network) Match(ip net.IP) (bool, bool) {
	if ip == nil {
		return false, false
	}

	// check if the ip is included in some networks
	ok := true
	for _, n := range m.includes {
		if n.Contains(ip) {
			ok = false
			break
		}
	}

	// if the ip is not in any networks,
	// it means that ip is not matched
	if ok {
		return false, false
	}

	// if this ip is excluded
	if m.ips[ip.String()] {
		return true, true
	}

	// if the ip is within any excluded network
	for _, n := range m.excludes {
		if n.Contains(ip) {
			return true, true
		}
	}

	return true, false
}
