package matchers

import (
	"fmt"
	"net"
)

// Network matches network based on src and dst IP.
// Checks if the ip is included and not excluded from list at the same time.
type Network struct {
	srcIncludes    []*net.IPNet
	srcExcludes    []*net.IPNet
	srcExcludesIps map[string]bool // compare ip as string

	dstIncludes    []*net.IPNet
	dstExcludes    []*net.IPNet
	dstExcludesIps map[string]bool // compare ip as string
}

// NewNetwork creates Network matcher for given includes and excludes netowrks.
// The excludes network acceptable format is cidr and ip.
func NewNetwork(srcIncludes, srcExcludes, dstIncludes, dstExcludes []string) (*Network, error) {
	if len(srcIncludes) == 0 {
		srcIncludes = []string{"0.0.0.0/0", "::/0"}
	}
	if len(dstIncludes) == 0 {
		dstIncludes = []string{"0.0.0.0/0", "::/0"}
	}

	m := &Network{
		srcExcludesIps: make(map[string]bool),
		dstExcludesIps: make(map[string]bool),
	}

	for i := range srcIncludes {
		_, ipnet, err := net.ParseCIDR(srcIncludes[i])
		if err != nil {
			return nil, err
		}
		m.srcIncludes = append(m.srcIncludes, ipnet)
	}

	for i := range dstIncludes {
		_, ipnet, err := net.ParseCIDR(dstIncludes[i])
		if err != nil {
			return nil, err
		}
		m.dstIncludes = append(m.dstIncludes, ipnet)
	}

	for i := range srcExcludes {
		ip := net.ParseIP(srcExcludes[i])
		_, ipnet, err := net.ParseCIDR(srcExcludes[i])
		if ip == nil && err != nil {
			return nil, fmt.Errorf("%s is not cidr nor ip", srcExcludes[i])
		}

		if ip != nil {
			m.srcExcludesIps[srcExcludes[i]] = true
		} else {
			if isIpnetIP(ipnet) {
				m.srcExcludesIps[ipnet.IP.String()] = true
				continue
			}
			m.srcExcludes = append(m.srcExcludes, ipnet)
		}
	}

	for i := range dstExcludes {
		ip := net.ParseIP(dstExcludes[i])
		_, ipnet, err := net.ParseCIDR(dstExcludes[i])
		if ip == nil && err != nil {
			return nil, fmt.Errorf("%s is not cidr nor ip", dstExcludes[i])
		}

		if ip != nil {
			m.dstExcludesIps[dstExcludes[i]] = true
		} else {
			if isIpnetIP(ipnet) {
				m.dstExcludesIps[ipnet.IP.String()] = true
				continue
			}
			m.dstExcludes = append(m.dstExcludes, ipnet)
		}
	}

	return m, nil
}

// MatchSrcIP matches sr cips and check if it's on networks included list
// at the same time checking if it's not in any excluded list.
func (m *Network) MatchSrcIP(srcIP net.IP) (bool, bool) {
	if srcIP == nil {
		return false, false
	}

	// check if the ip is included in source networks
	ok := false
	for _, n := range m.srcIncludes {
		if n.Contains(srcIP) {
			ok = true
			break
		}
	}

	// if the ip is not in any networks, it means that ip is not matched
	if !ok {
		return false, false
	}

	// check ip exclusion
	if m.srcExcludesIps[srcIP.String()] {
		return true, true
	}

	// if the ip is within any excluded source network
	for _, n := range m.srcExcludes {
		if n.Contains(srcIP) {
			return true, true
		}
	}

	return true, false
}

// MatchDstIP matches dest ips and check if it's on networks included list
// at the same time checking if it's not in any excluded list.
func (m *Network) MatchDstIP(dstIP net.IP) (bool, bool) {
	if dstIP == nil {
		return false, false
	}

	// check if the ip is included in destination networks
	ok := false
	for _, n := range m.dstIncludes {
		if n.Contains(dstIP) {
			ok = true
			break
		}
	}

	if !ok {
		return false, false
	}

	// check ip exclusion
	if m.dstExcludesIps[dstIP.String()] {
		return true, true
	}

	// if the ip is within any excluded destination network
	for _, n := range m.dstExcludes {
		if n.Contains(dstIP) {
			return true, true
		}
	}

	return true, false
}

// Match matches src and dest ips and check if it's on networks included list
// at the same time checking if it's not in any excluded list.
func (m *Network) Match(srcIP, dstIP net.IP) (bool, bool) {
	matched, excluded := m.MatchSrcIP(srcIP)
	if !matched || (matched && excluded) {
		return matched, excluded
	}

	return m.MatchDstIP(dstIP)
}

func isIpnetIP(ipnet *net.IPNet) bool {
	once, _ := ipnet.Mask.Size()
	return (ipnet.IP.To4() != nil && once == 32) || once == 128
}
