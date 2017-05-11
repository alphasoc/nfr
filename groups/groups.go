package groups

import (
	"net"
	"strings"

	"github.com/alphasoc/namescore/config"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Group struct {
	Name 		string
	network         []*net.IPNet
	excludedNetworks []*net.IPNet
	excludedIPs     []net.IP
	excludedDomains []string
}

func NewGroup(name string, networks []string, excludedNetworks []string, excludedDomains) *Group {
}

type matchers struct {
	dm *utils.DomainMatcher
	nm *utils.NetworkMacher
}

type Groups struct {
	groups map[string] matchers
}

func New() *Groups {
	gs := cfg.WhiteListConfig.GroupByName
	if len(gs) == 0 {
		return nil
	}

	gf := GroupsFilter{make(map[string]group)}
	for name, k := range gs {
		_, network, _ := net.ParseCIDR(k.MonitoredNetwork)

		g := group{network: network}
		for _, exn := range k.ExcludedNetworks {
			if _, exn1, _ := net.ParseCIDR(exn); exn1 != nil {
				g.excludedNets = append(g.excludedNets, exn1)
			} else if exip := net.ParseIP(exn); exip != nil {
				g.excludedIPs = append(g.excludedIPs, exip)
			}
		}

		for _, domain := range k.ExcludedDomains {
			if strings.HasPrefix(domain, "*") {
				g.excludedMultimatchDomains = append(g.excludedMultimatchDomains, domain[1:])
			} else {
				g.excludedStrictDomains = append(g.excludedStrictDomains, domain)
			}
		}
		gf.groups[name] = g
	}
	return &gf
}

func (g *Groups) Add(g *Group) {
	if g == nil {
		return
	}
}

func (g *Groups) Filter(packets []gopacket.Packet) []gopacket.Packet {
	if g == nil {
		return packets
	}

	n := 0
	for _, packet := range packets {
		l, ok := packet.ApplicationLayer().(gopacket.Layer).(*layers.DNS)
		if !ok || l.QR || len(l.Questions) == 0 {
			continue
		}

		var srcIP net.IP
		if lipv4, ok := packet.TransportLayer().(gopacket.Layer).(*layers.IPv4); ok {
			srcIP = lipv4.SrcIP
		} else if lipv6, ok := packet.TransportLayer().(gopacket.Layer).(*layers.IPv6); ok {
			srcIP = lipv6.SrcIP
		} else {
			continue
		}

		match := false
		for _, m := range f.groups {
			if m.nm.Match(srcIP) && !m.dm.Match(string(l.Questions[0].Name)) {
				match = true
				break
			}
		}

		if match {
			packets[n] = packet
			n++
		}
	}
	return packets[:n]
}
