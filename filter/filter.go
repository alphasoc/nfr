package filter

import (
	"net"
	"sort"
	"strings"

	"github.com/alphasoc/namescore/config"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Filter interface {
	Filter([]gopacket.Packet) []gopacket.Packet
}

type group struct {
	network *net.IPNet
	excludedNets []*net.IPNet
	excludedIPs []net.IP
	excludedStrictDomains []string
	excludedMultimatchDomains []string
}

type GroupsFilter struct {
	groups map[string]group
}

func NewGroupsFilter(cfg *config.Config) Filter {
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
			} else if exip := net.ParseIP(exn); exip !=  nil {
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
		sort.Strings(g.excludedStrictDomains)
		sort.Strings(g.excludedMultimatchDomains)
		gf.groups[name] = g
	}
	return &gf
}

func (f *GroupsFilter) Filter(packets []gopacket.Packet) []gopacket.Packet {
	if f == nil {
		return packets
	}

	n := 0
	for _, packet := range packets {
		l, ok := packet.ApplicationLayer().(gopacket.Layer).(*layers.DNS)
		if !ok || l.QR {
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

gLoop:
		for _, g := range f.groups {
			if g.network.Contains(srcIP) {
				for _, exip := range g.excludedIPs {
					if srcIP.Equal(exip) {
						continue gLoop
					}
				}
				for _, exnet := range g.excludedNets {
					if exnet.Contains(srcIP) {
						continue gLoop
					}
				}
				for i := range l.Questions {
					j := sort.SearchStrings(g.excludedStrictDomains, string(l.Questions[i].Name))
					if j < len(g.excludedStrictDomains) && g.excludedStrictDomains[j] == string(l.Questions[i].Name) {
						continue gLoop
					}

					for _, md := range g.excludedMultimatchDomains {
						if strings.HasSuffix(md, string(l.Questions[i].Name)) {
							continue gLoop
						}
					}
				}
			}
		}

		packets[n] = packet
		n++
	}
	return packets[:n]
}
