package filter

import (
	"sort"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Filter interface {
	Filter([]gopacket.Packet) []gopacket.Packet
}

type SrcIPFilter struct {
}

func NewSrcIPFilter() Filter {
	return &SrcIPFilter{}
}

func (f *SrcIPFilter) Filter(packets []gopacket.Packet) []gopacket.Packet {
	return packets
}

type FQDNFilter struct {
	domains []string
}

func NewFQDNFilter(domains []string) Filter {
	sort.Strings(domains)
	return &FQDNFilter{domains}
}

func (f *FQDNFilter) Filter(packets []gopacket.Packet)[]gopacket.Packet {
	n := 0
	for _, packet := range packets {
		l, ok := packet.ApplicationLayer().(gopacket.Layer).(*layers.DNS)
		if !ok || l.QR {
			continue
		}
		for i := range l.Questions {
			j := sort.SearchStrings(f.domains, string(l.Questions[i].Name))
			if j < len(f.domains) && f.domains[j] == string(l.Questions[i].Name) {
				continue
			}
		}
		packets[n] = packet
		n++
	}
	return packets[:n]
}
