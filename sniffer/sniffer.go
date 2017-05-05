// Package dns provides functions for DNS packet sniffing.
package sniffer

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// FQDNFilter is a type representing domain filter.
// If domain is found in filter, packet is not stored.
type FQDNFilter func([]byte) bool

// IPFilter is a type representing IP filter.
// If IP is found in filter, packet is not stored.
type IPFilter func(net.IP) bool

// Sniffer is performing DNS request sniffing on local NIC.
type Sniffer struct {
	S chan *DNSPacket

	handle     *pcap.Handle
	source     *gopacket.PacketSource
	ipFilter   IPFilter
	fqdnFilter FQDNFilter
}

type DNSQuestion struct {
	FQDN string
	Type string
}

type DNSPacket struct {
	SrcIP     net.IP
	Questions []layers.DNSQuestion
}

// NewSniffer is preparing sniffer to capture packets.
// After this function finish, packets can be retrieved from packetSource
func NewSniffer(protocols []string, port int, iface string) (*Sniffer, error) {
	handle, err := pcap.OpenLive(iface, 1600, false, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	if err := handle.SetBPFFilter("udp dst port 53"); err != nil {
		handle.Close()
		return nil, err
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	return &Sniffer{
		source: packetSource,
		handle: handle,
		S:      make(chan *DNSPacket, 2048),
	}, nil
}

// SetFQDNFilter sets domain filter on Sniffer
func (s *Sniffer) SetFQDNFilter(f FQDNFilter) {
	s.fqdnFilter = f
}

// SetIPFilter sets IP filter on Sniffer
func (s *Sniffer) SetIPFilter(f IPFilter) {
	s.ipFilter = f
}

// Sniff returs valid packet from packetSource
func (s *Sniffer) Sniff() *DNSPacket {
	for {
		rawPacket, err := s.source.NextPacket()
		if err != nil {
			continue
		}

		dnspacket := s.decodeRawPacket(rawPacket)
		if dnspacket == nil {
			continue
		}

		if s.shouldFilterDSNPacket(dnspacket) {
			continue
		}
		return dnspacket
	}
}

// Close stops Sniffer.
func (s *Sniffer) Close() {
	s.handle.Close()
}

func (s *Sniffer) shouldFilterDSNPacket(dp *DNSPacket) bool {
	if s.ipFilter != nil {
		if s.ipFilter(dp.SrcIP) {
			return true
		}
	}
	if s.fqdnFilter != nil {
		for i := range dp.Questions {
			if s.fqdnFilter(dp.Questions[i].Name) {
				return true
			}
		}
	}
	return false
}

func (s *Sniffer) decodeRawPacket(packet gopacket.Packet) *DNSPacket {
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return nil
	}
	dns := dnsLayer.(*layers.DNS)
	if dns.QR {
		return nil
	}

	var dnsPacket DNSPacket
	if IP4layer := packet.Layer(layers.LayerTypeIPv4); IP4layer != nil {
		dnsPacket.SrcIP = IP4layer.(*layers.IPv4).SrcIP
	} else if IP6layer := packet.Layer(layers.LayerTypeIPv6); IP6layer != nil {
		return nil
	}

	dnsPacket.Questions = dns.Questions
	return &dnsPacket
}
