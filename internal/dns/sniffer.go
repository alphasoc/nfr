package dns

import (
	"net"
	"time"

	"github.com/alphasoc/namescore/internal/asoc"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// FQDNFilter is a type representing domain filter.
// If domain is found in filter, packet is not stored.
type FQDNFilter func(string) bool

// IPFilter is a type representing IP filter.
// If IP is found in filter, packet is not stored.
type IPFilter func(net.IP) bool

// Capture is interface for DNS packet sniffer.
type Capture interface {
	Sniff() gopacket.Packet
	PacketToEntry(packet gopacket.Packet) []asoc.Entry
	Close()
}

// Sniffer is performing DNS request sniffing on local NIC.
type Sniffer struct {
	handle     *pcap.Handle
	source     *gopacket.PacketSource
	ipFilter   IPFilter
	fqdnFilter FQDNFilter
}

// Start is preparing sniffer to capture packets.
// After this function finish, packets can be retrieved from packetSource
// by using Sniff() function.
func Start(iface string) (*Sniffer, error) {
	handle, err := pcap.OpenLive(iface, 1600, false, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	if err := handle.SetBPFFilter("udp dst port 53"); err != nil {
		handle.Close()
		return nil, err
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	return &Sniffer{source: packetSource, handle: handle}, nil
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
func (s *Sniffer) Sniff() gopacket.Packet {
	for {
		if packet, err := s.source.NextPacket(); err == nil {
			return packet
		}
	}
}

// PacketToEntry converts packet to asoc.Entry.
// If packet does not meet requirements nil is retured.
func (s *Sniffer) PacketToEntry(packet gopacket.Packet) []asoc.Entry {
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return nil
	}
	dns, _ := dnsLayer.(*layers.DNS)
	if dns.QR {
		return nil
	}

	var IP net.IP
	if IP4layer := packet.Layer(layers.LayerTypeIPv4); IP4layer != nil {
		ip, _ := IP4layer.(*layers.IPv4)
		IP = ip.SrcIP
	} else if IP6layer := packet.Layer(layers.LayerTypeIPv6); IP6layer != nil {
		ip, _ := IP6layer.(*layers.IPv6)
		IP = ip.SrcIP
	}
	var entries []asoc.Entry
	t := time.Now()
	for i := range dns.Questions {
		if s.fqdnFilter != nil {
			if s.fqdnFilter(string(dns.Questions[i].Name)) {
				return nil
			}
			if s.ipFilter(IP) {
				return nil
			}
		}
		entries = append(entries, asoc.Entry{Time: t, IP: IP, QType: dns.Questions[i].Type.String(), FQDN: string(dns.Questions[i].Name)})
	}
	return entries
}

// Close stops Sniffer.
func (s *Sniffer) Close() {
	s.handle.Close()
}
