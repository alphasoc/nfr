package dns

import (
	"net"
	"time"

	"github.com/alphasoc/namescore/internal/asoc"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type FQDNFilter func(string) bool
type IPFilter func(net.IP) bool

type DNSCapture interface {
	Sniff() gopacket.Packet
	PacketToEntry(packet gopacket.Packet) []asoc.Entry
}

type Sniffer struct {
	handle     *pcap.Handle
	source     *gopacket.PacketSource
	ipFilter   IPFilter
	fqdnFilter FQDNFilter
}

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

func (s *Sniffer) SetFQDNFilter(f FQDNFilter) {
	s.fqdnFilter = f
}

func (s *Sniffer) SetIPFilter(f IPFilter) {
	s.ipFilter = f
}

func (s *Sniffer) Sniff() gopacket.Packet {
	for {
		packet, err := s.source.NextPacket()
		if err != nil {
			continue
		}
		return packet
	}
}

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
