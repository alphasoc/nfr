package dns

import (
	"fmt"

	"github.com/alphasoc/namescore/groups"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Sniffer sniffs dns packets.
type Sniffer struct {
	handle *pcap.Handle
	source *gopacket.PacketSource
	groups *groups.Groups
	c      chan *Packet
}

// NewLiveSniffer creates sniffer that capture packets from interface.
func NewLiveSniffer(iface string, protocols []string, port int) (*Sniffer, error) {
	handle, err := pcap.OpenLive(iface, 1600, false, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	return newsniffer(handle, protocols, port)
}

// NewOfflineSniffer creates sniffer that capture packets from file.
func NewOfflineSniffer(file string, protocols []string, port int) (*Sniffer, error) {
	handle, err := pcap.OpenOffline(file)
	if err != nil {
		return nil, err
	}
	return newsniffer(handle, protocols, port)

}

func newsniffer(handle *pcap.Handle, protocols []string, port int) (*Sniffer, error) {
	if err := handle.SetBPFFilter(sprintBPFFilter(protocols, port)); err != nil {
		handle.Close()
		return nil, err
	}

	return &Sniffer{
		source: gopacket.NewPacketSource(handle, handle.LinkType()),
		handle: handle,
	}, nil
}

// Packets returns a channel of packets, allowing easy iterating over packets.
func (s *Sniffer) Packets() chan *Packet {
	if s.c == nil {
		s.c = make(chan *Packet, 2048)
		go s.readPackets()
	}
	return s.c
}

// SetGroups sets sniffer groups that will be used to filter caputered packets.
func (s *Sniffer) SetGroups(groups *groups.Groups) {
	s.groups = groups
}

// Close closes underlying handle and stops sniffer.
func (s *Sniffer) Close() {
	s.handle.Close()
}

// readPackets reads in all packets from the pcap source and creates
// new *Packet that is sent to the channel.
func (s *Sniffer) readPackets() {
	defer close(s.c)
	for packet := range s.source.Packets() {
		if p := newPacket(packet); p != nil &&
			(s.groups == nil || (s.groups.IsDomainBlacklisted(p.FQDN) &&
				s.groups.IsIPWhitelisted(p.SourceIP))) {
			s.c <- p
		}
	}
}
func sprintBPFFilter(protocols []string, port int) string {
	fmt.Printf("(udp || tcp) dst port %d dns && (dns.flags.response == 0) && ! dns.response_in", port)
	switch len(protocols) {
	case 1:
		return fmt.Sprintf("%s dst port %d dns && (dns.flags.response == 0) && ! dns.response_in", protocols[0], port)
	default:
		return fmt.Sprintf("(udp || tcp) dst port %d dns && (dns.flags.response == 0) && ! dns.response_in", port)
	}
}
