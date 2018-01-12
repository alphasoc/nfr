package sniffer

import (
	"fmt"

	"github.com/alphasoc/nfr/dns"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Sniffer is an interface for iterate over captured packets.
type Sniffer interface {
	Packets() chan *dns.Packet // channel with captured packets
}

// PcapSniffer sniffs dns packets.
type PcapSniffer struct {
	handle *pcap.Handle
	source *gopacket.PacketSource
	c      chan *dns.Packet
}

// NewLivePcapSniffer creates sniffer that capture packets from interface.
func NewLivePcapSniffer(iface string, protocols []string, port int) (*PcapSniffer, error) {
	handle, err := pcap.OpenLive(iface, 1600, false, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	return newsniffer(handle, protocols, port)
}

// NewOfflinePcapSniffer creates sniffer that capture packets from pcap file.
func NewOfflinePcapSniffer(file string, protocols []string, port int) (*PcapSniffer, error) {
	handle, err := pcap.OpenOffline(file)
	if err != nil {
		return nil, err
	}
	return newsniffer(handle, protocols, port)
}

// newsniffer creates new sniffer and sets pcap filter for it.
func newsniffer(handle *pcap.Handle, protocols []string, port int) (*PcapSniffer, error) {
	filter, err := sprintBPFFilter(protocols, port)
	if err != nil {
		handle.Close()
		return nil, err
	}

	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return nil, err
	}

	return &PcapSniffer{
		source: gopacket.NewPacketSource(handle, handle.LinkType()),
		handle: handle,
	}, nil
}

// Packets returns a channel of captured packets, allowing easy iterating over packets.
func (s *PcapSniffer) Packets() chan *dns.Packet {
	if s.c == nil {
		s.c = make(chan *dns.Packet, 2048)
		go s.readPackets()
	}
	return s.c
}

// Close closes underlying handle and stops sniffer.
func (s *PcapSniffer) Close() {
	s.handle.Close()
}

// readPackets reads in all packets from the pcap source and creates
// new *Packet that is sent to the channel.
func (s *PcapSniffer) readPackets() {
	defer close(s.c)
	for packet := range s.source.Packets() {
		if p := dns.NewPacket(packet); p != nil {
			s.c <- p
		}
	}
}

// print pcap format filter based on protocols and port
func sprintBPFFilter(protocols []string, port int) (string, error) {
	if len(protocols) > 2 {
		return "", fmt.Errorf("too many protocols in list")
	}

	for _, proto := range protocols {
		if proto != "udp" && proto != "tcp" {
			return "", fmt.Errorf("invalid protocol %q name", proto)
		}
	}

	if port < 0 || port > 65355 {
		return "", fmt.Errorf("invalid %d port number", port)
	}

	switch len(protocols) {
	case 1:
		return fmt.Sprintf("%s dst port %d", protocols[0], port), nil
	default:
		return fmt.Sprintf("tcp or udp dst port %d", port), nil
	}
}
