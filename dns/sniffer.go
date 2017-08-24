package dns

import (
	"fmt"

	log "github.com/Sirupsen/logrus"
	"github.com/alphasoc/nfr/groups"
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

// newsniffer creates new sniffer and sets pcap filter for it.
func newsniffer(handle *pcap.Handle, protocols []string, port int) (*Sniffer, error) {
	if len(protocols) > 2 {
		handle.Close()
		return nil, fmt.Errorf("too many protocols in list")
	}

	for _, proto := range protocols {
		if proto != "udp" && proto != "tcp" {
			handle.Close()
			return nil, fmt.Errorf("invalid protocol %q name", proto)
		}
	}

	if port < 0 || port > 65355 {
		handle.Close()
		return nil, fmt.Errorf("invalid %d port number", port)
	}

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
		if p := newPacket(packet); p != nil && s.shouldSendPacket(p) {
			s.c <- p
		}
	}
}

// shouldSendPackets test if packet should be send to channel
func (s *Sniffer) shouldSendPacket(p *Packet) bool {
	// no scope groups configured
	if s.groups == nil {
		return true
	}
	name, t := s.groups.IsDNSQueryWhitelisted(p.FQDN, p.SourceIP)
	if !t {
		log.Debugf("dns query %s excluded by %s group", p, name)
	}
	return t
}

// print pcap format filter based on protocols and port
func sprintBPFFilter(protocols []string, port int) string {
	switch len(protocols) {
	case 1:
		return fmt.Sprintf("%s dst port %d", protocols[0], port)
	default:
		return fmt.Sprintf("tcp or udp dst port %d", port)
	}
}
