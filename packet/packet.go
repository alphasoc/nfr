package packet

import (
	"bytes"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// RawPacket is an interface that wraps method for raw packet
type RawPacket interface {
	Raw() gopacket.Packet
}

// Direction of the packet.
type Direction int

// List of all packet directions
const (
	DirectionUnknown Direction = 0
	DirectionIn      Direction = 1
	DirectionOut     Direction = 2
)

// IPPacket represents single dns query that could be
// converted to feed AlphaSOC API.
type IPPacket struct {
	raw    gopacket.Packet
	srcMAC net.HardwareAddr

	Timestamp  time.Time
	Protocol   string
	SrcIP      net.IP
	SrcPort    int
	DstIP      net.IP
	DstPort    int
	BytesCount int
	Direction  Direction
}

// NewIPPacket creates IPPacket from raw packet.
func NewIPPacket(raw gopacket.Packet) *IPPacket {
	linkLayer := raw.LinkLayer()
	networkLayer := raw.NetworkLayer()
	transportLayer := raw.TransportLayer()
	metadata := raw.Metadata()

	if linkLayer == nil || networkLayer == nil ||
		transportLayer == nil || metadata == nil {
		return nil
	}

	ethernet, ok := linkLayer.(gopacket.Layer).(*layers.Ethernet)
	if !ok {
		return nil
	}

	var ippacket = &IPPacket{
		raw:        raw,
		srcMAC:     ethernet.SrcMAC,
		Timestamp:  metadata.Timestamp,
		BytesCount: len(raw.Data()),
	}
	if lipv4, ok := networkLayer.(gopacket.Layer).(*layers.IPv4); ok {
		ippacket.SrcIP = lipv4.SrcIP
		ippacket.DstIP = lipv4.DstIP
	} else if lipv6, ok := networkLayer.(gopacket.Layer).(*layers.IPv6); ok {
		ippacket.SrcIP = lipv6.SrcIP
		ippacket.DstIP = lipv6.DstIP
	} else {
		return nil
	}

	if tcp, ok := transportLayer.(gopacket.Layer).(*layers.TCP); ok {
		ippacket.SrcPort = int(tcp.SrcPort)
		ippacket.DstPort = int(tcp.DstPort)
		ippacket.Protocol = "tcp"
	} else if udp, ok := transportLayer.(gopacket.Layer).(*layers.UDP); ok {
		ippacket.SrcPort = int(udp.SrcPort)
		ippacket.DstPort = int(udp.DstPort)
		ippacket.Protocol = "udp"
	} else {
		return nil
	}

	return ippacket
}

// Raw returns raw packet.
func (p *IPPacket) Raw() gopacket.Packet {
	return p.raw
}

// DetermineDirection determines packet direciton based on interface mac address.
func (p *IPPacket) DetermineDirection(ifaceMac net.HardwareAddr) {
	if bytes.Equal(p.srcMAC, ifaceMac) {
		p.Direction = DirectionOut
	} else {
		p.Direction = DirectionIn
	}
}

// DNSPacket represents single dns query that could be
// converted to feed AlphaSOC API.
type DNSPacket struct {
	raw gopacket.Packet

	Timestamp  time.Time
	Protocol   string
	SrcPort    int
	DstPort    int
	SrcIP      net.IP
	FQDN       string
	RecordType string
}

// NewDNSPacket creates new dns packet from raw packet.
func NewDNSPacket(raw gopacket.Packet) *DNSPacket {
	var (
		metadata         = raw.Metadata()
		networkLayer     = raw.NetworkLayer()
		transportLayer   = raw.TransportLayer()
		applicationLayer = raw.ApplicationLayer()
	)

	if metadata == nil || networkLayer == nil || transportLayer == nil || applicationLayer == nil {
		return nil
	}

	dns, ok := applicationLayer.(gopacket.Layer).(*layers.DNS)
	if !ok || dns.QR || len(dns.Questions) == 0 {
		return nil
	}

	var dnspacket = &DNSPacket{
		raw:        raw,
		Timestamp:  metadata.Timestamp,
		RecordType: dns.Questions[0].Type.String(),
		FQDN:       string(dns.Questions[0].Name),
	}

	if lipv4, ok := networkLayer.(gopacket.Layer).(*layers.IPv4); ok {
		dnspacket.SrcIP = lipv4.SrcIP
	} else if lipv6, ok := networkLayer.(gopacket.Layer).(*layers.IPv6); ok {
		dnspacket.SrcIP = lipv6.SrcIP
	} else {
		return nil
	}

	if tcp, ok := transportLayer.(gopacket.Layer).(*layers.TCP); ok {
		dnspacket.SrcPort = int(tcp.SrcPort)
		dnspacket.DstPort = int(tcp.DstPort)
		dnspacket.Protocol = "tcp"
	} else if udp, ok := transportLayer.(gopacket.Layer).(*layers.UDP); ok {
		dnspacket.SrcPort = int(udp.SrcPort)
		dnspacket.DstPort = int(udp.DstPort)
		dnspacket.Protocol = "udp"
	} else {
		return nil
	}

	return dnspacket
}

func (p *DNSPacket) String() string {
	return fmt.Sprintf("%s %s from %s", p.FQDN, p.RecordType, p.SrcIP.String())
}

// Equal checks if two packets are equal.
func (p *DNSPacket) Equal(p1 *DNSPacket) bool {
	if p == nil || p1 == nil {
		return false
	}
	return p.SrcIP.Equal(p1.SrcIP) &&
		p.RecordType == p1.RecordType &&
		p.FQDN == p1.FQDN
}

// Raw returns raw packet.
func (p *DNSPacket) Raw() gopacket.Packet {
	return p.raw
}
