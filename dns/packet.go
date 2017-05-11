package dns

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Packet represents single dns question packet that could be
// easily converted to feed AlphaSOC API.
type Packet struct {
	raw gopacket.Packet

	Timestamp  time.Time
	SourceIP   net.IP
	RecordType string
	FQDN       string
}

// newPackets creates packet from gopacket type.
// It returns nil if packet is not dns quesiton packet
// or metadata is missing.
func newPacket(packet gopacket.Packet) *Packet {
	l, ok := packet.ApplicationLayer().(gopacket.Layer).(*layers.DNS)
	if !ok || l.QR || len(l.Questions) == 0 {
		return nil
	}

	md := packet.Metadata()
	if md == nil {
		return nil
	}

	var srcIP net.IP
	if lipv4, ok := packet.TransportLayer().(gopacket.Layer).(*layers.IPv4); ok {
		srcIP = lipv4.SrcIP
	} else if lipv6, ok := packet.TransportLayer().(gopacket.Layer).(*layers.IPv6); ok {
		srcIP = lipv6.SrcIP
	} else {
		return nil
	}

	return &Packet{
		raw:        packet,
		Timestamp:  md.Timestamp,
		SourceIP:   srcIP,
		RecordType: l.Questions[0].Type.String(),
		FQDN:       string(l.Questions[0].Name),
	}
}

// ToRequestQuery converts packet into valid api request data.
func (p *Packet) ToRequestQuery() [4]string {
	return [4]string{
		p.Timestamp.Format(time.RFC3339),
		p.SourceIP.String(),
		p.RecordType,
		p.FQDN,
	}
}

// Decode decodes slice of packets into packets that could be converted to feed AlphaSOC api.
// func Decode(packets []gopacket.Packet) []*Packet {
// 	p := make([]*Packet, 0, len(packets))
//
// 	for i := range packets {
// 		l, ok := packets[i].ApplicationLayer().(gopacket.Layer).(*layers.DNS)
// 		if !ok || l.QR || len(l.Questions) == 0 {
// 			continue
// 		}
//
// 		md := packets[i].Metadata()
// 		if md == nil {
// 			continue
// 		}
//
// 		var srcIP net.IP
// 		if lipv4, ok := packets[i].TransportLayer().(gopacket.Layer).(*layers.IPv4); ok {
// 			srcIP = lipv4.SrcIP
// 		} else if lipv6, ok := packets[i].TransportLayer().(gopacket.Layer).(*layers.IPv6); ok {
// 			srcIP = lipv6.SrcIP
// 		} else {
// 			continue
// 		}
//
// 		p[i] = &Packet{
// 			raw:        packets[i],
// 			Timestamp:  md.Timestamp,
// 			SourceIP:   srcIP,
// 			RecordType: l.Questions[0].Type.String(),
// 			FQDN:       string(l.Questions[0].Name),
// 		}
// 	}
// 	return p
// }
