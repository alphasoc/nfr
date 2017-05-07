package utils

import (
	"net"
	"time"

	"github.com/alphasoc/namescore/client"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// DecodePackets into api Queries request.
// Packtes that has diffrent header then DNS are droped.
func DecodePackets(packets []gopacket.Packet) *client.QueriesRequest {
	qr := client.QueriesRequest{Data: make([][4]string, 0, len(packets))}

	for i := range packets {
		ldns, ok := packets[i].ApplicationLayer().(gopacket.Layer).(*layers.DNS)
		if !ok || ldns.QR {
			continue
		}

		timestamp := time.Now()
		if md := packets[i].Metadata(); md != nil {
			timestamp = md.Timestamp
		}

		var srcIP net.IP
		if lipv4, ok := packets[i].TransportLayer().(gopacket.Layer).(*layers.IPv4); ok {
			srcIP = lipv4.SrcIP
		} else if lipv6, ok := packets[i].TransportLayer().(gopacket.Layer).(*layers.IPv6); ok {
			srcIP = lipv6.SrcIP
		}

		for _, q := range ldns.Questions {
			qr.Data = append(qr.Data, [4]string{
				timestamp.Format(time.RFC3339),
				srcIP.String(),
				q.Type.String(),
				string(q.Name),
			})
		}
	}
	return nil
}

// IPNetIntersect checks for intersection of two net.IPNet
// IPNet must have the same IP type
func IPNetIntersect(n1, n2 *net.IPNet) bool {
        for i := range n1.IP {
                if n1.IP[i] & n1.Mask[i] != n2.IP[i] & n2.Mask[i] & n1.Mask[i] {
                        return false
                }
        }
        return true
}
