package helpers

import (
	"github.com/alphasoc/namescore/client"
	"github.com/google/gopacket"
)

// DecodePackets into api Queries request.
// Packtes that has diffrent header then DNS are droped.
func DecodePackets(packets []gopacket.Packet) *client.QueriesRequest {
	qs := QueriesRequest{Data: make([][4]string, 0, len(packets))}

	for i := range packets {

	}
	return nil
}
