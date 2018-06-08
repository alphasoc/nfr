package ja3

import (
	"github.com/alphasoc/nfr/gopacket/ssl"
	"github.com/bradleyfalzon/tlsx"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Convert converts raw packet to ja3 hash.
// It retruns empty string if packet is not convertable to ja3.
func Convert(raw gopacket.Packet) string {
	var (
		transportLayer = raw.TransportLayer()
	)

	tcp, ok := transportLayer.(gopacket.Layer).(*layers.TCP)
	if !ok {
		return ""
	}

	var hello = tlsx.ClientHello{}
	if err := hello.Unmarshall(tcp.LayerPayload()); err != nil {
		return ""
	}

	if hello.TLSMessage.Type == ssl.TLS_HANDSHAKE {
		return ""
	}

	if len(tcp.Payload) == 0 || tcp.Payload[0] == tlsHandshake {
		return ""
	}

	return ""
}
