package packet

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

// testPacketPacket0 is the packet:
//   13:35:56.456790 IP 10.0.2.15.13705 > 8.8.8.8.53: 59721+ [1au] A? api.alphasoc.net. (45)
//   	0x0000:  5254 0012 3502 0800 27b1 891d 0800 4500  RT..5...'.....E.
//   	0x0010:  0049 734b 4000 4011 ab3a 0a00 020f 0808  .IsK@.@..:......
//   	0x0020:  0808 3589 0035 0035 1c65 e949 0120 0001  ..5..5.5.e.I....
//   	0x0030:  0000 0000 0001 0361 7069 0861 6c70 6861  .......api.alpha
//   	0x0040:  736f 6303 6e65 7400 0001 0001 0000 2910  soc.net.......).
//   	0x0050:  0000 0000 0000 00                        .......
var testPacketDNSQuery = []byte{
	0x52, 0x54, 0x00, 0x12, 0x35, 0x02, 0x08, 0x00, 0x27, 0xb1, 0x89, 0x1d, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x49, 0x73, 0x4b, 0x40, 0x00, 0x40, 0x11, 0xab, 0x3a, 0x0a, 0x00, 0x02, 0x0f, 0x08, 0x08,
	0x08, 0x08, 0x35, 0x89, 0x00, 0x35, 0x00, 0x35, 0x1c, 0x65, 0xe9, 0x49, 0x01, 0x20, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x61, 0x70, 0x69, 0x08, 0x61, 0x6c, 0x70, 0x68, 0x61,
	0x73, 0x6f, 0x63, 0x03, 0x6e, 0x65, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x10,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

const testPacketDNSQueryLenght = 87

func TestNewDNSPacket(t *testing.T) {
	rawPacket := gopacket.NewPacket(testPacketDNSQuery, layers.LinkTypeEthernet, gopacket.Default)
	packet := NewDNSPacket(rawPacket)
	require.NotNil(t, packet)
	require.Equal(t, "api.alphasoc.net", packet.FQDN, "invalid fqdn")
	require.Equal(t, "A", packet.RecordType, "invalid record type")
	require.True(t, net.IPv4(10, 0, 2, 15).Equal(packet.SrcIP), "invalid soruce ip")
}

func TestDNSPacketEqual(t *testing.T) {
	packet := NewDNSPacket(gopacket.NewPacket(testPacketDNSQuery, layers.LinkTypeEthernet, gopacket.Default))
	require.False(t, packet.Equal(nil), "equal with nil must return false")
	require.True(t, packet.Equal(packet), "not equal with itself")
}

func TestNewIPPacket(t *testing.T) {
	rawPacket := gopacket.NewPacket(testPacketDNSQuery, layers.LinkTypeEthernet, gopacket.Default)
	packet := NewIPPacket(rawPacket)
	require.NotNil(t, packet)

	packet.DetermineDirection(net.HardwareAddr{0x8, 0x0, 0x27, 0xb1, 0x89, 0x1d})
	require.Equal(t, "udp", packet.Protocol)
	require.True(t, packet.SrcIP.Equal(net.IPv4(10, 0, 2, 15)))
	require.Equal(t, 13705, packet.SrcPort)
	require.True(t, packet.DstIP.Equal(net.IPv4(8, 8, 8, 8)))
	require.Equal(t, 53, packet.DstPort)
	require.Equal(t, DirectionOut, packet.Direction)
}
