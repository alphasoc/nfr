package packet

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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

func TestNewPacket(t *testing.T) {
	rawPacket := gopacket.NewPacket(testPacketDNSQuery, layers.LinkTypeEthernet, gopacket.Default)
	checkDNSPacket(t, rawPacket)
}

func TestDNSPacketEqual(t *testing.T) {
	packet := NewDNSPacket(gopacket.NewPacket(testPacketDNSQuery, layers.LinkTypeEthernet, gopacket.Default))
	if packet.Equal(nil) {
		t.Fatalf("equal with nil must return false")
	}

	if !packet.Equal(packet) {
		t.Fatalf("packet not equal to itself")
	}
}

func TestToRequestQuery(t *testing.T) {
	packet := NewDNSPacket(gopacket.NewPacket(testPacketDNSQuery, layers.LinkTypeEthernet, gopacket.Default))
	if s := packet.ToRequestQuery(); s[1] != "10.0.2.15" || s[2] != "A" || s[3] != "api.alphasoc.net" {
		t.Fatalf("invalid request query %v", s)
	}
}

func checkDNSPacket(t *testing.T, rawPacket gopacket.Packet) {
	packet := NewDNSPacket(rawPacket)
	if packet == nil {
		t.Fatal("got nic packet")
	}

	if packet.FQDN != "api.alphasoc.net" {
		t.Fatalf("invalid fqdn - got %s; exptected %s", packet.FQDN, "api.alphasoc.net")
	}
	if packet.RecordType != "A" {
		t.Fatalf("invalid recort type - got %s; exptected %s", packet.RecordType, "A")
	}
	if packet.SrcIP.String() != "10.0.2.15" {
		t.Fatalf("invalid source ip - got %s; exptected %s", packet.SrcIP, "10.0.2.15")
	}
}
