package packet

import "testing"

func TestDNSBufferWrite(t *testing.T) {
	b := NewDNSPacketBuffer()

	b.Write(&DNSPacket{})
	b.Write(&DNSPacket{})

	if packets := b.Packets(); len(packets) != 1 {
		t.Fatalf("invalid packet length")
	}
	if l := b.Len(); l != 0 {
		t.Fatalf("invalid buffer length - got %d; expected %d", l, 0)
	}
}
