package packet

import (
	"net"

	"testing"
)

func TestDNSBufferWrite(t *testing.T) {
	b := NewDNSPacketBuffer()

	p1 := &DNSPacket{SrcIP: net.IP{1, 1, 1, 1}}
	p2 := &DNSPacket{SrcIP: net.IP{2, 2, 2, 2}}
	p3 := &DNSPacket{SrcIP: net.IP{3, 3, 3, 3}}

	b.Write(p1)
	b.Write(p2)
	b.Write(p1) // should be deduplicated

	packets := b.Packets()
	if len(packets) != 2 {
		t.Fatalf("invalid packet length: %d", len(packets))
	}

	if packets[0] != p1 {
		t.Fatalf("invalid packet at 0: %v", packets[0])
	}
	if packets[1] != p2 {
		t.Fatalf("invalid packet at 1: %v", packets[1])
	}

	if l := b.Len(); l != 0 {
		t.Fatalf("invalid buffer length - got %d; expected %d", l, 0)
	}

	// write to buffer after reset, make sure previous packets
	// are not overwritten.
	b.Write(p3)
	if packets[0] != p1 {
		t.Fatalf("invalid packet at 0 after reset: %v", packets[0])
	}
}

func TestIPBufferWrite(t *testing.T) {
	b := NewIPPacketBuffer()

	p1 := &IPPacket{SrcIP: net.IP{1, 1, 1, 1}}
	p2 := &IPPacket{SrcIP: net.IP{2, 2, 2, 2}}
	p3 := &IPPacket{SrcIP: net.IP{3, 3, 3, 3}}

	b.Write(p1)
	b.Write(p2)
	b.Write(p1) // not deduplicated for IPs

	packets := b.Packets()
	if len(packets) != 3 {
		t.Fatalf("invalid packet length: %d", len(packets))
	}

	if packets[0] != p1 {
		t.Fatalf("invalid packet at 0: %v", packets[0])
	}
	if packets[1] != p2 {
		t.Fatalf("invalid packet at 1: %v", packets[1])
	}
	if packets[2] != p1 {
		t.Fatalf("invalid packet at 1: %v", packets[2])
	}

	if l := b.Len(); l != 0 {
		t.Fatalf("invalid buffer length - got %d; expected %d", l, 0)
	}

	// write to buffer after reset, make sure previous packets
	// are not overwritten.
	b.Write(p3)
	if packets[0] != p1 {
		t.Fatalf("invalid packet at 0 after reset: %v", packets[0])
	}
}
