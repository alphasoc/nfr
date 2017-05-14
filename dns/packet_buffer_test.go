package dns

import "testing"

func TestBasicOperations(t *testing.T) {
	b := NewPacketBuffer()
	if l := b.Write(&Packet{}); l != 1 {
		t.Fatalf("invalid buffer length - got %d; expected %d", l, 1)
	}
	if packets := b.Packets(); len(packets) != 1 {
		t.Fatalf("invalid packet length")
	}
	if l := b.len(); l != 0 {
		t.Fatalf("invalid buffer length - got %d; expected %d", l, 0)
	}
}
