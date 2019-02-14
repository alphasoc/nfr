package packet

import (
	"github.com/alphasoc/nfr/client"
)

// A HTTPPacketBuffer holds slice of packets.
type HTTPPacketBuffer struct {
	packets []*client.HTTPEntry
}

// NewHTTPPacketBuffer initializes a new HTTPPacketBuffer.
func NewHTTPPacketBuffer() *HTTPPacketBuffer {
	return &HTTPPacketBuffer{}
}

// Writes HTTP packets to the buffer.
func (b *HTTPPacketBuffer) Write(packets ...*client.HTTPEntry) {
	b.packets = append(b.packets, packets...)
}

// Packets returns slice of packets and reset the buffer.
func (b *HTTPPacketBuffer) Packets() []*client.HTTPEntry {
	packets := make([]*client.HTTPEntry, len(b.packets))
	copy(packets, b.packets)
	b.packets = b.packets[:0]
	return packets
}

// Len returns the number of packets in the buffer.
func (b *HTTPPacketBuffer) Len() int {
	return len(b.packets)
}
