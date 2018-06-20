package packet

// A IPPacketBuffer holds slice of packets.
type IPPacketBuffer struct {
	packets []*IPPacket
}

// NewIPPacketBuffer initializes a new IPPacketBuffer.
func NewIPPacketBuffer() *IPPacketBuffer {
	return &IPPacketBuffer{packets: make([]*IPPacket, 0, 1024)}
}

// Writes single ip packet to the buffer.
func (b *IPPacketBuffer) Write(packets ...*IPPacket) {
	b.packets = append(b.packets, packets...)
}

// Packets returns slice of packets and reset the buffer.
func (b *IPPacketBuffer) Packets() []*IPPacket {
	packets := make([]*IPPacket, len(b.packets))
	copy(packets, b.packets)
	b.packets = b.packets[:0]
	return packets
}

// Len returns the number of packets in the buffer.
func (b *IPPacketBuffer) Len() int {
	return len(b.packets)
}

// reset resets the buffer to be empty.
func (b *IPPacketBuffer) reset() {
	b.packets = b.packets[:0]
}
