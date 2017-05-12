// Package dns implment functions for the manipulation and gather dns packets.
package dns

// A PacketBuffer holds slice of packets, that could be saved into the file.
type PacketBuffer struct {
	packets []*Packet
}

// NewPacketBuffer creates and initializes a new PacketBuffer using given options.
func NewPacketBuffer() *PacketBuffer {
	return &PacketBuffer{}
}

// Writes appends single packet to buffer.
// Returns number of packets in buffer
func (b *PacketBuffer) Write(packets ...*Packet) int {
	b.packets = append(b.packets, packets...)
	return b.len()
}

// Packets returns slice of packets.
func (b *PacketBuffer) Packets() []*Packet {
	packets := b.packets[:]
	b.reset()
	return packets
}

// len returns the number of packets.
func (b *PacketBuffer) len() int {
	return len(b.packets)
}

// Reset resets the buffer to be empty.
func (b *PacketBuffer) reset() {
	b.packets = b.packets[0:0]
}
