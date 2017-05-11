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

// Len returns the number of packets.
func (b *PacketBuffer) Len() int {
	return len(b.packets)
}

// Writes appends single packet to buffer.
func (b *PacketBuffer) Write(packets ...*Packet) {
	b.packets = append(b.packets, packets...)
}

// Packets returns slice of packets.
func (b *PacketBuffer) Packets() []*Packet {
	return b.packets
}

// Reset resets the buffer to be empty.
func (b *PacketBuffer) Reset() {
	b.packets = b.packets[0:0]
}
