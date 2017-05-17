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
// Returns number of packets added to buffer and buffer length.
func (b *PacketBuffer) Write(packets ...*Packet) (int, int) {
	// do not write packets that was duplicated recentrly
	// checks 8 packets back.
	l := b.len()
	pos := l - 8
	if pos < 0 {
		pos = 0
	}
	add := 0

packetLoop:
	for i := range packets {
		for j := pos; j < l; j++ {
			if b.packets[j].Equal(packets[i]) {
				continue packetLoop
			}
		}
		b.packets = append(b.packets, packets[i])
		pos++
		add++
	}

	return add, b.len()
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
