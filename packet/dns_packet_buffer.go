package packet

// A DNSPacketBuffer holds slice of packets.
type DNSPacketBuffer struct {
	packets []*DNSPacket
}

// NewDNSPacketBuffer initializes a new DNSPacketBuffer.
func NewDNSPacketBuffer() *DNSPacketBuffer {
	return &DNSPacketBuffer{}
}

// Writes single dns packet to the buffer.
// Returns number of packets added to the buffer and length of the buffer.
func (b *DNSPacketBuffer) Write(packets ...*DNSPacket) {
	// do not write packets that was duplicated recentrly
	// checks 8 packets back.
	l := b.Len()
	pos := l - 8
	if pos < 0 {
		pos = 0
	}

packetLoop:
	for i := range packets {
		for j := pos; j < l; j++ {
			if b.packets[j].Equal(packets[i]) {
				continue packetLoop
			}
		}
		b.packets = append(b.packets, packets[i])
		pos++
	}
}

// Packets returns slice of packets and reset the buffer.
func (b *DNSPacketBuffer) Packets() []*DNSPacket {
	packets := b.packets[:]
	b.reset()
	return packets
}

// Len returns the number of packets in the buffer.
func (b *DNSPacketBuffer) Len() int {
	return len(b.packets)
}

// reset resets the buffer to be empty.
func (b *DNSPacketBuffer) reset() {
	b.packets = b.packets[:0]
}
