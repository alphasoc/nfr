package pcap

import (
	"github.com/alphasoc/nfr/packet"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// A Reader reads network events from pcap logs.
type Reader struct {
	handle *pcap.Handle
}

// NewReader creates new pcap reader. Logs will be read from given file.
func NewReader(filename string) (*Reader, error) {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return nil, err
	}

	return &Reader{handle: handle}, nil
}

// ReadDNS reads all dns packets from the file.
func (r *Reader) ReadDNS() ([]*packet.DNSPacket, error) {
	var packets []*packet.DNSPacket

	source := gopacket.NewPacketSource(r.handle, r.handle.LinkType())
	for raw := range source.Packets() {
		if dnspacket := packet.NewDNSPacket(raw); dnspacket != nil {
			packets = append(packets, dnspacket)
		}
	}
	return packets, nil
}

// ReadIP reads all ip packets from the file.
func (r *Reader) ReadIP() ([]*packet.IPPacket, error) {
	var packets []*packet.IPPacket

	source := gopacket.NewPacketSource(r.handle, r.handle.LinkType())
	for raw := range source.Packets() {
		if ippacket := packet.NewIPPacket(raw); ippacket != nil {
			packets = append(packets, ippacket)
		}
	}
	return packets, nil
}

// Close underlying log file.
func (r *Reader) Close() error {
	r.handle.Close()
	return nil
}
