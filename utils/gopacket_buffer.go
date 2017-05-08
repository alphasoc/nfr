package utils

import (
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type PacketBuffer struct {
	bufSize int
	packets []gopacket.Packet
	w       *pcapgo.Writer
	f       *os.File
}

func NewPacketBuffer(options ...Option) (*PacketBuffer, error) {
	b := &PacketBuffer{bufSize: 2048}
	for i := range options {
		if err := options[i].apply(b); err != nil {
			return nil, err
		}
	}
	return b, nil
}

func (b *PacketBuffer) Len() int {
	return len(b.packets)
}

func (b *PacketBuffer) Write(packet gopacket.Packet) error {
	b.packets = append(b.packets, packet)
	if b.w == nil {
		return nil
	}
	// save to file
	md := packet.Metadata()
	if md == nil {
		return nil
	}
	return b.w.WritePacket(md.CaptureInfo, packet.Data())
}

func (b *PacketBuffer) Read() []gopacket.Packet {
	return b.packets
}

func (b *PacketBuffer) Clear() {
	b.packets = make([]gopacket.Packet, 0, b.bufSize)
}

func (b *PacketBuffer) Close() error {
	if b.f != nil {
		err := b.f.Close()
		b.f = nil
		return err
	}
	return nil
}

func Size(size int) Option {
	return optionFunc(func(b *PacketBuffer) error {
		b.packets = make([]gopacket.Packet, 0, size)
		b.bufSize = size
		return nil
	})
}

func FailedFile(file string) Option {
	return optionFunc(func(b *PacketBuffer) error {
		f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE, 0755)
		if err == nil {
			// set file header for new files
			b.f, b.w = f, pcapgo.NewWriter(f)
			return b.w.WriteFileHeader(65536, layers.LinkTypeRaw)
		}

		f, err = os.OpenFile(file, os.O_WRONLY|os.O_APPEND, 0755)
		if err != nil {
			return err
		}

		b.f, b.w = f, pcapgo.NewWriter(f)
		return nil
	})
}

type Option interface {
	apply(*PacketBuffer) error
}

type optionFunc func(*PacketBuffer) error

func (f optionFunc) apply(b *PacketBuffer) error {
	return f(b)
}
