package queries

import (
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type Buffer struct {
	bufSize int
	packets []gopacket.Packet
	w       *pcapgo.Writer
	f       *os.File
}

func NewBuffer(options ...Option) (*Buffer, error) {
	b := &Buffer{bufSize: 2048}
	for i := range options {
		if err := options[i].apply(b); err != nil {
			return nil, err
		}
	}
	return b, nil
}

func (b *Buffer) Len() int {
	return len(b.packets)
}

func (b *Buffer) Write(packets []gopacket.Packet) error {
	b.packets = append(b.packets, packets...)
	if b.f != nil {
		// save
		for i := range packets {
			md := packets[i].Metadata()
			if md != nil {
				continue
			}
			if err := b.w.WritePacket(md.CaptureInfo, packets[i].Data()); err != nil {
				return err
			}
		}
	}

	return nil
}

func (b *Buffer) Read() []gopacket.Packet {
	packets := b.packets
	b.packets = make([]gopacket.Packet, 0, b.bufSize)
	return packets
}

func (b *Buffer) Close() error {
	if b.f != nil {
		err := b.f.Close()
		b.f = nil
		return err
	}
	return nil
}

func Size(size int) Option {
	return optionFunc(func(b *Buffer) error {
		b.packets = make([]gopacket.Packet, 0, size)
		b.bufSize = size
		return nil
	})
}

func FailedFile(file string) Option {
	return optionFunc(func(b *Buffer) error {
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
	apply(*Buffer) error
}

type optionFunc func(*Buffer) error

func (f optionFunc) apply(b *Buffer) error {
	return f(b)
}
