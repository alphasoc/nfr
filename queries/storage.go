package queries

import "github.com/google/gopacket"

// Storage interface for queries
type Storage interface {
	Len() int
	Write([]gopacket.Packet) (int, error)
	Read() ([]gopacket.Packet, error)
	ReadAll() ([]gopacket.Packet, error)
}
