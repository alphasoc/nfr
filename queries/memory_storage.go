package queries

import "github.com/google/gopacket"

type MemStorage struct {
}

func NewMemStorage(bSize int) (Storage, error) {
	return &MemStorage{}, nil
}

func (s *MemStorage) Read() ([]gopacket.Packet, error) {
	return nil, nil
}

func (s *MemStorage) ReadAll() ([]gopacket.Packet, error) {
	return nil, nil
}

func (s *MemStorage) Write([]gopacket.Packet) (int, error) {
	return 0, nil
}
