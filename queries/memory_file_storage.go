package queries

import "github.com/google/gopacket"

type MemFileStorage struct {
	ms *MemStorage
	fs *FileStorage
}

func NewMemFileStorage(file string) (Storage, error) {
	return &MemStorage{}, nil
}

func (s *MemFileStorage) Read() ([]gopacket.Packet, error) {
	return nil, nil
}

func (s *MemFileStorage) ReadAll() ([]gopacket.Packet, error) {
	return nil, nil
}

func (s *MemFileStorage) Write([]gopacket.Packet) (int, error) {
	return 0, nil
}
