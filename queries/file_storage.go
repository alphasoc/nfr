package queries

import "github.com/google/gopacket"

type FileStorage struct {
}

func NewFileStorage(file string) (Storage, error) {
	return &FileStorage{}, nil
}

func (s *FileStorage) Read() ([]gopacket.Packet, error) {
	return nil, nil
}

func (s *FileStorage) ReadAll() ([]gopacket.Packet, error) {
	return nil, nil
}

func (s *FileStorage) Write([]gopacket.Packet) (int, error) {
	return 0, nil
}
