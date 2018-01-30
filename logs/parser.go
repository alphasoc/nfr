package logs

import "github.com/alphasoc/nfr/packet"

// FileParser is the interface what wraps ip and dns parser.
type FileParser interface {
	ReadDNS() ([]*packet.DNSPacket, error)
	ReadIP() ([]*packet.IPPacket, error)
}

// Parser is the interface what wraps ip and dns parser.
type Parser interface {
	ParseLineDNS(line string) (*packet.DNSPacket, error)
	ParseLineIP(line string) (*packet.IPPacket, error)
}
