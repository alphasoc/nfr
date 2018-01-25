package logs

import "github.com/alphasoc/nfr/packet"

// Reader is the interface what wraps ip and dns packets read.
type Reader interface {
	ReadDNS() ([]*packet.DNSPacket, error)
	ReadIP() ([]*packet.IPPacket, error)
}
