package syslognamed

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/alphasoc/nfr/packet"
)

// A Parser parses and reads network events from syslog-named logs.
type Parser struct {
	r io.ReadCloser
}

// NewParser creates new syslog-named parser.
func NewParser() *Parser {
	return &Parser{}
}

// NewFileParser creates new syslog-named reader from given file.
func NewFileParser(filename string) (*Parser, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	return &Parser{r: f}, nil
}

// ReadDNS reads all dns packets from the file.
func (p *Parser) ReadDNS() ([]*packet.DNSPacket, error) {
	if p.r == nil {
		return nil, fmt.Errorf("syslog-named parser must be created with file reader")
	}

	var packets []*packet.DNSPacket

	s := bufio.NewScanner(p.r)
	for s.Scan() {
		dnspacket, err := p.ParseLineDNS(string(s.Bytes()))
		if err != nil {
			return nil, err
		}
		if dnspacket != nil {
			packets = append(packets, dnspacket)
		}
	}

	if err := s.Err(); err != nil {
		return nil, err
	}
	return packets, nil
}

// ReadIP reads all ip packets from the file.
func (*Parser) ReadIP() ([]*packet.IPPacket, error) {
	return nil, errors.New("syslog-named read ip packet unimplemented")
}

var re = regexp.MustCompile(`(\d+).*named\[\d+\]: queries: info: client (.*)#\d+.*query: (.*) IN (.*) \+`)

// ParseLineDNS parse single log line with dns data.
func (*Parser) ParseLineDNS(line string) (*packet.DNSPacket, error) {
	m := re.FindStringSubmatch(line)
	if len(m) != 5 {
		return nil, nil
	}

	srcIP := net.ParseIP(m[2])
	if srcIP == nil {
		return nil, fmt.Errorf("syslog-named: invalid ip: %s", line)
	}

	sec, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("syslog-named: invalid timestamp: %s", line)
	}

	return &packet.DNSPacket{
		DstPort:    0,
		Protocol:   "udp",
		Timestamp:  time.Unix(sec, 0),
		SrcIP:      srcIP,
		RecordType: m[4],
		FQDN:       m[3],
	}, nil
}

// ParseLineIP reads all ip packets from the file.
func (*Parser) ParseLineIP(line string) (*packet.IPPacket, error) {
	return nil, errors.New("syslog-named read ip packet unimplemented")
}

// Close underlying log file.
func (p *Parser) Close() error {
	return p.r.Close()
}
