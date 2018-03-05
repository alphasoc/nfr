package msdns

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/alphasoc/nfr/packet"
)

// A Parser parses and reads network events from msdns logs.
type Parser struct {
	r io.ReadCloser
}

// NewParser creates new msdns parser.
func NewParser() *Parser {
	return &Parser{}
}

// NewFileParser creates new msdns reader from given file.
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
		return nil, fmt.Errorf("msdns parser must be created with file reader")
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
	return nil, errors.New("msdns read ip packet unimplemented")
}

var numToDotRe = regexp.MustCompile(`\(\d+\)`)

// ParseLineDNS parse single log line with dns data.
func (*Parser) ParseLineDNS(line string) (*packet.DNSPacket, error) {
	s := strings.Fields(line)
	if len(s) != 15 || s[3] != "PACKET" || s[6] != "Rcv" || s[9] != "Q" {
		return nil, nil
	}

	timestamp, err := time.Parse("2006-01-02 15:04:05", s[0]+" "+s[1])
	if err != nil {
		return nil, err
	}

	srcIP := net.ParseIP(s[7])
	if err != nil {
		return nil, fmt.Errorf("invalid source ip at line %s", line)
	}

	return &packet.DNSPacket{
		DstPort:    0,
		Protocol:   strings.ToLower(s[5]),
		Timestamp:  timestamp,
		SrcIP:      srcIP,
		RecordType: s[13],
		FQDN:       strings.Trim(numToDotRe.ReplaceAllString(s[14], "."), "."),
	}, nil
}

// ParseLineIP reads all ip packets from the file.
func (*Parser) ParseLineIP(line string) (*packet.IPPacket, error) {
	return nil, errors.New("msdns read ip packet unimplemented")
}

// Close underlying log file.
func (p *Parser) Close() error {
	return p.r.Close()
}
