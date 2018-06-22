package edge

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/alphasoc/nfr/packet"
)

// dnsLog represents single DNS log entry
type dnsLog struct {
	Time      int64  `json:"time"`
	Source    string `json:"source"`
	Query     string `json:"query"`
	QueryType string `json:"queryType"`
	Protocol  string `json:"queryProtocol"`
}

func (l *dnsLog) toPacket() (*packet.DNSPacket, error) {
	if l.Time <= 0 {
		return nil, fmt.Errorf("invalid time: %d", l.Time)
	}
	srcIP := net.ParseIP(l.Source)
	if srcIP == nil {
		return nil, fmt.Errorf("invalid source (must be valid IP): %s", l.Source)
	}

	return &packet.DNSPacket{
		Timestamp:  time.Unix(l.Time/1000, (l.Time%1000)*int64(time.Millisecond)),
		SrcIP:      srcIP,
		Protocol:   strings.ToLower(l.Protocol),
		FQDN:       l.Query,
		RecordType: l.QueryType,
	}, nil
}

// A Parser parses and reads network events from edge logs.
type Parser struct {
	r io.ReadCloser
}

// NewParser creates new edge parser.
func NewParser() *Parser {
	return &Parser{}
}

// NewFileParser creates new edge reader from given file.
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
		return nil, fmt.Errorf("parser must be created with file reader")
	}

	var entries []dnsLog
	dec := json.NewDecoder(p.r)
	if err := dec.Decode(&entries); err != nil {
		return nil, err
	}

	res := make([]*packet.DNSPacket, 0, len(entries))
	for n := range entries {
		p, err := entries[n].toPacket()
		if err != nil {
			return nil, fmt.Errorf("failed to parse event %d: %s", n, err)
		}
		res = append(res, p)
	}

	return res, nil
}

// ReadIP reads all ip packets from the file.
func (*Parser) ReadIP() ([]*packet.IPPacket, error) {
	return nil, errors.New(" read ip packet from edge logs unimplemented")
}

// ParseLineDNS parse single log line with dns data.
func (*Parser) ParseLineDNS(line string) (*packet.DNSPacket, error) {
	return nil, errors.New("line parser not implemented for edge format")
}

// ParseLineIP reads all ip packets from the file.
func (*Parser) ParseLineIP(line string) (*packet.IPPacket, error) {
	return nil, errors.New("read ip packet from edge logs unimplemented")
}

// Close underlying log file.
func (p *Parser) Close() error {
	return p.r.Close()
}
