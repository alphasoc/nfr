package suricata

import (
	"bufio"
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

// logEntry represents single log file in used in surciata eve output.
type logEntry struct {
	Timestamp timestamp `json:"timestamp"`
	SrcIP     string    `json:"src_ip"`
	DestPort  int       `json:"dest_port"`
	Proto     string    `json:"proto"`
	DNS       struct {
		Type   string `json:"type"`
		Rrname string `json:"rrname"`
		Rrtype string `json:"rrtype"`
	} `json:"dns"`
}

// A Parser parses and reads network events from suricata logs.
type Parser struct {
	r io.ReadCloser
}

// NewParser creates new suricata parser.
func NewParser() *Parser {
	return &Parser{}
}

// NewFileParser creates new suricata reader from given file.
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
		return nil, fmt.Errorf("suricata parser must be created with file reader")
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
	return nil, errors.New("suricata read ip packet from suricata logs unimplemented")
}

// ParseLineDNS parse single log line with dns data.
func (*Parser) ParseLineDNS(line string) (*packet.DNSPacket, error) {
	if len(line) == 0 {
		return nil, nil
	}

	var entry logEntry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return nil, fmt.Errorf("suricata %s", err)
	}

	if entry.DNS.Type != "query" {
		return nil, nil
	}

	return &packet.DNSPacket{
		DstPort:    entry.DestPort,
		Protocol:   strings.ToLower(entry.Proto),
		Timestamp:  time.Time(entry.Timestamp),
		SrcIP:      net.ParseIP(entry.SrcIP),
		RecordType: entry.DNS.Rrtype,
		FQDN:       entry.DNS.Rrname,
	}, nil
}

// ParseLineIP reads all ip packets from the file.
func (*Parser) ParseLineIP(line string) (*packet.IPPacket, error) {
	return nil, errors.New("read ip packet from suricata logs unimplemented")
}

// Close underlying log file.
func (p *Parser) Close() error {
	return p.r.Close()
}
