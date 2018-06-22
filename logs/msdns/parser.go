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
	// TimeFormat used for parsing timestamp.
	// If not set, will accept the following format:
	//   2006-01-02 3:04:05 PM
	//   2006/01/02 3:04:05 PM
	//   2006-01-02 15:04:05
	//   2006/01/02 15:04:05
	TimeFormat string

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

func guessTimeFormat(s string) string {
	if len(s) < 10 {
		return ""
	}

	sep := s[4]                  // date separator
	ampm := (s[len(s)-1] == 'M') // use 12h clock (AM/PM)

	switch true {
	case sep == '-' && ampm:
		return "2006-01-02 3:04:05 PM"
	case sep == '-' && !ampm:
		return "2006-01-02 15:04:05"
	case sep == '/' && ampm:
		return "2006/01/02 3:04:05 PM"
	case sep == '/' && !ampm:
		return "2006/01/02 15:04:05"
	}

	return ""
}

// ParseLineDNS parse single log line with dns data.
func (p *Parser) ParseLineDNS(line string) (*packet.DNSPacket, error) {
	s := strings.Fields(line)

	if len(s) < 15 {
		return nil, nil
	}

	// find Context field, which can be 4th or 5th field,
	// depends if timestamp consists of 2 or 3 fields.
	contextIdx := 0
	switch "PACKET" {
	case s[3]:
		contextIdx = 3
	case s[4]:
		contextIdx = 4
	default:
		return nil, nil
	}

	ts := strings.Join(s[:contextIdx-1], " ")
	s = s[contextIdx:]

	// fields are now starting with Context, expect 12 fields
	if len(s) != 12 || s[3] != "Rcv" || s[6] != "Q" {
		return nil, nil
	}

	timeFormat := p.TimeFormat
	if timeFormat == "" {
		timeFormat = guessTimeFormat(ts)
	}
	if timeFormat == "" {
		return nil, fmt.Errorf("Unknown time format for timestamp: %s", ts)
	}

	timestamp, err := time.ParseInLocation(timeFormat, ts, time.Local)
	if err != nil {
		return nil, err
	}

	srcIP := net.ParseIP(s[4])
	if err != nil {
		return nil, fmt.Errorf("invalid source ip at line %s", line)
	}

	return &packet.DNSPacket{
		DstPort:    0,
		Protocol:   strings.ToLower(s[2]),
		Timestamp:  timestamp,
		SrcIP:      srcIP,
		RecordType: s[10],
		FQDN:       strings.Trim(numToDotRe.ReplaceAllString(s[11], "."), "."),
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
