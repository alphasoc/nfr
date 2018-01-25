package suricata

import (
	"bufio"
	"encoding/json"
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

// A Reader reads network events from suricata logs.
type Reader struct {
	r io.ReadCloser
}

// NewReader creates new suricata reader from given file.
func NewReader(filename string) (*Reader, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	return &Reader{r: f}, nil
}

// ReadDNS reads all dns packets from the file.
func (r *Reader) ReadDNS() ([]*packet.DNSPacket, error) {
	var (
		packets []*packet.DNSPacket
		entry   logEntry
	)

	s := bufio.NewScanner(r.r)
	for s.Scan() {
		line := s.Bytes()
		if len(line) == 0 {
			continue
		}

		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}

		if entry.DNS.Type != "query" {
			continue
		}

		packets = append(packets, &packet.DNSPacket{
			DstPort:    entry.DestPort,
			Protocol:   strings.ToLower(entry.Proto),
			Timestamp:  time.Time(entry.Timestamp),
			SrcIP:      net.ParseIP(entry.SrcIP),
			RecordType: entry.DNS.Rrtype,
			FQDN:       entry.DNS.Rrname,
		})
	}

	if err := s.Err(); err != nil {
		return nil, err
	}
	return packets, nil
}

// ReadIP reads all ip packets from the file.
func (r *Reader) ReadIP() ([]*packet.IPPacket, error) {
	return nil, nil
}

// Close underlying log file.
func (r *Reader) Close() error {
	return r.r.Close()
}
