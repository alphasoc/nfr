package suricata

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"github.com/alphasoc/nfr/client"
	"github.com/alphasoc/nfr/packet"
)

// logEntry represents single log file in used in surciata eve output.
type logEntry struct {
	Timestamp timestamp `json:"timestamp"`
	SrcIP     string    `json:"src_ip"`
	SrcPort   uint16    `json:"src_port"`
	DestPort  int       `json:"dest_port"`
	Proto     string    `json:"proto"`
	DNS       struct {
		Type   string `json:"type"`
		Rrname string `json:"rrname"`
		Rrtype string `json:"rrtype"`
	} `json:"dns"`
	HTTP struct {
		Hostname        string `json:"hostname"`
		URL             string `json:"url"`
		HTTPUserAgent   string `json:"http_user_agent"`
		HTTPContentType string `json:"http_content_type"`
		HTTPRefer       string `json:"http_refer"`
		HTTPMethod      string `json:"http_method"`
		Protocol        string `json:"protocol"`
		Status          int    `json:"status"`
		Length          int    `json:"length"`
	} `json:"http"`
	TLS struct {
		SessionResumed bool   `json:"session_resumed"`
		Sni            string `json:"sni"`
		Version        string `json:"version"`
		Ja3            struct {
			Hash   string `json:"hash"`
			String string `json:"string"`
		} `json:"ja3"`
	} `json:"tls"`
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
	return nil, nil
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
	return nil, nil
}

func (p *Parser) ReadHTTP() ([]*client.HTTPEntry, error) {
	if p.r == nil {
		return nil, fmt.Errorf("suricata parser must be created with file reader")
	}

	var packets []*client.HTTPEntry

	s := bufio.NewScanner(p.r)
	for s.Scan() {
		dnspacket, err := p.ParseLineHTTP(string(s.Bytes()))
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

func (p *Parser) ParseLineHTTP(line string) (*client.HTTPEntry, error) {
	if len(line) == 0 {
		return nil, nil
	}

	var entry logEntry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return nil, fmt.Errorf("suricata %s", err)
	}

	if entry.HTTP.Hostname == "" {
		return nil, nil
	}

	// TODO: if different port then attach to URL?
	schema := ""
	switch entry.DestPort {
	case 80:
		schema = "http://"
	case 443:
		schema = "https://"
	}

	return &client.HTTPEntry{
		Timestamp: time.Time(entry.Timestamp),
		SrcIP:     net.ParseIP(entry.SrcIP),
		SrcPort:   entry.SrcPort,

		URL:         schema + path.Join(entry.HTTP.Hostname, entry.HTTP.URL),
		Method:      entry.HTTP.HTTPMethod,
		Status:      entry.HTTP.Status,
		ContentType: entry.HTTP.HTTPContentType,
		Referrer:    entry.HTTP.HTTPRefer,
		UserAgent:   entry.HTTP.HTTPUserAgent,

		// Action:
		// BytesIn:
		// BytesOut: entry.HTTP.Length ?
	}, nil
}

// Close underlying log file.
func (p *Parser) Close() error {
	return p.r.Close()
}
