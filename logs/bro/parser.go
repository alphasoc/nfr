package bro

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/alphasoc/nfr/client"
	"github.com/alphasoc/nfr/packet"
)

// A Parser parses and reads network events from bro logs.
type Parser struct {
	r io.ReadCloser

	metadata struct {
		separator    string
		setSeparator string
		emptyField   string
		unsetField   string
		fields       []string
	}
}

// NewParser creates new bro parser.
func NewParser() *Parser {
	var p = &Parser{}

	// bro log uses space to separate separator and value, then
	// the next key separator is used.
	p.metadata.separator = " "
	return p
}

// NewFileParser creates new bro parser that is capable of parse given file.
func NewFileParser(filename string) (*Parser, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	var p = &Parser{r: f}
	// bro log uses space to separate separator and value, then
	// the next key separator is used.
	p.metadata.separator = " "

	return p, nil
}

func (p *Parser) nonEmpty(f string) string {
	if f == p.metadata.emptyField || f == p.metadata.unsetField {
		return ""
	}
	return f
}

// ReadDNS reads all dns packets from the file.
func (p *Parser) ReadDNS() ([]*packet.DNSPacket, error) {
	if p.r == nil {
		return nil, fmt.Errorf("bro parser must be created with file reader")
	}

	var packets []*packet.DNSPacket

	// bro log uses space to separate separator and value, then
	// the next key separator is used.
	p.metadata.separator = " "

	s := bufio.NewScanner(p.r)
	for s.Scan() {
		packet, err := p.ParseLineDNS(s.Text())
		if err != nil {
			return nil, err
		}
		if packet != nil {
			packets = append(packets, packet)
		}
	}

	if err := s.Err(); err != nil {
		return nil, err
	}
	return packets, nil
}

// ReadIP reads all ip packets from the file.
func (p *Parser) ReadIP() ([]*packet.IPPacket, error) {
	if p.r == nil {
		return nil, fmt.Errorf("bro parser must be created with file reader")
	}

	var packets []*packet.IPPacket

	s := bufio.NewScanner(p.r)
	for s.Scan() {
		packet, err := p.ParseLineIP(s.Text())
		if err != nil {
			return nil, err
		}
		if packet != nil {
			packets = append(packets, packet)
		}
	}

	if err := s.Err(); err != nil {
		return nil, err
	}
	return packets, nil
}

// ParseLineDNS parse single log line with dns data.
func (p *Parser) ParseLineDNS(line string) (*packet.DNSPacket, error) {
	line = strings.TrimSpace(line)
	if len(line) == 0 {
		return nil, nil
	}
	if line[0] == '#' {
		if err := p.readMetadata(line); err != nil {
			return nil, err
		}
		return nil, nil
	}

	// get values for one entry
	fields := strings.Split(line, p.metadata.separator)
	if len(fields) != len(p.metadata.fields) {
		return nil, fmt.Errorf("bro dns log invalid entry at line: %q", line)
	}

	var dnspacket packet.DNSPacket

	// parse values based on fields
	for i, f := range p.metadata.fields {
		switch f {
		case "ts":
			timestamp, err := parseEpochTime(fields[i])
			if err != nil {
				return nil, fmt.Errorf("bro dns log invalid timestamp: %s", err)
			}
			dnspacket.Timestamp = timestamp
		case "id.orig_h":
			dnspacket.SrcIP = net.ParseIP(fields[i])
		case "id.orig_p":
			port, err := strconv.ParseUint(fields[i], 10, 16)
			if err != nil {
				return nil, fmt.Errorf("conn bro log - invalid port at line: %q: %s", line, err)
			}
			dnspacket.SrcPort = int(port)
		case "query":
			dnspacket.FQDN = fields[i]
		case "qtype_name":
			dnspacket.RecordType = fields[i]
		case "id.resp_p":
			port, err := strconv.ParseUint(fields[i], 10, 16)
			if err != nil {
				return nil, fmt.Errorf("bro dns log invalid port at line: %q", line)
			}
			dnspacket.DstPort = int(port)
		case "proto":
			dnspacket.Protocol = strings.ToLower(fields[i])
		}
	}

	return &dnspacket, nil
}

// ParseLineIP parse single log line with ip data.
func (p *Parser) ParseLineIP(line string) (*packet.IPPacket, error) {
	line = strings.TrimSpace(line)
	if len(line) == 0 {
		return nil, nil
	}
	if line[0] == '#' {
		if err := p.readMetadata(line); err != nil {
			return nil, err
		}
		return nil, nil
	}

	// get values for one entry
	fields := strings.Split(line, p.metadata.separator)
	if len(fields) != len(p.metadata.fields) {
		return nil, fmt.Errorf("conn bro log - invalid entry at line: %q", line)
	}

	var ippacket packet.IPPacket

	// parse values based on fields
	for i, f := range p.metadata.fields {
		switch f {
		case "ts":
			timestamp, err := parseEpochTime(fields[i])
			if err != nil {
				return nil, fmt.Errorf("conn bro log - invalid timestamp: %s", err)
			}
			ippacket.Timestamp = timestamp
		case "id.orig_h":
			ippacket.SrcIP = net.ParseIP(fields[i])
		case "id.orig_p":
			port, err := strconv.ParseUint(fields[i], 10, 16)
			if err != nil {
				return nil, fmt.Errorf("conn bro log - invalid port at line: %q", line)
			}
			ippacket.SrcPort = int(port)
		case "id.resp_h":
			ippacket.DstIP = net.ParseIP(fields[i])
		case "id.resp_p":
			port, err := strconv.ParseUint(fields[i], 10, 16)
			if err != nil {
				return nil, fmt.Errorf("conn bro log - invalid port at line: %q", line)
			}
			ippacket.DstPort = int(port)
		case "proto":
			ippacket.Protocol = strings.ToLower(fields[i])
		case "orig_bytes":
			fallthrough
		case "orig_ip_bytes":
			if fields[i] != p.metadata.unsetField {
				count, err := strconv.ParseInt(fields[i], 10, 64)
				if err != nil {
					return nil, fmt.Errorf("conn bro log - invalid orig bytes count at line: %q %q %q", line, fields[i], p.metadata.unsetField)
				}
				if count > 0 {
					ippacket.BytesCount += int(count)
					ippacket.Direction = packet.DirectionOut
				}
			}
		case "resp_bytes":
			fallthrough
		case "resp_ip_bytes":
			if fields[i] != p.metadata.unsetField {
				count, err := strconv.ParseInt(fields[i], 10, 64)
				if err != nil {
					return nil, fmt.Errorf("conn bro log - invalid resp bytes count at line: %q", line)
				}
				if count > 0 {
					ippacket.BytesCount += int(count)
					ippacket.Direction = packet.DirectionIn
				}
			}
		case "ja3":
			ippacket.Ja3 = p.nonEmpty(fields[i])
		}
	}

	return &ippacket, nil
}

func (p *Parser) ReadHTTP() ([]*client.HTTPEntry, error) {
	if p.r == nil {
		return nil, fmt.Errorf("bro parser must be created with file reader")
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
	line = strings.TrimSpace(line)
	if len(line) == 0 {
		return nil, nil
	}
	if line[0] == '#' {
		if err := p.readMetadata(line); err != nil {
			return nil, err
		}
		return nil, nil
	}

	// get values for one entry
	fields := strings.Split(line, p.metadata.separator)
	if len(fields) != len(p.metadata.fields) {
		return nil, fmt.Errorf("bro dns log invalid entry at line: %q", line)
	}

	var (
		entry     client.HTTPEntry
		host, uri string
	)

	// parse values based on fields
	for i, f := range p.metadata.fields {
		switch f {
		case "ts":
			timestamp, err := parseEpochTime(fields[i])
			if err != nil {
				return nil, fmt.Errorf("conn bro log - invalid timestamp: %s", err)
			}
			entry.Timestamp = timestamp
		case "id.orig_h":
			entry.SrcIP = net.ParseIP(fields[i])
		case "id.orig_p":
			port, err := strconv.ParseUint(fields[i], 10, 16)
			if err != nil {
				return nil, fmt.Errorf("conn bro log - invalid port at line: %q", line)
			}
			entry.SrcPort = uint16(port)
		case "method":
			entry.Method = fields[i]
		case "host":
			host = fields[i]
		case "uri":
			uri = fields[i]
		case "referrer":
			entry.Referrer = p.nonEmpty(fields[i])
		case "user_agent":
			entry.UserAgent = p.nonEmpty(fields[i])
		case "request_body_len":
			count, err := strconv.ParseInt(fields[i], 10, 63)
			if err != nil {
				return nil, fmt.Errorf("conn bro log - invalid request_body_len at line: %q %q %q", line, fields[i], p.metadata.unsetField)
			}
			entry.BytesOut = count
		case "response_body_len":
			count, err := strconv.ParseInt(fields[i], 10, 63)
			if err != nil {
				return nil, fmt.Errorf("conn bro log - invalid response_body_len at line: %q %q %q", line, fields[i], p.metadata.unsetField)
			}
			entry.BytesIn = count
		case "status_code":
			code, err := strconv.ParseUint(fields[i], 10, 16)
			if err != nil {
				return nil, fmt.Errorf("conn bro log - invalid status_code at line: %q %q %q", line, fields[i], p.metadata.unsetField)
			}
			entry.Status = int(code)
		case "resp_mime_types":
			entry.ContentType = p.nonEmpty(fields[i])
		}
	}

	entry.URL = fmt.Sprintf("http://%s%s", host, uri)

	return &entry, nil
}

// Close underlying log file.
func (p *Parser) Close() error {
	return p.r.Close()
}

// reads metadata from bro file.
func (p *Parser) readMetadata(line string) error {
	// sometimes metadata needs to be reloaded
	// if line starts with set_separator then clear metadata separator
	if strings.HasPrefix(line, "#separator") {
		p.metadata.separator = " "
	}

	// skip first # and extract values
	metadata := strings.SplitN(line[1:], p.metadata.separator, 2)
	if len(metadata) < 2 {
		return fmt.Errorf("bro log - invalid metadata at line: %q", line)
	}

	switch metadata[0] {
	case "separator":
		// remove hex prefix '\x' and decode hex value into string
		sep, err := hex.DecodeString(strings.Trim(metadata[1], "\\x"))
		if err != nil {
			return fmt.Errorf("bro log - invalid separator at line: %q", line)
		}

		p.metadata.separator = string(sep)
	case "set_separator":
		p.metadata.setSeparator = metadata[1]
	case "empty_field":
		p.metadata.emptyField = metadata[1]
	case "unset_field":
		p.metadata.unsetField = metadata[1]
	case "fields":
		p.metadata.fields = strings.Split(metadata[1], p.metadata.separator)
	}

	return nil
}
