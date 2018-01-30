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

	"github.com/alphasoc/nfr/packet"
)

// A Parser parses and reads network events from bro logs.
type Parser struct {
	r io.ReadCloser

	metadata struct {
		separator    string
		setSeparator string
		emptyField   string
		unsetFiled   string
		fileds       []string
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
	fileds := strings.Split(line, p.metadata.separator)
	if len(fileds) != len(p.metadata.fileds) {
		return nil, fmt.Errorf("bro dns log invalid entry at line: %q", line)
	}

	var dnspacket packet.DNSPacket

	// parse values based on fileds
	for i, f := range p.metadata.fileds {
		switch f {
		case "ts":
			timestamp, err := parseEpochTime(fileds[i])
			if err != nil {
				return nil, fmt.Errorf("bro dns log invalid timestamp: %s", err)
			}
			dnspacket.Timestamp = timestamp
		case "id.orig_h":
			dnspacket.SrcIP = net.ParseIP(fileds[i])
		case "query":
			dnspacket.FQDN = fileds[i]
		case "qtype_name":
			dnspacket.RecordType = fileds[i]
		case "id.resp_p":
			port, err := strconv.ParseInt(fileds[i], 10, 8)
			if err != nil {
				return nil, fmt.Errorf("bro dns log invalid port at line: %q", line)
			}
			dnspacket.DstPort = int(port)
		case "proto":
			dnspacket.Protocol = strings.ToLower(fileds[i])
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
	fileds := strings.Split(line, p.metadata.separator)
	if len(fileds) != len(p.metadata.fileds) {
		return nil, fmt.Errorf("conn bro log - invalid entry at line: %q", line)
	}

	var ippacket packet.IPPacket

	// parse values based on fileds
	for i, f := range p.metadata.fileds {
		switch f {
		case "ts":
			timestamp, err := parseEpochTime(fileds[i])
			if err != nil {
				return nil, fmt.Errorf("conn bro log - invalid timestamp: %s", err)
			}
			ippacket.Timestamp = timestamp
		case "id.orig_h":
			ippacket.SrcIP = net.ParseIP(fileds[i])
		case "id.orig_p":
			port, err := strconv.ParseInt(fileds[i], 10, 8)
			if err != nil {
				return nil, fmt.Errorf("conn bro log - invalid port at line: %q", line)
			}
			ippacket.SrcPort = int(port)
		case "id.resp_h":
			ippacket.DstIP = net.ParseIP(fileds[i])
		case "id.resp_p":
			port, err := strconv.ParseInt(fileds[i], 10, 8)
			if err != nil {
				return nil, fmt.Errorf("conn bro log - invalid port at line: %q", line)
			}
			ippacket.DstPort = int(port)
		case "proto":
			ippacket.Protocol = strings.ToLower(fileds[i])
		case "orig_bytes":
			fallthrough
		case "orig_ip_bytes":
			if fileds[i] != p.metadata.unsetFiled {
				count, err := strconv.ParseInt(fileds[i], 10, 8)
				if err != nil {
					return nil, fmt.Errorf("conn bro log - invalid orig bytes count at line: %q %q %q", line, fileds[i], p.metadata.unsetFiled)
				}
				if count > 0 {
					ippacket.BytesCount += int(count)
					ippacket.Direction = packet.DirectionOut
				}
			}
		case "resp_bytes":
			fallthrough
		case "resp_ip_bytes":
			if fileds[i] != p.metadata.unsetFiled {
				count, err := strconv.ParseInt(fileds[i], 10, 8)
				if err != nil {
					return nil, fmt.Errorf("conn bro log - invalid resp bytes count at line: %q", line)
				}
				if count > 0 {
					ippacket.BytesCount += int(count)
					ippacket.Direction = packet.DirectionIn
				}
			}
		}
	}

	return &ippacket, nil
}

// Close underlying log file.
func (p *Parser) Close() error {
	return p.r.Close()
}

// reads metadata from bro file.
func (p *Parser) readMetadata(line string) error {
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
		p.metadata.unsetFiled = metadata[1]
	case "fields":
		p.metadata.fileds = strings.Split(metadata[1], p.metadata.separator)
	}

	return nil
}
