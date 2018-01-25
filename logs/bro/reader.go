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

// A Reader reads network events from bro logs.
type Reader struct {
	r io.ReadCloser

	metadata struct {
		separator    string
		setSeparator string
		emptyField   string
		unsetFiled   string
		fileds       []string
	}
}

// NewReader creates new suricata reader from given file.
func NewReader(filename string) (*Reader, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	return &Reader{r: f}, nil
}

// reads metadata from bro file.
func (r *Reader) readMetadata(line string) error {
	// skip first # and extract values
	metadata := strings.SplitN(line[1:], r.metadata.separator, 2)
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

		r.metadata.separator = string(sep)
	case "set_separator":
		r.metadata.setSeparator = metadata[1]
	case "empty_field":
		r.metadata.emptyField = metadata[1]
	case "unset_field":
		r.metadata.unsetFiled = metadata[1]
	case "fields":
		r.metadata.fileds = strings.Split(metadata[1], r.metadata.separator)
	}

	return nil
}

// ReadDNS reads all dns packets from the file.
func (r *Reader) ReadDNS() ([]*packet.DNSPacket, error) {
	var packets []*packet.DNSPacket

	// bro log uses space to separate separator and value, then
	// the next key separator is used.
	r.metadata.separator = " "

	s := bufio.NewScanner(r.r)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if len(line) == 0 {
			continue
		}
		if line[0] == '#' {
			if err := r.readMetadata(line); err != nil {
				return nil, err
			}
			continue
		}

		// get values for one entry
		fileds := strings.Split(line, r.metadata.separator)
		if len(fileds) != len(r.metadata.fileds) {
			return nil, fmt.Errorf("dns bro log - invalid entry at line: %q", line)
		}

		var p packet.DNSPacket

		// parse values based on fileds
		for i, f := range r.metadata.fileds {
			switch f {
			case "ts":
				timestamp, err := parseEpochTime(fileds[i])
				if err != nil {
					return nil, fmt.Errorf("dns bro log - invalid timestamp: %s", err)
				}
				p.Timestamp = timestamp
			case "id.orig_h":
				p.SrcIP = net.ParseIP(fileds[i])
			case "query":
				p.FQDN = fileds[i]
			case "qtype_name":
				p.RecordType = fileds[i]
			case "id.resp_p":
				port, err := strconv.ParseInt(fileds[i], 10, 8)
				if err != nil {
					return nil, fmt.Errorf("dns bro log - invalid port at line: %q", line)
				}
				p.DstPort = int(port)
			case "proto":
				p.Protocol = strings.ToLower(fileds[i])
			}
		}

		packets = append(packets, &p)
	}

	if err := s.Err(); err != nil {
		return nil, err
	}
	return packets, nil
}

// ReadIP reads all ip packets from the file.
func (r *Reader) ReadIP() ([]*packet.IPPacket, error) {
	var packets []*packet.IPPacket

	// bro log uses space to separate separator and value, then
	// the next key separator is used.
	r.metadata.separator = " "

	s := bufio.NewScanner(r.r)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if len(line) == 0 {
			continue
		}
		if line[0] == '#' {
			if err := r.readMetadata(line); err != nil {
				return nil, err
			}
			continue
		}

		// get values for one entry
		fileds := strings.Split(line, r.metadata.separator)
		if len(fileds) != len(r.metadata.fileds) {
			return nil, fmt.Errorf("conn bro log - invalid entry at line: %q", line)
		}

		var p packet.IPPacket

		// parse values based on fileds
		for i, f := range r.metadata.fileds {
			switch f {
			case "ts":
				timestamp, err := parseEpochTime(fileds[i])
				if err != nil {
					return nil, fmt.Errorf("conn bro log - invalid timestamp: %s", err)
				}
				p.Timestamp = timestamp
			case "id.orig_h":
				p.SrcIP = net.ParseIP(fileds[i])
			case "id.orig_p":
				port, err := strconv.ParseInt(fileds[i], 10, 8)
				if err != nil {
					return nil, fmt.Errorf("conn bro log - invalid port at line: %q", line)
				}
				p.SrcPort = int(port)
			case "id.resp_h":
				p.DstIP = net.ParseIP(fileds[i])
			case "id.resp_p":
				port, err := strconv.ParseInt(fileds[i], 10, 8)
				if err != nil {
					return nil, fmt.Errorf("conn bro log - invalid port at line: %q", line)
				}
				p.DstPort = int(port)
			case "proto":
				p.Protocol = strings.ToLower(fileds[i])
			case "orig_bytes":
				fallthrough
			case "orig_ip_bytes":
				if fileds[i] != r.metadata.unsetFiled {
					count, err := strconv.ParseInt(fileds[i], 10, 8)
					if err != nil {
						return nil, fmt.Errorf("conn bro log - invalid orig bytes count at line: %q %q %q", line, fileds[i], r.metadata.unsetFiled)
					}
					if count > 0 {
						p.BytesCount += int(count)
						p.Direction = packet.DirectionOut
					}
				}
			case "resp_bytes":
				fallthrough
			case "resp_ip_bytes":
				if fileds[i] != r.metadata.unsetFiled {
					count, err := strconv.ParseInt(fileds[i], 10, 8)
					if err != nil {
						return nil, fmt.Errorf("conn bro log - invalid resp bytes count at line: %q", line)
					}
					if count > 0 {
						p.BytesCount += int(count)
						p.Direction = packet.DirectionIn
					}
				}
			}
		}

		packets = append(packets, &p)
	}

	if err := s.Err(); err != nil {
		return nil, err
	}
	return packets, nil
}

// Close underlying log file.
func (r *Reader) Close() error {
	return r.r.Close()
}
