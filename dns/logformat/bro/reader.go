package bro

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/alphasoc/nfr/dns"
)

// A Reader reads dns packets from suricata eve logs.
type Reader struct {
	r io.ReadCloser

	c         chan *dns.Packet
	protocols []string
	port      int

	metadata struct {
		separator    string
		setSeparator string
		emptyField   string
		unsetFiled   string
		fileds       []string
	}
}

// NewReader creates new suricata reader. Logs will be read from filename and filter
// by protocos and port. It returns error on file open fail.
func NewReader(filename string, protocols []string, port int) (*Reader, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	return &Reader{r: f, protocols: protocols, port: port}, nil
}

// reads metadata from bro file.
func (r *Reader) readMetadata(line string) error {

	// skip first # and extract values
	metadata := strings.SplitN(line[1:], r.metadata.separator, 2)
	if len(metadata) < 2 {
		return fmt.Errorf("dns bro log - invalid metadata at line: %q", line)
	}

	switch metadata[0] {
	case "separator":
		// remove hex prefix '\x' and decode hex value into string
		sep, err := hex.DecodeString(strings.Trim(metadata[1], "\\x"))
		if err != nil {
			return fmt.Errorf("dns bro log - invalid separator at line: %q", line)
		}

		r.metadata.separator = string(sep)
	case "set_separator":
		r.metadata.setSeparator = metadata[1]
	case "empty_field":
		r.metadata.emptyField = metadata[1]
	case "unset_filed":
		r.metadata.unsetFiled = metadata[1]
	case "fields":
		r.metadata.fileds = strings.Split(metadata[1], r.metadata.separator)
	}

	return nil
}

// Read reads all dns pacets from file.
func (r *Reader) Read() ([]*dns.Packet, error) {
	var (
		packets []*dns.Packet
	)

	// bro log uses space to separate separator and value, then
	// in next key separator is used.
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
			log.Println(len(fileds), len(r.metadata.fileds))
			return nil, fmt.Errorf("dns bro log - invalid entry at line: %q", line)
		}

		var (
			p     dns.Packet
			proto string
			port  int
		)

		// parse values based on fileds
		for i, f := range r.metadata.fileds {
			switch f {
			case "ts":
				timestamp, err := parseEpochTime(fileds[i])
				if err != nil {
					return nil, fmt.Errorf("dns bro log - %s", err)
				}
				p.Timestamp = timestamp
			case "id.orig_h":
				p.SourceIP = net.ParseIP(fileds[i])
			case "query":
				p.FQDN = fileds[i]
			case "qtype_name":
				p.RecordType = fileds[i]
			case "id.resp_p":
				p, err := strconv.ParseInt(fileds[i], 10, 8)
				if err != nil {
					return nil, fmt.Errorf("dns bro log - invalid dns port at line: %q", line)
				}
				port = int(p)
			case "proto":
				proto = fileds[i]
			}
		}

		if r.port != 0 && r.port != port {
			continue
		}

		if sort.SearchStrings(r.protocols, proto) == len(r.protocols) {
			continue
		}

		packets = append(packets, &p)
	}

	if err := s.Err(); err != nil {
		return nil, err
	}
	return packets, nil
}

// Packets implements dns.Sniffer interface.
func (r *Reader) Packets() chan *dns.Packet {
	if r.c != nil {
		return r.c
	}

	r.c = make(chan *dns.Packet, 2048)
	go func() {
		defer close(r.c)
		defer r.Close()

		packets, err := r.Read()
		if err != nil {
			log.Errorln("reading suricata file failed - ", err)
			return
		}

		for _, p := range packets {
			r.c <- p
		}
	}()
	return r.c
}

// Close underlying dns log file.
func (r *Reader) Close() error {
	return r.r.Close()
}
