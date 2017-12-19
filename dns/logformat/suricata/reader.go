package suricata

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/alphasoc/nfr/dns"
)

// LogEntry represents single log file in used in surciata eve output.
type LogEntry struct {
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

// A Reader reads dns packets from suricata eve logs.
type Reader struct {
	r io.ReadCloser

	c         chan *dns.Packet
	protocols []string
	port      int
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

// Read reads all dns pacets from file.
func (r *Reader) Read() ([]*dns.Packet, error) {
	var (
		packets []*dns.Packet
		entry   LogEntry
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

		if r.port != 0 && r.port != entry.DestPort {
			continue
		}

		proto := strings.ToLower(entry.Proto)
		if sort.SearchStrings(r.protocols, proto) == len(r.protocols) {
			continue
		}

		packets = append(packets, &dns.Packet{
			Timestamp:  time.Time(entry.Timestamp),
			SourceIP:   net.ParseIP(entry.SrcIP),
			RecordType: entry.DNS.Rrtype,
			FQDN:       entry.DNS.Rrname,
		})
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
