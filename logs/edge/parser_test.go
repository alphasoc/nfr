package edge

import (
	"io/ioutil"
	"net"
	"os"
	"testing"
	"time"
)

func TestReaderReadDNS(t *testing.T) {
	const (
		filename   = "edge.json"
		logcontent = `[
{"time":1529603514134,"source":"10.0.0.1","query":"google.com.","queryType":"A","queryProtocol":"UDP"},
{"time":1529603514134,"source":"10.0.0.2","query":"api.google.com.","queryType":"AAAA","queryProtocol":"TCP"}
]`
	)

	if _, err := NewFileParser("non-existing-log.json"); err == nil {
		t.Fatal("NewFileParser should return error")
	}

	if err := ioutil.WriteFile(filename, []byte(logcontent), os.ModePerm); err != nil {
		t.Fatalf("write log file failed - %s", err)
	}
	defer os.Remove(filename)

	r, err := NewFileParser(filename)
	if err != nil {
		t.Fatalf("create reader failed - %s", err)
	}
	defer r.Close()

	packets, err := r.ReadDNS()
	if err != nil {
		t.Fatalf("reading log failed - %s", err)
	}

	if len(packets) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(packets))
	}

	tc := time.Date(2018, 6, 21, 17, 51, 54, 134000000, time.UTC)
	if !(packets[0].Protocol == "udp" &&
		packets[0].Timestamp.Equal(tc) &&
		packets[0].SrcIP.Equal(net.IPv4(10, 0, 0, 1)) &&
		packets[0].RecordType == "A" &&
		packets[0].FQDN == "google.com.") {
		t.Fatalf("invalid 1st packet %+q", packets[0])
	}

	if !(packets[1].Protocol == "tcp" &&
		packets[1].Timestamp.Equal(tc) &&
		packets[1].SrcIP.Equal(net.IPv4(10, 0, 0, 2)) &&
		packets[1].RecordType == "AAAA" &&
		packets[1].FQDN == "api.google.com.") {
		t.Fatalf("invalid 2nd packet %+q", packets[1])
	}
}
