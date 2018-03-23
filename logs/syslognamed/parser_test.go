package syslognamed

import (
	"io/ioutil"
	"net"
	"os"
	"testing"
	"time"
)

func TestReaderReadDNS(t *testing.T) {
	const (
		filename   = "syslog-named.log"
		logcontent = `
1483228800 Jan 1 00:00:00 localhost named[100]: queries: info: client 10.0.0.1#10000 (alphasoc.com): query: alphasoc.com IN A +ED (10.0.0.1)
1483228800 Jan 1 00:00:00 localhost named[100]: queries: info: client 10.0.0.2#10001 (alphasoc.net): query: alphasoc.net IN AAAA +T (10.205.40.193)
`
	)

	if _, err := NewFileParser("non-existing-log"); err == nil {
		t.Fatal("NewFileParser should return error")
	}

	if err := ioutil.WriteFile(filename, []byte(logcontent), os.ModePerm); err != nil {
		t.Fatalf("write syslog-named log file failed - %s", err)
	}
	defer os.Remove(filename)

	r, err := NewFileParser(filename)
	if err != nil {
		t.Fatalf("create syslog-named reader failed - %s", err)
	}
	defer r.Close()

	packets, err := r.ReadDNS()
	if err != nil {
		t.Fatalf("reading syslog-named log failed - %s", err)
	}

	if len(packets) != 2 {
		t.Fatalf("reading syslog-named dns package failed - want: 2, got: %d", len(packets))
	}

	tc := time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC)
	if !(packets[0].DstPort == 0 &&
		packets[0].Protocol == "udp" &&
		packets[0].Timestamp.Equal(tc) &&
		packets[0].SrcIP.Equal(net.IPv4(10, 0, 0, 1)) &&
		packets[0].RecordType == "A" &&
		packets[0].FQDN == "alphasoc.com") {
		t.Fatalf("invalid 1st packet %+q", packets[0])
	}

	if !(packets[1].DstPort == 0 &&
		packets[1].Protocol == "udp" &&
		packets[1].Timestamp.Equal(tc) &&
		packets[1].SrcIP.Equal(net.IPv4(10, 0, 0, 2)) &&
		packets[1].RecordType == "AAAA" &&
		packets[1].FQDN == "alphasoc.net") {
		t.Fatalf("invalid 2nd packet %+q", packets[1])
	}
}
