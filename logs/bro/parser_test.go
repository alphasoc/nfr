package bro

import (
	"io/ioutil"
	"net"
	"os"
	"testing"
	"time"

	"github.com/alphasoc/nfr/packet"
)

func TestReaderReadDNS(t *testing.T) {
	const (
		filename   = "dns.log"
		logcontent = `#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	dns
#open	2017-01-01-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	trans_id	rtt	query	qclass	qclass_name	qtype	qtype_name	rcode	rcode_name	AA	TC	RD	RA	Z	answers	TTLs	rejected
#types	time	string	addr	port	addr	port	enum	count	interval	string	count	string	count	string	count	string	bool	bool	bool	bool	count	vector[string]	vector[interval]	bool
1483228800.000000	COSwep1PLjkOcNQdoa	10.0.0.1	52213	10.0.0.1	53	udp	53	-	alphasoc.com	-	-	-	A	0	NOERROR	F	F	F	T	0	35.196.211.126	t0.000000	F

1483228800.000000	CDx0B32ubObBNO6lUk	10.0.0.1	52214	10.0.0.1	53	udp	53	-	alphasoc.net	-	-	-	A	0	NOERROR	F	F	F	T	0	35.196.211.126	50.000000	F
#close	2017-01-01-00-00-00
`
	)

	if _, err := NewFileParser("non-existing-log.json"); err == nil {
		t.Fatal("file parser should return error")
	}

	if err := ioutil.WriteFile(filename, []byte(logcontent), os.ModePerm); err != nil {
		t.Fatalf("write bro log file failed - %s", err)
	}
	defer os.Remove(filename)

	r, err := NewFileParser(filename)
	if err != nil {
		t.Fatalf("create sucricata parser failed - %s", err)
	}
	defer r.Close()

	packets, err := r.ReadDNS()
	if err != nil {
		t.Fatalf("reading bro log failed - %s", err)
	}

	if len(packets) != 2 {
		t.Fatalf("reading bro dns package failed - want: 2, got: %d", len(packets))
	}

	tc := time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC)
	if !(packets[0].DstPort == 53 &&
		packets[0].SrcPort == 52213 &&
		packets[0].Protocol == "udp" &&
		packets[0].Timestamp.Equal(tc) &&
		packets[0].RecordType == "A" &&
		packets[0].FQDN == "alphasoc.com") {
		t.Fatal("invalid 1st packet", packets[0])
	}

	if !(packets[1].DstPort == 53 &&
		packets[1].SrcPort == 52214 &&
		packets[1].Protocol == "udp" &&
		packets[1].Timestamp.Equal(tc) &&
		packets[1].SrcIP.Equal(net.IPv4(10, 0, 0, 1)) &&
		packets[1].RecordType == "A" &&
		packets[1].FQDN == "alphasoc.net") {
		t.Fatal("invalid 2st packet", packets[1])
	}
}

func TestReaderReadIP(t *testing.T) {
	const (
		filename   = "ip.log"
		logcontent = `#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	2018-01-24-01-01-01
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents
#types	time	string	addr	port	addr	port	enum	string	interval	count	count	string	bool	bool	count	string	count	count	count	count	set[string]
1483228800.000000	1	10.0.0.1	5021	10.0.0.2	22	udp	ssh	-	-	-	S0	-	-	0	D	1	10	0	0	(empty)
1483228800.000000	2	10.0.0.1	3210	10.0.0.2	22	tcp	ssh	-	-	20	S1	-	-	0	D	1	0	0	0	(empty)`
	)

	if _, err := NewFileParser("non-existing-log.json"); err == nil {
		t.Fatal("file parser should return error")
	}

	if err := ioutil.WriteFile(filename, []byte(logcontent), os.ModePerm); err != nil {
		t.Fatalf("write bro log file failed - %s", err)
	}
	defer os.Remove(filename)

	r, err := NewFileParser(filename)
	if err != nil {
		t.Fatalf("create sucricata parser failed - %s", err)
	}
	defer r.Close()

	packets, err := r.ReadIP()
	if err != nil {
		t.Fatalf("reading bro log failed - %s", err)
	}

	if len(packets) != 2 {
		t.Fatalf("reading bro dns package failed - want: 2, got: %d", len(packets))
	}

	tc := time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC)
	if !(packets[0].SrcIP.Equal(net.IPv4(10, 0, 0, 1)) &&
		packets[0].SrcPort == 5021 &&
		packets[0].DstIP.Equal(net.IPv4(10, 0, 0, 2)) &&
		packets[0].DstPort == 22 &&
		packets[0].Protocol == "udp" &&
		packets[0].Timestamp.Equal(tc) &&
		packets[0].BytesCount == 10 &&
		packets[0].Direction == packet.DirectionOut) {
		t.Fatal("invalid 1st packet")
	}

	if !(packets[1].SrcIP.Equal(net.IPv4(10, 0, 0, 1)) &&
		packets[1].SrcPort == 3210 &&
		packets[1].DstIP.Equal(net.IPv4(10, 0, 0, 2)) &&
		packets[1].DstPort == 22 &&
		packets[1].Protocol == "tcp" &&
		packets[1].Timestamp.Equal(tc) &&
		packets[1].BytesCount == 20 &&
		packets[1].Direction == packet.DirectionIn) {
		t.Fatal("invalid 2nd packet")
	}
}
