package bro

import (
	"io/ioutil"
	"net"
	"os"
	"testing"
	"time"
)

func TestReaderRead(t *testing.T) {
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
1483228800.000000	COSwep1PLjkOcNQdoa	10.0.0.1	35633	10.0.0.1	53	udp	53	-	alphasoc.com	-	-	-	A	0	NOERROR	F	F	F	T	0	35.196.211.126	t0.000000	F
1483228800.000000	CDx0B32ubObBNO6lUk	10.0.0.1	48478	10.0.0.1	53	udp	53	-	alphasoc.net	-	-	-	A	0	NOERROR	F	F	F	T	0	35.196.211.126	50.000000	F
#close	2017-01-01-00-00-00
`
	)

	if _, err := NewReader("non-existing-log.json", nil, 0); err == nil {
		t.Fatal("NewReader should return error")
	}

	if err := ioutil.WriteFile(filename, []byte(logcontent), os.ModePerm); err != nil {
		t.Fatalf("write suricata log file failed - %s", err)
	}
	defer os.Remove(filename)

	r, err := NewReader(filename, []string{"udp"}, 53)
	if err != nil {
		t.Fatalf("create sucricata reader failed - %s", err)
	}
	defer r.Close()

	packets, err := r.Read()
	if err != nil {
		t.Fatalf("reading suricata log failed - %s", err)
	}

	if len(packets) != 2 {
		t.Fatalf("reading suricata dns package failed - want: 2, got: %d", len(packets))
	}

	tc := time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC)
	if !(packets[0].Timestamp.Equal(tc) &&
		packets[0].RecordType == "A" &&
		packets[0].FQDN == "alphasoc.com") {
		t.Fatal("invalid 1st packet", packets[0], packets[0].Timestamp)
	}

	if !(packets[1].Timestamp.Equal(tc) &&
		packets[1].SourceIP.Equal(net.IPv4(10, 0, 0, 1)) &&
		packets[1].RecordType == "A" &&
		packets[1].FQDN == "alphasoc.net") {
		t.Fatalf("invalid 2nd packet")
	}
}
