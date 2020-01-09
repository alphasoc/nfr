package bro

import (
	"io/ioutil"
	"net"
	"os"
	"testing"
	"time"
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

1483228800.000000	CDx0B32ubObBNO6lUk	10.0.0.1	52214	10.0.0.1	53	udp	53	-	alphasoc.net	-	-	-	-	0	NOERROR	F	F	F	T	0	35.196.211.126	50.000000	F
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
		packets[1].RecordType == "" &&
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
		t.Fatalf("create bro parser failed - %s", err)
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
		packets[0].BytesCount == 10) {
		t.Fatal("invalid 1st packet")
	}

	if !(packets[1].SrcIP.Equal(net.IPv4(10, 0, 0, 1)) &&
		packets[1].SrcPort == 3210 &&
		packets[1].DstIP.Equal(net.IPv4(10, 0, 0, 2)) &&
		packets[1].DstPort == 22 &&
		packets[1].Protocol == "tcp" &&
		packets[1].Timestamp.Equal(tc) &&
		packets[1].BytesCount == 20) {
		t.Fatal("invalid 2nd packet")
	}
}

func TestReaderReadHTTP(t *testing.T) {
	const (
		filename   = "http.log"
		logcontent = `#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	http
#open	2019-10-01-16-08-28
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	trans_depth	method	host	uri	referrer	version	user_agent	request_body_len	response_body_len	status_code	status_msg	info_code	info_msg	tags	username	password	proxied	orig_fuids	orig_filenames	orig_mime_types	resp_fuids	resp_filenames	resp_mime_types
#types	time	string	addr	port	addr	port	count	string	string	string	string	string	string	count	count	count	string	count	string	set[enum]	string	string	set[string]	vector[string]	vector[string]	vector[string]	vector[string]	vector[string]	vector[string]
1569938908.384253	C2YBbB4oCIHnYJQbhh	10.0.0.1	50434	17.253.107.201	80	1	GET	ocsp.apple.com	/ocsp-devid01/ME4wTKADAgEAMEUwQzBBMAkGBSsOAwIaBQAEFDOB0e/baLCFIU0u76+MSmlkPCpsBBRXF+2iz9x8mKEQ4Py+hy0s8uMXVAIIFelDYw2P904=	-	1.1	com.apple.trustd/2.0	0	3698	200	OK	-	-	(empty)	-	-	-	-	-	-	FlUaB7nbVNzuhJpgh	-	application/ocsp-response
1569938911.839230	CPgxUR3KvtWXSHXpRl	10.0.0.2	50450	80.252.0.235	80	1	GET	gazeta.hit.gemius.pl	/gemius.js	http://wyborcza.pl/0,0.html	1.1	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1 Safari/605.1.15	0	0	304	Not Modified	-	-	(empty)	-	-	-	-	-	-	-	-	-
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
		t.Fatalf("create bro parser failed - %s", err)
	}
	defer r.Close()

	packets, err := r.ReadHTTP()
	if err != nil {
		t.Fatalf("reading bro log failed - %s", err)
	}

	if len(packets) != 2 {
		t.Fatalf("reading bro dns package failed - want: 2, got: %d", len(packets))
	}

	if !(packets[0].Timestamp.Equal(time.Date(2019, 10, 1, 14, 8, 28, 384253, time.UTC)) &&
		packets[0].SrcIP.Equal(net.IPv4(10, 0, 0, 1)) &&
		packets[0].SrcPort == 50434 &&
		packets[0].URL == "http://ocsp.apple.com/ocsp-devid01/ME4wTKADAgEAMEUwQzBBMAkGBSsOAwIaBQAEFDOB0e/baLCFIU0u76+MSmlkPCpsBBRXF+2iz9x8mKEQ4Py+hy0s8uMXVAIIFelDYw2P904=" &&
		packets[0].Method == "GET" &&
		packets[0].Referrer == "" &&
		packets[0].Status == 200 &&
		packets[0].BytesOut == 0 &&
		packets[0].BytesIn == 3698 &&
		packets[0].ContentType == "application/ocsp-response" &&
		packets[0].UserAgent == "com.apple.trustd/2.0") {
		t.Errorf("invalid 1st packet: %+v", packets[0])
	}

	if !(packets[1].Timestamp.Equal(time.Date(2019, 10, 1, 14, 8, 31, 839230, time.UTC)) &&
		packets[1].SrcIP.Equal(net.IPv4(10, 0, 0, 2)) &&
		packets[1].SrcPort == 50450 &&
		packets[1].URL == "http://gazeta.hit.gemius.pl/gemius.js" &&
		packets[1].Method == "GET" &&
		packets[1].Referrer == "http://wyborcza.pl/0,0.html" &&
		packets[1].Status == 304 &&
		packets[1].BytesOut == 0 &&
		packets[1].BytesIn == 0 &&
		packets[1].ContentType == "" &&
		packets[1].UserAgent == "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1 Safari/605.1.15") {
		t.Errorf("invalid 2nd packet: %+v", packets[1])
	}
}
