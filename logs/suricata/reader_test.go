package suricata

import (
	"io/ioutil"
	"net"
	"os"
	"testing"
	"time"
)

func TestReaderReadDNS(t *testing.T) {
	const (
		filename   = "suricata-eve.json"
		logcontent = `
{"timestamp":"2017-01-01T00:00:00.000000+0000","flow_id":1,"in_iface":"eth0","event_type":"dns","src_ip":"10.0.0.1","dest_ip":"10.0.0.1","dest_port":53,"proto":"UDP","dns":{"type":"query","id":1,"rrname":"alphasoc.com","rrtype":"A","tx_id":0}}
{"timestamp":"2017-01-01T00:00:00.000000+0000","flow_id":1,"in_iface":"eth0","event_type":"dns","src_ip":"10.0.0.2","dest_ip":"10.0.0.1","dest_port":1053,"proto":"TCP","dns":{"type":"answer","id":1,"rcode":"NOERROR","rrname":"alphasoc.com","rrtype":"AAAA","ttl":300,"rdata":"35.196.211.126"}}
{"timestamp":"2017-01-01T00:00:00.000000+0000","flow_id":2,"in_iface":"eth0","event_type":"dns","src_ip":"10.0.0.2","dest_ip":"10.0.0.1","dest_port":1053,"proto":"TCP","dns":{"type":"query","id":1,"rrname":"alphasoc.net","rrtype":"AAAA","tx_id":0}}
`
	)

	if _, err := NewReader("non-existing-log.json"); err == nil {
		t.Fatal("NewReader should return error")
	}

	if err := ioutil.WriteFile(filename, []byte(logcontent), os.ModePerm); err != nil {
		t.Fatalf("write suricata log file failed - %s", err)
	}
	defer os.Remove(filename)

	r, err := NewReader(filename)
	if err != nil {
		t.Fatalf("create sucricata reader failed - %s", err)
	}
	defer r.Close()

	packets, err := r.ReadDNS()
	if err != nil {
		t.Fatalf("reading suricata log failed - %s", err)
	}

	if len(packets) != 2 {
		t.Fatalf("reading suricata dns package failed - want: 2, got: %d", len(packets))
	}

	tc := time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC)
	if !(packets[0].DstPort == 53 &&
		packets[0].Protocol == "udp" &&
		packets[0].Timestamp.Equal(tc) &&
		packets[0].SrcIP.Equal(net.IPv4(10, 0, 0, 1)) &&
		packets[0].RecordType == "A" &&
		packets[0].FQDN == "alphasoc.com") {
		t.Fatalf("invalid 1st packet %+q", packets[0])
	}

	if !(packets[1].DstPort == 1053 &&
		packets[1].Protocol == "tcp" &&
		packets[1].Timestamp.Equal(tc) &&
		packets[1].SrcIP.Equal(net.IPv4(10, 0, 0, 2)) &&
		packets[1].RecordType == "AAAA" &&
		packets[1].FQDN == "alphasoc.net") {
		t.Fatalf("invalid 2nd packet %+q", packets[1])
	}
}
