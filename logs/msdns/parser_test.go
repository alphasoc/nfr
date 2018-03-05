package msdns

import (
	"io/ioutil"
	"net"
	"os"
	"testing"
	"time"
)

func TestReaderReadDNS(t *testing.T) {
	const (
		filename   = "msdns-eve.json"
		logcontent = `
DNS Server log file creation at 2017-01-01 00:00:00
Message logging key (for packets - other items use a subset of these fields):
    Field #  Information         Values
    -------  -----------         ------
       1     Date
       2     Time
       3     Thread ID
       4     Context
       5     Internal packet identifier
       6     UDP/TCP indicator
       7     Send/Receive indicator
       8     Remote IP
       9     Xid (hex)
      10     Query/Response      R = Response
                                 blank = Query
      11     Opcode              Q = Standard Query
                                 N = Notify
                                 U = Update
                                 ? = Unknown
      12     [ Flags (hex)
      13     Flags (char codes)  A = Authoritative Answer
                                 T = Truncated Response
                                 D = Recursion Desired
                                 R = Recursion Available
      14     ResponseCode ]
      15     Question Type
      16     Question Name
2017-01-01 00:00:00 01A0 EVENT   The DNS server did not detect any zones of either primary or secondary type during initialization. It will not be authoritative for any zones, and it will run as a caching-only server until a zone is loaded manually or by Active Directory replication. For more information, see the online Help.
2017-01-01 00:00:00 01A0 EVENT   The DNS server has started.
2017-01-01 00:00:00 0DB8 PACKET  0000000001962BB0 UDP Rcv 10.0.0.1   0030   Q [0001   D   NOERROR] A      (8)alphasoc(3)com(0)
2017-01-01 00:00:00 0DB8 PACKET  0000000001962BB0 UDP Snd 127.0.0.1  0030   Q [0001   D   NOERROR] A      (8)alphasoc(3)com(0)
2017-01-01 00:00:00 0DB8 PACKET  0000000001962BB0 TCP Rcv 10.0.0.2   0030   Q [0001   D   NOERROR] AAAA   (8)alphasoc(3)net(0)
`
	)

	if _, err := NewFileParser("non-existing-log.json"); err == nil {
		t.Fatal("NewFileParser should return error")
	}

	if err := ioutil.WriteFile(filename, []byte(logcontent), os.ModePerm); err != nil {
		t.Fatalf("write msdns log file failed - %s", err)
	}
	defer os.Remove(filename)

	r, err := NewFileParser(filename)
	if err != nil {
		t.Fatalf("create msdns reader failed - %s", err)
	}
	defer r.Close()

	packets, err := r.ReadDNS()
	if err != nil {
		t.Fatalf("reading msdns log failed - %s", err)
	}

	if len(packets) != 2 {
		t.Fatalf("reading msdns dns package failed - want: 2, got: %d", len(packets))
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
		packets[1].Protocol == "tcp" &&
		packets[1].Timestamp.Equal(tc) &&
		packets[1].SrcIP.Equal(net.IPv4(10, 0, 0, 2)) &&
		packets[1].RecordType == "AAAA" &&
		packets[1].FQDN == "alphasoc.net") {
		t.Fatalf("invalid 2nd packet %+q", packets[1])
	}
}
