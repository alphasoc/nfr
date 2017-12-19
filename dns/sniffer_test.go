package dns

import (
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/google/gopacket/pcap"
)

func TestPcapSnifferPackets(t *testing.T) {
	s, err := NewOfflinePcapSniffer("sniffer_test.data", []string{"udp"}, 53)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	var i int
	for range s.Packets() {
		i++
	}

	if i != 1 {
		t.Errorf("invalid packet count - got: %d, expected: 1", i)
	}
}

func TestSprintBPFFilter(t *testing.T) {
	// craete pcap handler for calling SetBPFFilter
	f, err := ioutil.TempFile("", "pcap.out")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(f.Name())
	// write header to file
	w, err := NewWriter(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	w.Close()

	handle, err := pcap.OpenOffline(f.Name())
	if err != nil {
		t.Fatal(err)
	}

	var tests = []struct {
		protocols []string
		port      int
		err       string
	}{
		{[]string{"tcp"}, 53, ""},
		{[]string{"udp"}, 53, ""},
		{[]string{"udp", "tcp"}, 53, ""},

		{[]string{"udp", "tcp", "udp"}, 0, "too many protocols in list"},
		{[]string{"icmp"}, 0, "invalid protocol \"icmp\" name"},
		{[]string{"tcp"}, -1, "invalid -1 port number"},
	}

	for _, tt := range tests {
		filter, err := sprintBPFFilter(tt.protocols, tt.port)
		if (err == nil && tt.err != "") || (err != nil && err.Error() != tt.err) {
			t.Fatalf("invalid error - got: %s, want: %s", err, tt.err)
		}
		if err := handle.SetBPFFilter(filter); err != nil {
			t.Fatal(err)
		}

	}
}
