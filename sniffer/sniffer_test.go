package sniffer

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/alphasoc/nfr/packet"
	"github.com/google/gopacket/pcap"
)

func TestSS(t *testing.T) {
	cfg := &Config{
		EnableIPAnalitics:  true,
		EnableDNSAnalitics: true,
		Protocols:          []string{"udp"},
		Port:               53,
	}

	expr, _ := sprintBPFFilter(cfg)
	t.Log(expr)
}

func TestPcapSnifferPackets(t *testing.T) {
	cfg := &Config{
		EnableDNSAnalitics: true,
		Protocols:          []string{"udp"},
		Port:               53,
	}
	if _, err := NewOfflinePcapSniffer("no.data", cfg); err == nil {
		t.Fatal("sniffer create without error for non existing file")
	}

	s, err := NewOfflinePcapSniffer("sniffer_test.data", cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	i := 0
	for range s.Packets() {
		i++
	}

	if i != 1 {
		t.Errorf("invalid packet count - got: %d, expected: 1", i)
	}
}

func TestNewSniffer(t *testing.T) {
	cfg := &Config{
		EnableDNSAnalitics: true,
		Protocols:          []string{"icmp"},
		Port:               53,
	}
	handle, err := pcap.OpenOffline("sniffer_test.data")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newsniffer(handle, cfg); err == nil {
		t.Fatal("sniffer create with invalid protocol")
	}
}

func TestNewLivePcapSniffer(t *testing.T) {
	if _, err := NewLivePcapSniffer("__none", nil); err == nil {
		t.Fatal("sniffer create without error for non existing interface")
	}
}

func TestSprintBPFFilter(t *testing.T) {
	// craete pcap handler for calling SetBPFFilter
	f, err := ioutil.TempFile("", "pcap.out")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	// write header to file
	w, err := packet.NewWriter(f.Name())
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
		cfg := &Config{
			EnableDNSAnalitics: true,
			Protocols:          tt.protocols,
			Port:               tt.port,
		}
		filter, err := sprintBPFFilter(cfg)
		if (err == nil && tt.err != "") || (err != nil && err.Error() != tt.err) {
			t.Fatalf("invalid error - got: %s, want: %s", err, tt.err)
		}
		if err := handle.SetBPFFilter(filter); err != nil {
			t.Fatal(err)
		}
	}
}
