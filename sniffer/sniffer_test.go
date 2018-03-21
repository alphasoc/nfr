package sniffer

import (
	"testing"

	"github.com/google/gopacket/pcap"
)

func TestPcapSnifferPackets(t *testing.T) {
	cfg := &Config{
		BPFilter: "tcp or udp",
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

	if i != 2 {
		t.Errorf("invalid packet count - got: %d, expected: 2", i)
	}
}

func TestNewSniffer(t *testing.T) {
	cfg := &Config{
		BPFilter: "tcp or udp",
	}
	handle, err := pcap.OpenOffline("sniffer_test.data")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newsniffer(handle, cfg); err != nil {
		t.Fatal(err)
	}
}

func TestNewLivePcapSniffer(t *testing.T) {
	if _, err := NewLivePcapSniffer("__none", nil); err == nil {
		t.Fatal("sniffer create without error for non existing interface")
	}
}
