package pcap

import (
	"testing"
)

func TestReader(t *testing.T) {
	if _, err := NewReader("no.data"); err == nil {
		t.Fatal("sniffer create without error for non existing file")
	}
}

func TestReadDNS(t *testing.T) {
	r, err := NewReader("pcap.log")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	packets, err := r.ReadDNS()
	if err != nil {
		t.Fatal(err)
	}

	if len(packets) != 1 {
		t.Errorf("invalid packet count - got: %d, expected: 1", len(packets))
	}
}

func TestReadIP(t *testing.T) {
	r, err := NewReader("pcap.log")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	packets, err := r.ReadIP()
	if err != nil {
		t.Fatal(err)
	}

	if len(packets) != 2 {
		t.Errorf("invalid packet count - got: %d, expected: 1", len(packets))
	}
}
