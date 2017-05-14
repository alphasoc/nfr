package dns

import (
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/google/gopacket/pcap"
)

func TestSprintBPFFilter(t *testing.T) {
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

	if err := handle.SetBPFFilter(sprintBPFFilter([]string{"tcp"}, 53)); err != nil {
		t.Fatal(err)
	}
	if err := handle.SetBPFFilter(sprintBPFFilter([]string{"udp"}, 53)); err != nil {
		t.Fatal(err)
	}
	if err := handle.SetBPFFilter(sprintBPFFilter([]string{"udp", "tcp"}, 53)); err != nil {
		t.Fatal(err)
	}
}
