package packet

import (
	"bytes"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func TestWriteHeader(t *testing.T) {
	dir, err := ioutil.TempDir("", "packet_writer")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	name := filepath.Join(dir, "pcap.out")

	// first time write header to file
	w, err := NewWriter(name)
	if err != nil {
		t.Fatal(err)
	}
	w.Close()

	// check if pcap reader accept file header
	closer, _ := newPcapReader(t, name)
	closer()

	// reopend file should have the same
	// content length and the same header
	b1, err := ioutil.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}

	w1, err := NewWriter(name)
	if err != nil {
		t.Fatal(err)
	}
	w1.Close()

	b2, err := ioutil.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}

	if len(b1) == 0 || !bytes.Equal(b1, b2) {
		t.Fatal("file headers different between writes", "\n", b1, "\n", b2)
	}
}

func TestWrite(t *testing.T) {
	dir, err := ioutil.TempDir("", "packet_writer")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	name := filepath.Join(dir, "out")
	w, err := NewWriter(name)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	// write one packet to file
	rawPacket := gopacket.NewPacket(testPacketDNSQuery, layers.LinkTypeEthernet, gopacket.Default)
	// set proper packet length
	md := rawPacket.Metadata()
	md.CaptureLength, md.Length = testPacketDNSQueryLenght, testPacketDNSQueryLenght
	if err = w.Write(NewDNSPacket(rawPacket)); err != nil {
		t.Fatal(err)
	}

	// read packet and check if has proper dns fileds
	closer, r := newPcapReader(t, name)
	defer closer()

	data, _, err := r.ReadPacketData()
	if err != nil {
		t.Fatal(err)
	}

	rawPacket2 := gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.Default)
	packet := NewDNSPacket(rawPacket2)

	require.NotNil(t, packet)
	require.Equal(t, "api.alphasoc.net", packet.FQDN, "invalid fqdn")
	require.Equal(t, "A", packet.RecordType, "invalid record type")
	require.True(t, net.IPv4(10, 0, 2, 15).Equal(packet.SrcIP), "invalid soruce ip")
}

func newPcapReader(t *testing.T, name string) (func() error, *pcapgo.Reader) {
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}

	r, err := pcapgo.NewReader(f)
	if err != nil {
		f.Close()
		t.Fatal(err)
	}
	return f.Close, r
}
