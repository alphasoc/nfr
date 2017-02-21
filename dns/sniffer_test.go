package dns

import (
	"net"
	"os"
	"os/exec"
	"testing"

	"github.com/alphasoc/namescore/asoc"
)

func TestSnifferWrongInterface(t *testing.T) {
	wrongInterface := "invalid_network_interface"
	sniffer, err := Start(wrongInterface)
	if err == nil {
		t.Errorf("Start(%q) expected err", wrongInterface)
	}

	if sniffer != nil {
		t.Errorf("Start(%q) expected nil sniffer", wrongInterface)
	}
}

func TestSniffer(t *testing.T) {
	lookup := "google.com"
	qtype := "A"

	if os.Getuid() != 0 {
		return
	}

	ni := getIface()
	if ni == "" {
		return
	}

	sniffer, err := Start(ni)
	if err != nil {
		t.Fatalf("Start(%q) failed: err=%v", ni, err)
	}
	defer sniffer.handle.Close()

	cmd := exec.Command("nslookup", lookup)
	if err := cmd.Run(); err != nil {
		t.Fatalf("exec of nslookup failed err=%v", err)
	}

	var dns []asoc.Entry

	for {
		packet := sniffer.Sniff()
		if packet == nil {
			t.Fatalf("Sniff() returned empty packet")
		}

		if dns = sniffer.PacketToEntry(packet); dns != nil {
			break
		}

	}

	if l := len(dns); l != 1 {
		t.Errorf("GetDNS() expected one request, but got %d", l)
	}

	if dns[0].IP.To4() == nil && dns[0].IP.To16() == nil {
		t.Errorf("GetDNS() SourceIP=%q is not IPv4 or IPv6", dns[0].IP.String())
	}

	if dns[0].QType != qtype {
		t.Errorf("GetDNS() QType=%q, expected %q", dns[0].QType, qtype)
	}

	if dns[0].FQDN != lookup {
		t.Errorf("GetDNS() FQDN=%q, expected %q", dns[0].FQDN, lookup)
	}
}

func BenchmarkSniffer(b *testing.B) {
	ni := getIface()
	sniffer, err := Start(ni)
	if err != nil {
		b.Fatalf("Start(%q) failed: err=%v", ni, err)
	}
	defer sniffer.handle.Close()

	cmd := exec.Command("nslookup", "google.pl")
	if err := cmd.Run(); err != nil {
		return
	}
	packet := sniffer.Sniff()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sniffer.PacketToEntry(packet)
	}
}

func getIface() string {
	n, err := net.Interfaces()
	if err != nil {
		return ""
	}

	for _, v := range n {
		if v.Flags&net.FlagLoopback != 0 {
			continue
		}

		a, e := v.Addrs()
		if e != nil || a == nil {
			continue
		}

		return v.Name
	}
	return ""
}
