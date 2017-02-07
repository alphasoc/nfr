package dns

import (
	"net"
	"os"
	"os/exec"
	"testing"
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

// todo Idea to improve test: create fake server and send hardcoded DNS request on loopback device
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
	defer sniffer.Close()
	if err != nil {
		t.Errorf("Start(%q) failed: err=%v", ni, err)
	}

	cmd := exec.Command("nslookup", lookup)
	if err := cmd.Run(); err != nil {
		return
	}

	dns := sniffer.GetDNS()
	if l := len(dns); l != 1 {
		t.Errorf("GetDNS() expected one request, but got %d", l)
	}

	if dns[0][0] == "" {
		t.Errorf("GetDNS() Time is empty")
	}

	srcIP := net.ParseIP(dns[0][1])
	if srcIP.To4() == nil && srcIP.To16 == nil {
		t.Errorf("GetDNS() SourceIP=%q is not IPv4 or IPv6", dns[0][1])
	}

	if dns[0][2] != qtype {
		t.Errorf("GetDNS() QType=%q, expected %q", dns[0][2], qtype)
	}

	if dns[0][3] != lookup {
		t.Errorf("GetDNS() FQDN=%q, expected %q", dns[0][3], lookup)
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
