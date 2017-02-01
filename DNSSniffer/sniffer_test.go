package DNSSniffer

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

	if dns[0].FQDN != lookup {
		t.Errorf("GetDNS() FQDN=%q, expected %q", dns[0].FQDN, lookup)
	}

	if dns[0].QType != qtype {
		t.Errorf("GetDNS() QType=%q, expected %q", dns[0].QType, qtype)
	}

	if dns[0].Time == "" {
		t.Errorf("GetDNS() Time is empty")
	}

	srcIP := net.ParseIP(dns[0].SourceIP)
	if srcIP.To4() == nil && srcIP.To16 == nil {
		t.Errorf("GetDNS() SourceIP is not IPv4 or IPv6")
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
