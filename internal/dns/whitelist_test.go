package dns

import "testing"
import "io/ioutil"
import "os"
import "net"

// no errors should be returned when whitelist file does not exits
func TestWhitelistNonExist(t *testing.T) {
	var (
		file = "/tmp/namescore_whitelist.nonexist"
	)

	w, err := NewWhitelist(file)
	if err == nil {
		t.Fatalf("NewWhitelist(%q) expected error", file)
	} else if w != nil {
		t.Fatalf("NewWhitelist(%q) returned non-nil object", file)
	}
}

// checking whitelist reading and matching
func TestWhitelist(t *testing.T) {
	var (
		file    = "/tmp/namescore_whitelist_test"
		content = `networks = ["192.168.1.0/24", "127.0.0.1/8"]
domains = ["google.com", "site.net", "internal.company.org"]`
	)

	if err := ioutil.WriteFile(file, []byte(content), 0666); err != nil {
		t.Fatalf("When creating test file %q unexpected error: %v", file, err)
	}
	defer func() {
		if err := os.Remove(file); err != nil {
			t.Fatalf("Remove(%q) unexpected error: %v", file, err)
		}
	}()

	w, err := NewWhitelist(file)
	if err != nil {
		t.Fatalf("NewWhitelist(%q) unexpected error: %v", file, err)
	} else if w == nil {
		t.Fatalf("NewWhitelist(%q) returned nil object", file)
	}

	domains := []struct {
		domain string
		ret    bool
	}{
		{"google.com", true},
		{"site.net", true},
		{"google.com", true},
		{"fake.org", false},
		{"org", false},
		{"company.org", false},
	}

	IPs := []struct {
		ip  string
		ret bool
	}{
		{"127.0.0.1", true},
		{"127.1.0.1", true},
		{"192.168.1.1", true},
		{"192.168.1.6", true},
		{"192.169.1.0", false},
		{"192.168.2.0", false},
	}

	for _, d := range domains {
		if w.CheckFqdn(d.domain) != d.ret {
			t.Fatalf("CheckFqdn(%q) didn't return %v", d.domain, d.ret)
		}
	}

	for _, i := range IPs {
		j := net.ParseIP(i.ip)
		if w.CheckIP(j) != i.ret {
			t.Fatalf("CheckIP(%q) didn't return %v", i.ip, i.ret)
		}
	}
}

// only domains in file
func TestWhitelistOnlyDomains(t *testing.T) {
	var (
		file    = "/tmp/namescore_whitelist_test"
		content = `domains = ["google.com", "site.net", "internal.company.org"]`
	)

	if err := ioutil.WriteFile(file, []byte(content), 0666); err != nil {
		t.Fatalf("When creating test file %q unexpected error: %v", file, err)
	}
	defer func() {
		if err := os.Remove(file); err != nil {
			t.Fatalf("Remove(%q) unexpected error: %v", file, err)
		}
	}()

	w, err := NewWhitelist(file)
	if err != nil {
		t.Fatalf("NewWhitelist(%q) unexpected error: %v", file, err)
	} else if w == nil {
		t.Fatalf("NewWhitelist(%q) returned nil object", file)
	}

	domains := []struct {
		domain string
		ret    bool
	}{
		{"google.com", true},
		{"site.net", true},
		{"google.com", true},
		{"fake.org", false},
		{"org", false},
		{"company.org", false},
	}

	IPs := []struct {
		ip  string
		ret bool
	}{
		{"127.0.0.1", false},
		{"127.1.0.1", false},
		{"192.168.1.1", false},
		{"192.168.1.6", false},
		{"192.169.1.0", false},
		{"192.168.2.0", false},
	}

	for _, d := range domains {
		if w.CheckFqdn(d.domain) != d.ret {
			t.Fatalf("CheckFqdn(%q) didn't return %v", d.domain, d.ret)
		}
	}

	for _, i := range IPs {
		j := net.ParseIP(i.ip)
		if w.CheckIP(j) != i.ret {
			t.Fatalf("CheckIP(%q) didn't return %v", i.ip, i.ret)
		}
	}
}

// only networks in file
func TestWhitelistOnlyNets(t *testing.T) {
	var (
		file    = "/tmp/namescore_whitelist_test"
		content = `networks = ["192.168.1.0/24", "127.0.0.1/8"]`
	)

	if err := ioutil.WriteFile(file, []byte(content), 0666); err != nil {
		t.Fatalf("When creating test file %q unexpected error: %v", file, err)
	}
	defer func() {
		if err := os.Remove(file); err != nil {
			t.Fatalf("Remove(%q) unexpected error: %v", file, err)
		}
	}()

	w, err := NewWhitelist(file)
	if err != nil {
		t.Fatalf("NewWhitelist(%q) unexpected error: %v", file, err)
	} else if w == nil {
		t.Fatalf("NewWhitelist(%q) returned nil object", file)
	}

	domains := []struct {
		domain string
		ret    bool
	}{
		{"google.com", false},
		{"site.net", false},
		{"google.com", false},
		{"fake.org", false},
		{"org", false},
		{"company.org", false},
	}

	IPs := []struct {
		ip  string
		ret bool
	}{
		{"127.0.0.1", true},
		{"127.1.0.1", true},
		{"192.168.1.1", true},
		{"192.168.1.6", true},
		{"192.169.1.0", false},
		{"192.168.2.0", false},
	}

	for _, d := range domains {
		if w.CheckFqdn(d.domain) != d.ret {
			t.Fatalf("CheckFqdn(%q) didn't return %v", d.domain, d.ret)
		}
	}

	for _, i := range IPs {
		j := net.ParseIP(i.ip)
		if w.CheckIP(j) != i.ret {
			t.Fatalf("CheckIP(%q) didn't return %v", i.ip, i.ret)
		}
	}
}
