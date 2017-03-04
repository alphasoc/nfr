package dns

import (
	"io/ioutil"
	"net"
	"os"
	"testing"
)

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
		content = `
[networks]
  1.1.1.250
  10.100.1.5/32
  192.168.1.0/24
  127.0.0.1/8

[domains] 
  *.example.com 
  whatever.com
  google.com
  site.net
  internal.company.org`
	)

	file, errt := ioutil.TempFile("", "namescore_whitelist")
	if errt != nil {
		t.Fatalf("TempFile(), unexpected error %v", errt)
	}

	if _, err := file.WriteString(content); err != nil {
		t.Fatalf("WriteString(%q), unexpected error %v", file.Name(), err)
	}

	if err := file.Close(); err != nil {
		t.Fatalf("Close(%q), unexpected error %v", file.Name(), err)
	}

	defer func() {
		if err := os.Remove(file.Name()); err != nil {
			t.Fatalf("Remove(%q) unexpected error: %v", file.Name(), err)
		}
	}()

	w, err := NewWhitelist(file.Name())
	if err != nil {
		t.Fatalf("NewWhitelist(%q) unexpected error: %v", file.Name(), err)
	} else if w == nil {
		t.Fatalf("NewWhitelist(%q) returned nil object", file.Name())
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
		{"sub.example.com", true},
		{"www.sub.example.com", true},
		{"company.org", false},
		{"com", false},
	}

	IPs := []struct {
		ip  string
		ret bool
	}{
		{"127.0.0.1", true},
		{"127.1.0.1", true},
		{"192.168.1.1", true},
		{"192.168.1.6", true},
		{"1.1.1.250", true},
		{"10.100.1.5", true},
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

// checking whitelist reading and matching with reverse sections
func TestWhitelistReverse(t *testing.T) {
	var (
		content = `[domains] 
*.example.com 
whatever.com
google.com
site.net
internal.company.org

[networks]
1.1.1.250
10.100.1.5/32
192.168.1.0/24
127.0.0.1/8`
	)

	file, errt := ioutil.TempFile("", "namescore_whitelist")
	if errt != nil {
		t.Fatalf("TempFile(), unexpected error %v", errt)
	}

	if _, err := file.WriteString(content); err != nil {
		t.Fatalf("WriteString(%q), unexpected error %v", file.Name(), err)
	}

	if err := file.Close(); err != nil {
		t.Fatalf("Close(%q), unexpected error %v", file.Name(), err)
	}

	defer func() {
		if err := os.Remove(file.Name()); err != nil {
			t.Fatalf("Remove(%q) unexpected error: %v", file.Name(), err)
		}
	}()

	w, err := NewWhitelist(file.Name())
	if err != nil {
		t.Fatalf("NewWhitelist(%q) unexpected error: %v", file.Name(), err)
	} else if w == nil {
		t.Fatalf("NewWhitelist(%q) returned nil object", file.Name())
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
		{"sub.example.com", true},
		{"company.org", false},
		{"com", false},
	}

	IPs := []struct {
		ip  string
		ret bool
	}{
		{"127.0.0.1", true},
		{"127.1.0.1", true},
		{"192.168.1.1", true},
		{"192.168.1.6", true},
		{"1.1.1.250", true},
		{"10.100.1.5", true},
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

// checking whitelist reading and matching, only domains
func TestWhitelistOnlyDomains(t *testing.T) {
	var (
		content = `[domains] 
*.example.com 
whatever.com
google.com
site.net
internal.company.org`
	)

	file, errt := ioutil.TempFile("", "namescore_whitelist")
	if errt != nil {
		t.Fatalf("TempFile(), unexpected error %v", errt)
	}

	if _, err := file.WriteString(content); err != nil {
		t.Fatalf("WriteString(%q), unexpected error %v", file.Name(), err)
	}

	if err := file.Close(); err != nil {
		t.Fatalf("Close(%q), unexpected error %v", file.Name(), err)
	}

	defer func() {
		if err := os.Remove(file.Name()); err != nil {
			t.Fatalf("Remove(%q) unexpected error: %v", file.Name(), err)
		}
	}()

	w, err := NewWhitelist(file.Name())
	if err != nil {
		t.Fatalf("NewWhitelist(%q) unexpected error: %v", file.Name(), err)
	} else if w == nil {
		t.Fatalf("NewWhitelist(%q) returned nil object", file.Name())
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
		{"sub.example.com", true},
		{"company.org", false},
		{"com", false},
	}

	for _, d := range domains {
		if w.CheckFqdn(d.domain) != d.ret {
			t.Fatalf("CheckFqdn(%q) didn't return %v", d.domain, d.ret)
		}
	}
}

// checking whitelist reading and matching, only networks
func TestWhitelistOnlyNeworks(t *testing.T) {
	var (
		content = `
[networks]
1.1.1.250
10.100.1.5/32
192.168.1.0/24
127.0.0.1/8`
	)

	file, errt := ioutil.TempFile("", "namescore_whitelist")
	if errt != nil {
		t.Fatalf("TempFile(), unexpected error %v", errt)
	}

	if _, err := file.WriteString(content); err != nil {
		t.Fatalf("WriteString(%q), unexpected error %v", file.Name(), err)
	}

	if err := file.Close(); err != nil {
		t.Fatalf("Close(%q), unexpected error %v", file.Name(), err)
	}

	defer func() {
		if err := os.Remove(file.Name()); err != nil {
			t.Fatalf("Remove(%q) unexpected error: %v", file.Name(), err)
		}
	}()

	w, err := NewWhitelist(file.Name())
	if err != nil {
		t.Fatalf("NewWhitelist(%q) unexpected error: %v", file.Name(), err)
	} else if w == nil {
		t.Fatalf("NewWhitelist(%q) returned nil object", file.Name())
	}

	IPs := []struct {
		ip  string
		ret bool
	}{
		{"127.0.0.1", true},
		{"127.1.0.1", true},
		{"192.168.1.1", true},
		{"192.168.1.6", true},
		{"1.1.1.250", true},
		{"10.100.1.5", true},
		{"192.169.1.0", false},
		{"192.168.2.0", false},
	}

	for _, i := range IPs {
		j := net.ParseIP(i.ip)
		if w.CheckIP(j) != i.ret {
			t.Fatalf("CheckIP(%q) didn't return %v", i.ip, i.ret)
		}
	}
}

func TestWhitelistIPParserFail(t *testing.T) {
	lines := []string{
		"invalid",
		"1-1",
		"1.1.1.1.1.1",
		"32/13.12.31.31",
		"12.1.1.1/asd",
	}

	whitelist := &Whitelist{}

	for _, line := range lines {
		if err := whitelist.networkParser(line); err == nil {
			t.Fatalf("networkParser(%q) didn't return error", line)
		}
	}
}

func TestWhitelistDomainParser(t *testing.T) {
	var (
		lineMultimatch  = "*.google.com"
		storeMultimatch = ".google.com"
		lineStrict      = "site.com"
		storeStrict     = "site.com"
	)
	whitelist := &Whitelist{}
	if err := whitelist.domainParser(lineMultimatch); err != nil {
		t.Fatalf("domainParser(%q) unexpected error=%v", lineMultimatch, err)
	}
	if err := whitelist.domainParser(lineStrict); err != nil {
		t.Fatalf("domainParser(%q) unexpected error=%v", lineStrict, err)
	}

	if len(whitelist.multimatchDomains) != 1 {
		t.Fatalf("len(whitelist.multimatchDomains), expected 1, got %d", len(whitelist.multimatchDomains))
	}

	if len(whitelist.strictDomains) != 1 {
		t.Fatalf("len(whitelist.strictDomains), expected 1, got %d", len(whitelist.strictDomains))
	}

	if whitelist.multimatchDomains[0] != storeMultimatch {
		t.Fatalf("domainParser(%q) unexpected to store %q, got %q", lineMultimatch, storeMultimatch, whitelist.multimatchDomains[0])
	}

	if whitelist.strictDomains[0] != storeStrict {
		t.Fatalf("domainParser(%q) unexpected to store %q, got %q", lineMultimatch, storeStrict, whitelist.strictDomains[0])
	}

}

// checking whitelist reading and matching if whitelist is empty
func TestWhitelistEmpty(t *testing.T) {
	var (
		content = `
[networks]
[domains]`
	)

	file, errt := ioutil.TempFile("", "namescore_whitelist")
	if errt != nil {
		t.Fatalf("TempFile(), unexpected error %v", errt)
	}

	if _, err := file.WriteString(content); err != nil {
		t.Fatalf("WriteString(%q), unexpected error %v", file.Name(), err)
	}

	if err := file.Close(); err != nil {
		t.Fatalf("Close(%q), unexpected error %v", file.Name(), err)
	}

	defer func() {
		if err := os.Remove(file.Name()); err != nil {
			t.Fatalf("Remove(%q) unexpected error: %v", file.Name(), err)
		}
	}()

	w, err := NewWhitelist(file.Name())
	if err != nil {
		t.Fatalf("NewWhitelist(%q) unexpected error: %v", file.Name(), err)
	} else if w == nil {
		t.Fatalf("NewWhitelist(%q) returned nil object", file.Name())
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
		{"sub.example.com", false},
		{"company.org", false},
		{"com", false},
	}

	IPs := []struct {
		ip  string
		ret bool
	}{
		{"127.0.0.1", false},
		{"127.1.0.1", false},
		{"192.168.1.1", false},
		{"192.168.1.6", false},
		{"1.1.1.250", false},
		{"10.100.1.5", false},
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
