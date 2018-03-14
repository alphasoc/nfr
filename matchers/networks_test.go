package matchers

import (
	"net"
	"testing"
)

func TestNetwork(t *testing.T) {
	networksTests := []struct {
		name        string
		srcincludes []string
		srcexcludes []string
		dstincludes []string
		dstexcludes []string
		srcIP       []net.IP
		dstIP       []net.IP
		expected    []bool // two bool for one test
	}{
		{
			"no network",
			nil,
			nil,
			nil,
			nil,
			[]net.IP{net.IPv4(10, 0, 0, 0)},
			[]net.IP{net.IPv4(0, 0, 0, 0)},
			[]bool{true, false, false, false},
		},
		{
			"multiple source network",
			[]string{"10.0.0.0/16", "10.1.0.0/16"},
			nil,
			nil,
			nil,
			[]net.IP{net.IPv4(10, 0, 0, 0), net.IPv4(10, 1, 0, 0), net.IPv4(10, 2, 0, 0)},
			[]net.IP{net.IPv4(0, 0, 0, 0), net.IPv4(0, 0, 0, 0), net.IPv4(0, 0, 0, 0)},
			[]bool{true, false, true, false, false, false},
		},
		{
			"exclude source network",
			[]string{"0.0.0.0/0"},
			[]string{"10.0.0.0/16"},
			nil,
			nil,
			[]net.IP{net.IPv4(10, 0, 0, 0), net.IPv4(10, 1, 0, 0)},
			[]net.IP{net.IPv4(0, 0, 0, 0), net.IPv4(0, 0, 0, 0)},
			[]bool{true, true, true, false},
		},
		{
			"many different source networks",
			[]string{"10.0.0.0/16", "10.1.0.0/16"},
			[]string{"10.0.0.0/24", "10.1.0.0"},
			nil,
			nil,
			[]net.IP{net.IPv4(10, 0, 0, 0), net.IPv4(10, 1, 0, 0), net.IPv4(10, 0, 1, 0), net.IPv4(10, 1, 1, 0)},
			[]net.IP{net.IPv4(0, 0, 0, 0), net.IPv4(0, 0, 0, 0), net.IPv4(0, 0, 0, 0), net.IPv4(0, 0, 0, 0)},
			[]bool{true, true, true, true, true, false, true, false},
		},
		{
			"max mask size source networks",
			[]string{"10.0.0.0/32", "10.0.0.1/32"},
			[]string{"10.0.0.1/32", "::1/128"},
			nil,
			nil,
			[]net.IP{net.IPv4(10, 0, 0, 0), net.IPv4(10, 0, 0, 1)},
			[]net.IP{net.IPv4(0, 0, 0, 0), net.IPv4(0, 0, 0, 0)},
			[]bool{true, false, true, true},
		},

		{
			"multiple destination network",
			nil,
			nil,
			[]string{"10.0.0.0/16", "10.1.0.0/16"},
			nil,
			[]net.IP{net.IPv4(0, 0, 0, 0), net.IPv4(0, 0, 0, 0), net.IPv4(0, 0, 0, 0)},
			[]net.IP{net.IPv4(10, 0, 0, 0), net.IPv4(10, 1, 0, 0), net.IPv4(10, 2, 0, 0)},
			[]bool{true, false, true, false, false, false},
		},
		{
			"exclude destination network",
			nil,
			nil,
			[]string{"0.0.0.0/0"},
			[]string{"10.0.0.0/16"},
			[]net.IP{net.IPv4(0, 0, 0, 0), net.IPv4(0, 0, 0, 0)},
			[]net.IP{net.IPv4(10, 0, 0, 0), net.IPv4(10, 1, 0, 0)},
			[]bool{true, true, true, false},
		},
		{
			"many different destination networks",
			nil,
			nil,
			[]string{"10.0.0.0/16", "10.1.0.0/16"},
			[]string{"10.0.0.0/24", "10.1.0.0"},
			[]net.IP{net.IPv4(0, 0, 0, 0), net.IPv4(0, 0, 0, 0), net.IPv4(0, 0, 0, 0), net.IPv4(0, 0, 0, 0)},
			[]net.IP{net.IPv4(10, 0, 0, 0), net.IPv4(10, 1, 0, 0), net.IPv4(10, 0, 1, 0), net.IPv4(10, 1, 1, 0)},
			[]bool{true, true, true, true, true, false, true, false},
		},
		{
			"max mask size destination networks",
			nil,
			nil,
			[]string{"10.0.0.0/32", "10.0.0.1/32"},
			[]string{"10.0.0.1/32", "::1/128"},
			[]net.IP{net.IPv4(0, 0, 0, 0), net.IPv4(0, 0, 0, 0)},
			[]net.IP{net.IPv4(10, 0, 0, 0), net.IPv4(10, 0, 0, 1)},
			[]bool{true, false, true, true},
		},
	}

	for _, tt := range networksTests {
		matcher, err := NewNetwork(tt.srcincludes, tt.srcexcludes, tt.dstincludes, tt.dstexcludes)
		if err != nil {
			t.Fatalf("%s %s", tt.name, err)
		}

		for i := range tt.srcIP {
			included, excluded := matcher.Match(tt.srcIP[i], tt.dstIP[i])
			if included != tt.expected[i*2] || excluded != tt.expected[i*2+1] {
				t.Fatalf("test %s - match(%s, %s) = %t, %t; expected %t, %t",
					tt.name, tt.srcIP[i], tt.dstIP[i], included, excluded,
					tt.expected[i*2], tt.expected[i*2+1])
			}
		}
	}
}

func TestInvalidNetwork(t *testing.T) {
	if _, err := NewNetwork([]string{"10.0.0.0"}, nil, nil, nil); err == nil {
		t.Fatalf("got %s; expected <nil>", err)
	}
	if _, err := NewNetwork([]string{"10.0.0.0/8"}, []string{"bad_ip_address"}, nil, nil); err == nil {
		t.Fatalf("got %s; expected <nil>", err)
	}
}
