package matchers

import (
	"net"
	"testing"
)

func TestNetwork(t *testing.T) {
	networksTests := []struct {
		name     string
		includes []string
		excludes []string
		cases    []net.IP
		expected []bool // store two bool for one test
	}{
		{
			"include 0.0.0.0/0 network",
			[]string{"0.0.0.0/0"},
			[]string{},
			[]net.IP{net.IPv4(10, 0, 0, 0), nil},
			[]bool{true, false, false, false},
		},
		{
			"multiple includes network",
			[]string{"10.0.0.0/16", "10.1.0.0/16"},
			[]string{},
			[]net.IP{net.IPv4(10, 0, 0, 0), net.IPv4(10, 1, 0, 0), net.IPv4(10, 2, 0, 0)},
			[]bool{true, false, true, false, false, false},
		},
		{
			"exclude network",
			[]string{"0.0.0.0/0"},
			[]string{"10.0.0.0/16"},
			[]net.IP{net.IPv4(10, 0, 0, 0), net.IPv4(10, 1, 0, 0)},
			[]bool{true, true, true, false},
		},
		{
			"many diffrent networks",
			[]string{"10.0.0.0/16", "10.1.0.0/16"},
			[]string{"10.0.0.0/24", "10.1.0.0"},
			[]net.IP{net.IPv4(10, 0, 0, 0), net.IPv4(10, 1, 0, 0), net.IPv4(10, 0, 1, 0), net.IPv4(10, 1, 1, 0)},
			[]bool{true, true, true, true, true, false, true, false},
		},
	}

	for _, tt := range networksTests {
		matcher, err := NewNetwork(tt.includes, tt.excludes)
		if err != nil {
			t.Fatalf("%s %s", tt.name, err)
		}
		for i := range tt.cases {
			included, excluded := matcher.Match(tt.cases[i])
			if included != tt.expected[i*2] || excluded != tt.expected[i*2+1] {
				t.Fatalf("test %s - match(%s) = %t, %t; want %t, %t", tt.name, tt.cases[i],
					included, excluded, tt.expected[i*2], tt.expected[i*2+1])
			}
		}
	}
}

func TestInvalidNetwork(t *testing.T) {
	if _, err := NewNetwork([]string{"10.0.0.0"}, nil); err == nil {
		t.Fatalf("got %s; expected <nil>", err)
	}
	if _, err := NewNetwork([]string{"10.0.0.0/8"}, []string{"bad_ip_address"}); err == nil {
		t.Fatalf("got %s; expected <nil>", err)
	}
	if _, err := NewNetwork(nil, nil); err == nil {
		t.Fatalf("got %s; expected <nil>", err)
	}
}
