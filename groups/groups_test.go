package groups

import (
	"net"
	"testing"
)

func TestGroups(t *testing.T) {
	var testsGroups = []struct {
		name   string
		groups []*Group

		domains  []string
		ips      []net.IP
		expected []bool
	}{
		{
			"allow any ips",
			[]*Group{
				&Group{
					Name:     "allow any",
					Includes: []string{"0.0.0.0/0"},
				},
			},
			[]string{"a"},
			[]net.IP{net.IPv4(10, 0, 0, 0)},
			[]bool{true},
		},
		{
			"allow private networks",
			[]*Group{
				&Group{
					Name:     "private network 1",
					Includes: []string{"10.0.0.0/8"},
				},
				&Group{
					Name:     "private network 2",
					Includes: []string{"192.168.0.0/16"},
				},
			},
			[]string{"a", "a", "a"},
			[]net.IP{net.IPv4(10, 0, 0, 0), net.IPv4(192, 168, 0, 0), net.IPv4(11, 0, 0, 0)},
			[]bool{true, true, false},
		},
		{
			"allow private networks with excludes",
			[]*Group{
				&Group{
					Name:     "private network 1",
					Includes: []string{"10.0.0.0/8"},
					Excludes: []string{"10.1.0.0/16"},
				},
				&Group{
					Name:     "private network 2",
					Includes: []string{"192.168.0.0/16"},
					Excludes: []string{"10.2.0.0/16"},
				},
			},
			[]string{"a", "a", "a", "a"},
			[]net.IP{net.IPv4(10, 0, 0, 0), net.IPv4(192, 168, 0, 0), net.IPv4(10, 1, 0, 0), net.IPv4(10, 2, 0, 0)},
			[]bool{true, true, false, true},
		},
		{
			"include in one group then exclude in next group",
			[]*Group{
				&Group{
					Name:     "private network 1",
					Includes: []string{"10.0.0.0/8"},
				},
				&Group{
					Name:     "private network 2",
					Includes: []string{"10.1.0.0/16"},
					Excludes: []string{"10.1.1.0/24"},
				},
			},
			[]string{"a", "a"},
			[]net.IP{net.IPv4(10, 1, 0, 0), net.IPv4(10, 1, 1, 0)},
			[]bool{true, false},
		},
		{
			"exclude domain in multiple groups",
			[]*Group{
				&Group{
					Name:     "private network 1",
					Includes: []string{"10.0.0.0/16"},
					Domains:  []string{"a"},
				},
				&Group{
					Name:     "private network 2",
					Includes: []string{"10.1.0.0/16"},
					Domains:  []string{"b"},
				},
			},
			[]string{"a", "b", "a", "b"},
			[]net.IP{net.IPv4(10, 0, 0, 0), net.IPv4(10, 0, 0, 0), net.IPv4(10, 1, 0, 0), net.IPv4(10, 1, 0, 0)},
			[]bool{false, true, true, false},
		},
	}

	for _, tt := range testsGroups {
		g := New()
		for _, group := range tt.groups {
			if err := g.Add(group); err != nil {
				t.Fatal(err)
			}
		}
		for i := range tt.domains {
			if g.IsDNSQueryWhitelisted(tt.domains[i], tt.ips[i]) != tt.expected[i] {
				t.Fatalf("IsDNSQueryWhitelisted(%s, %s) got %t; expected %t",
					tt.domains[i], tt.ips[i], !tt.expected[i], tt.expected[i])
			}
		}
	}
}

func TestEmptyGroup(t *testing.T) {
	var g *Groups
	if !g.IsDNSQueryWhitelisted("a", net.IPv4(10, 0, 0, 0)) {
		t.Fatalf("nil groups must whitelist domain")
	}

	if g = New(); !g.IsDNSQueryWhitelisted("a", net.IPv4(10, 0, 0, 0)) {
		t.Fatalf("no groups must whitelist domain")
	}
}
