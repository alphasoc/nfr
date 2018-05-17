package groups

import (
	"net"
	"testing"
)

func TestIsDNSQueryWhitelisted(t *testing.T) {
	var testsGroups = []struct {
		name   string
		groups []*Group

		domains  []string
		srcIps   []net.IP
		dstIps   []net.IP
		expected []bool
	}{
		{
			"allow any ips",
			[]*Group{
				{
					Name:        "allow any",
					SrcIncludes: []string{"0.0.0.0/0"},
				},
			},
			[]string{"a"},
			[]net.IP{net.IPv4(10, 0, 0, 0)},
			[]net.IP{net.IPv4(10, 0, 0, 0)},
			[]bool{true},
		},
		{
			"allow private networks",
			[]*Group{
				{
					Name:        "private network 1",
					SrcIncludes: []string{"10.0.0.0/8"},
				},
				{
					Name:        "private network 2",
					SrcIncludes: []string{"192.168.0.0/16"},
				},
			},
			[]string{"a", "a", "a"},
			[]net.IP{net.IPv4(10, 0, 0, 0), net.IPv4(192, 168, 0, 0), net.IPv4(11, 0, 0, 0)},
			[]net.IP{net.IPv4(0, 0, 0, 0), net.IPv4(0, 0, 0, 0), net.IPv4(0, 0, 0, 0)},
			[]bool{true, true, false},
		},
		{
			"allow private networks with excludes",
			[]*Group{
				{
					Name:        "private network 1",
					SrcIncludes: []string{"10.0.0.0/8"},
					SrcExcludes: []string{"10.1.0.0/16"},
				},
				{
					Name:        "private network 2",
					SrcIncludes: []string{"192.168.0.0/16"},
					SrcExcludes: []string{"10.2.0.0/16"},
				},
			},
			[]string{"a", "a", "a", "a"},
			[]net.IP{net.IPv4(10, 0, 0, 0), net.IPv4(192, 168, 0, 0), net.IPv4(10, 1, 0, 0), net.IPv4(10, 2, 0, 0)},
			[]net.IP{net.IPv4(10, 0, 0, 0), net.IPv4(192, 168, 0, 0), net.IPv4(10, 1, 0, 0), net.IPv4(10, 2, 0, 0)},
			[]bool{true, true, false, true},
		},
		{
			"include in one group then exclude in next group",
			[]*Group{
				{
					Name:        "private network 1",
					SrcIncludes: []string{"10.0.0.0/8"},
				},
				{
					Name:        "private network 2",
					SrcIncludes: []string{"10.1.0.0/16"},
					SrcExcludes: []string{"10.1.1.0/24"},
				},
			},
			[]string{"a", "a"},
			[]net.IP{net.IPv4(10, 1, 0, 0), net.IPv4(10, 1, 1, 0)},
			[]net.IP{net.IPv4(10, 1, 0, 0), net.IPv4(10, 1, 1, 0)},
			[]bool{true, false},
		},
		{
			"exclude domain in multiple groups",
			[]*Group{
				{
					Name:            "private network 1",
					SrcIncludes:     []string{"10.0.0.0/16"},
					ExcludedDomains: []string{"a"},
				},
				{
					Name:            "private network 2",
					SrcIncludes:     []string{"10.1.0.0/16"},
					ExcludedDomains: []string{"b"},
				},
			},
			[]string{"a", "b", "a", "B"},
			[]net.IP{net.IPv4(10, 0, 0, 0), net.IPv4(10, 0, 0, 0), net.IPv4(10, 1, 0, 0), net.IPv4(10, 1, 0, 0)},
			[]net.IP{net.IPv4(10, 0, 0, 0), net.IPv4(10, 0, 0, 0), net.IPv4(10, 1, 0, 0), net.IPv4(10, 1, 0, 0)},
			[]bool{false, true, true, false},
		},
		{
			"mix",
			[]*Group{
				{
					Name:        "private network",
					SrcIncludes: []string{"10.0.0.0/24", "10.1.0.0/24"},
					SrcExcludes: []string{"10.0.0.1", "10.1.0.1"},
					DstIncludes: []string{"11.0.0.0/24", "11.1.0.0/24"},
					DstExcludes: []string{"11.0.0.1", "11.1.0.1"},
				},
			},
			[]string{"a", "a", "a", "a", "a", "a"},
			[]net.IP{net.IPv4(10, 0, 0, 0), net.IPv4(10, 0, 0, 0), net.IPv4(10, 1, 0, 0), net.IPv4(10, 1, 0, 0), net.IPv4(10, 1, 0, 1), net.IPv4(10, 1, 0, 0)},
			[]net.IP{net.IPv4(10, 0, 0, 0), net.IPv4(11, 0, 0, 0), net.IPv4(10, 1, 0, 0), net.IPv4(11, 1, 0, 0), net.IPv4(11, 0, 0, 0), net.IPv4(11, 1, 0, 1)},
			[]bool{false, true, false, true, false, false},
		},
		{
			"public",
			[]*Group{
				{
					Name:            "default",
					SrcIncludes:     []string{"0.0.0.0/0"},
					SrcExcludes:     []string{},
					DstIncludes:     []string{"0.0.0.0/0", "::/0"},
					DstExcludes:     []string{"10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12", "fc00::/7"},
					ExcludedDomains: []string{"*.arpa", "*.lan", "*.local", "*.internal"},
				},
			},
			[]string{"alphasoc.com"},
			[]net.IP{net.IPv4(172, 31, 84, 103)},
			[]net.IP{net.IPv4(31, 13, 65, 56)},
			[]bool{true},
		},
	}

	for _, tt := range testsGroups {
		g := New()
		for _, group := range tt.groups {
			if err := g.Add(group); err != nil {
				t.Fatal(tt.name, err)
			}
		}
		for i := range tt.domains {
			if name, b := g.IsDNSQueryWhitelisted(tt.domains[i], tt.srcIps[i], tt.dstIps[i]); b != tt.expected[i] {
				t.Fatalf("%s IsDNSQueryWhitelisted(%s, %s, %s) %s %t; expected %t", tt.name,
					tt.domains[i], tt.srcIps[i], tt.dstIps[i], name, b, tt.expected[i])
			}
		}
	}
}

func TestIsIPWhitelisted(t *testing.T) {
	var testsGroups = []struct {
		name   string
		groups []*Group

		srcIps   []net.IP
		dstIps   []net.IP
		expected []bool
	}{
		{
			"mix",
			[]*Group{
				{
					Name:        "private network",
					SrcIncludes: []string{"10.0.0.0/24", "10.1.0.0/24"},
					SrcExcludes: []string{"10.0.0.1", "10.1.0.1"},
					DstIncludes: []string{"11.0.0.0/24", "11.1.0.0/24"},
					DstExcludes: []string{"11.0.0.1", "11.1.0.1"},
				},
			},
			[]net.IP{net.IPv4(10, 0, 0, 0), net.IPv4(10, 0, 0, 0), net.IPv4(10, 1, 0, 0), net.IPv4(10, 1, 0, 0), net.IPv4(10, 1, 0, 1), net.IPv4(10, 1, 0, 0)},
			[]net.IP{net.IPv4(10, 0, 0, 0), net.IPv4(11, 0, 0, 0), net.IPv4(10, 1, 0, 0), net.IPv4(11, 1, 0, 0), net.IPv4(11, 0, 0, 0), net.IPv4(11, 1, 0, 1)},
			[]bool{false, true, false, true, false, false},
		},
	}

	for _, tt := range testsGroups {
		g := New()
		for _, group := range tt.groups {
			if err := g.Add(group); err != nil {
				t.Fatal(err)
			}
		}
		for i := range tt.srcIps {
			if _, b := g.IsIPWhitelisted(tt.srcIps[i], tt.dstIps[i]); b != tt.expected[i] {
				t.Fatalf("IsIPWhitelisted(%s, %s) got %t; expected %t", tt.srcIps[i], tt.dstIps[i], b, tt.expected[i])
			}
		}
	}
}

func TestEmptyGroup(t *testing.T) {
	var g *Groups
	if _, b := g.IsDNSQueryWhitelisted("a", net.IPv4(10, 0, 0, 0), net.IPv4(10, 0, 0, 0)); !b {
		t.Fatalf("nil groups must whitelist domain")
	}
	g = New()
	if _, b := g.IsDNSQueryWhitelisted("a", net.IPv4(10, 0, 0, 0), net.IPv4(10, 0, 0, 0)); !b {
		t.Fatalf("no groups must whitelist domain")
	}
}
