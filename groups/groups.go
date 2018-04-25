package groups

import (
	"net"
	"strings"

	"github.com/alphasoc/nfr/matchers"
)

// Group is a definition used for whitelising ip and dns traffic.
type Group struct {
	Name  string
	Label string

	// source ip/cidr
	SrcIncludes []string
	SrcExcludes []string
	// destination ip/cidr
	DstIncludes []string
	DstExcludes []string

	// only used for dns query whitelist
	ExcludedDomains []string
}

// matcher type for single group
type matcher struct {
	dm *matchers.Domain
	nm *matchers.Network
}

// Groups is a set of group definition used for whitelisting ip and dns traffic.
type Groups struct {
	ms map[string]matcher

	gs map[string]*Group
}

// New creates new Groups.
func New() *Groups {
	return &Groups{
		ms: make(map[string]matcher),
		gs: make(map[string]*Group),
	}
}

// Add adds whitelist group.
func (g *Groups) Add(group *Group) error {
	dm, err := matchers.NewDomain(group.ExcludedDomains)
	if err != nil {
		return err
	}

	nm, err := matchers.NewNetwork(group.SrcIncludes, group.SrcExcludes, group.DstIncludes, group.DstExcludes)
	if err != nil {
		return err
	}

	g.ms[group.Name] = matcher{dm, nm}
	g.gs[group.Name] = group
	return nil
}

// IsIPWhitelisted returns true if ip packet doesn't match any of a groups.
func (g *Groups) IsIPWhitelisted(srcIP, dstIP net.IP) (string, bool) {
	// if there is no groups, then every query is whitelisted
	if g == nil || len(g.ms) == 0 {
		return "<no-whitelist>", true
	}

	if srcIP == nil || dstIP == nil {
		return "<no-data>", false
	}

	// ip must be included in at least 1 group, while
	// being not excluded from others groups.
	ok := false
	for name, matcher := range g.ms {
		matched, excluded := matcher.nm.Match(srcIP, dstIP)
		if !matched {
			continue
		}
		if excluded {
			return name, false
		}
		ok = true
	}

	return "<no-match>", ok
}

// IsDNSQueryWhitelisted returns true if dns query doesn't match any of groups.
func (g *Groups) IsDNSQueryWhitelisted(domain string, srcIP, dstIP net.IP) (string, bool) {
	// if there is no group, then every query is whitelisted
	if g == nil || len(g.ms) == 0 {
		return "<no-whitelist>", true
	}

	if domain == "" || srcIP == nil {
		return "<no-data>", false
	}

	// ip must be included in at least 1 matcher, while
	// being not excluded from others groups.
	// At the same time domain can't be included in
	// groups excluded domains.
	var (
		ok                = false
		matched, excluded bool
	)
	for name, matcher := range g.ms {
		// allow dstIP to be null, some logs format dosen't track dst ip.
		if dstIP != nil {
			matched, excluded = matcher.nm.Match(srcIP, dstIP)
		} else {
			matched, excluded = matcher.nm.MatchSrcIP(srcIP)
		}
		if !matched {
			continue
		}
		if excluded {
			return name, false
		}

		// ip is matched, now check if domain is not excluded
		if matcher.dm.Match(strings.ToLower(domain)) {
			return name, false
		}

		// in case of success do not break, because the ip/domain
		// could be on other lists.
		ok = true
	}

	return "", ok
}

// FindGroupsBySrcIP finds first group src ip belongs to.
func (g *Groups) FindGroupsBySrcIP(srcIP net.IP) (groups []*Group) {
	for name, matcher := range g.ms {
		if matched, excluded := matcher.nm.MatchSrcIP(srcIP); matched && !excluded {
			groups = append(groups, g.gs[name])
		}
	}
	return
}
