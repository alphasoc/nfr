package groups

import (
	"net"

	"github.com/alphasoc/nfr/matchers"
)

// Group represents single group used for
// whitelising dns traffic.
type Group struct {
	Name     string
	Includes []string
	Excludes []string
	Domains  []string
}

// matcher type for single group
type matcher struct {
	dm *matchers.Domain
	nm *matchers.Network
}

// Groups represents all groups used for
// whitelisting dns traffic.
type Groups struct {
	groups map[string]matcher
}

// New creates new Groups.
func New() *Groups {
	return &Groups{make(map[string]matcher)}
}

// Add adds whitelist group.
func (g *Groups) Add(group *Group) error {
	dm, err := matchers.NewDomain(group.Domains)
	if err != nil {
		return err
	}

	nm, err := matchers.NewNetwork(group.Includes, group.Excludes)
	if err != nil {
		return err
	}
	g.groups[group.Name] = matcher{dm, nm}
	return nil
}

// IsDNSQueryWhitelisted returns true if dns query is not match any of groups
func (g *Groups) IsDNSQueryWhitelisted(domain string, ip net.IP) (string, bool) {
	// if there is no groups, then every query is whitelisted
	if g == nil || len(g.groups) == 0 {
		return "<no-whitelsit>", true
	}

	if domain == "" || ip == nil {
		return "<no-data>", false
	}

	ok, groupName := false, ""
	// ip must be included in at least 1 group, while
	// being not excluded from others groups.
	// At the same time domain can't be included in
	// groups' excluded domains.
	for name, group := range g.groups {
		matched, excluded := group.nm.Match(ip)
		if !matched {
			continue
		}
		if excluded {
			return name, false
		}

		// ip is matched, now check if domain is not excluded
		if group.dm.Match(domain) {
			return name, false
		}

		// in case of success do not break, because the ip/domain
		// could be on other lists.
		ok, groupName = true, name
	}

	return groupName, ok
}
