package groups

import (
	"net"

	"github.com/alphasoc/namescore/matchers"
)

type Group struct {
	Name     string
	Includes []string
	Excludes []string
	Domains  []string
}

type matcher struct {
	dm *matchers.Domain
	nm *matchers.Network
}

type Groups struct {
	groups map[string]matcher
}

func New() *Groups {
	return &Groups{make(map[string]matcher)}
}

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

func (g *Groups) IsDomainBlacklisted(domain string) bool {
	for _, group := range g.groups {
		if group.dm.Match(domain) {
			return true
		}
	}
	return false
}

func (g *Groups) IsIPWhitelisted(ip net.IP) bool {
	for _, group := range g.groups {
		if group.nm.Match(ip) {
			return true
		}
	}
	return false
}
