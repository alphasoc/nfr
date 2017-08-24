package matchers

import (
	"fmt"
	"strings"

	"github.com/alphasoc/nfr/utils"
)

// Domain matches domain on blacklist.
type Domain struct {
	snames    map[string]bool // strict domain names
	mnames    map[string]bool // multimatch domain names
	maxLabels int             // maxLabels is max count of '.' char in multimatch domains map
}

// NewDomain creates Domain macher for given domains list.
// It retrus errors if any of domain has invalid format.
// Domains could be strict domain like alphasoc.com or
// multimatch domain with prefix *. like *.alphasoc.com.
func NewDomain(domains []string) (*Domain, error) {
	d := &Domain{
		snames: make(map[string]bool),
		mnames: make(map[string]bool),
	}
	return d, d.add(domains)
}

// add adds domains to Domain matcher.
func (m *Domain) add(domains []string) error {
	for _, domain := range domains {
		// check if it's valid strict or multimatch domain
		if !utils.IsDomainName(domain) &&
			!utils.IsDomainName(strings.TrimPrefix(domain, "*.")) {
			// Do not add invalid domains
			return fmt.Errorf("%s is not valid domain name", domain)
		}

		// if it's strict domain then put it on list
		if !strings.HasPrefix(domain, "*") {
			domain = strings.Trim(domain, ".")
			m.snames[domain] = true
			continue
		}

		// otherwise domain must be multimatch domain
		domain = strings.TrimPrefix(domain, "*")
		domain = strings.Trim(domain, ".")
		m.mnames[domain] = true

		if labels := strings.Count(domain, ".") + 1; labels > m.maxLabels {
			m.maxLabels = labels
		}
	}
	return nil
}

// Match matches domain and check if it's on any domain blacklist.
func (m *Domain) Match(domain string) bool {
	if domain == "" {
		return false
	}

	if m.snames[domain] {
		return true
	}

	if len(m.mnames) == 0 {
		return false
	}

	// shrink to longest suffix, used to search in map
	dot := len(domain)
	for n := m.maxLabels; n > 0 && dot > 0; n-- {
		dot = strings.LastIndexByte(domain[:dot], '.')
	}
	domain = domain[dot+1:]

	// find matching suffix
	for len(domain) > 0 {
		if _, ok := m.mnames[domain]; ok {
			return true
		}

		// remove first subdomain and check if the
		// rest of domain is in map, for example:
		// a.b.c becomes b.c and is checked in blacklist map.
		dot := strings.IndexByte(domain, '.')
		if dot < 0 {
			return false
		}
		domain = domain[dot+1:]
	}

	return false
}
