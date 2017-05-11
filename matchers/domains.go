package matchers

import (
	"fmt"
	"strings"

	"github.com/alphasoc/namescore/utils"
)

type Domain struct {
	snames    map[string]bool // strict domain names
	mnames    map[string]bool // multimatch domain names
	maxLabels int             // maxLabels is max count of '.' char in multimatch domains map
}

func NewDomain(domains []string) (*Domain, error) {
	d := &Domain{
		snames: make(map[string]bool),
		mnames: make(map[string]bool),
	}
	return d, d.add(domains)
}

func (m *Domain) add(domains []string) error {
	for _, domain := range domains {
		if !utils.IsDomainName(domain) {
			// Do not add invalid domains
			return fmt.Errorf("%s is not valid domain name", domain)
		}

		if !strings.HasPrefix(domain, "*") {
			domain = strings.Trim(domain, ".")
			m.snames[domain] = true
			continue
		}

		domain = strings.TrimPrefix(domain, "*")
		domain = strings.Trim(domain, ".")
		m.mnames[domain] = true

		if labels := strings.Count(domain, ".") + 1; labels > m.maxLabels {
			m.maxLabels = labels
		}
	}
	return nil
}

// Match returns the longest matching suffix.
// If nothing matches empty string is returned.
func (m *Domain) Match(name string) bool {
	if name == "" {
		return false
	}

	if m.snames[name] {
		return true
	}

	// shrink to longest suffix
	dot := len(name)
	for n := m.maxLabels; n > 0 && dot > 0; n-- {
		dot = strings.LastIndexByte(name[:dot], '.')
	}
	name = name[dot+1:]

	// Find matching suffix
	for len(name) > 0 {
		if _, ok := m.mnames[name]; ok {
			return true
		}
		dot := strings.IndexByte(name, '.')
		if dot < 0 {
			return false
		}
		name = name[dot+1:]
	}

	return false
}
