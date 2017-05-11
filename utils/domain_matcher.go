package utils

import "strings"

type DomainMatcher struct {
	snames    map[string]bool // strict domain names
	mnames    map[string]bool // multimatch domain names
	maxLabels int             // maxLabels is max count of '.' char in multimatch domains map
}

func NewDomainMatcher() *DomainMatcher {
	return &DomainMatcher{
		snames: make(map[string]bool),
		mnames: make(map[string]bool),
	}
}

func (m *DomainMatcher) Add(name string) {
	if !IsDomainName(name) {
		// Do not add invalid domains
		return
	}

	if !strings.HasPrefix(name, "*") {
		name = strings.Trim(name, ".")
		m.snames[name] = true
		return
	}

	name = strings.TrimPrefix(name, "*")
	name = strings.Trim(name, ".")
	m.mnames[name] = true

	if labels := strings.Count(name, ".") + 1; labels > m.maxLabels {
		m.maxLabels = labels
	}
}

// Match returns the longest matching suffix.
// If nothing matches empty string is returned.
func (m *DomainMatcher) Match(name string) bool {
	if name == "" {
		return false
	}

	if m.snames[name] {
		return true
	}

	// Shrink to longest suffix
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
