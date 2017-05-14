package matchers

import "testing"

func TestDomain(t *testing.T) {
	domainsTests := []struct {
		name     string
		domains  []string
		cases    []string
		expected []bool
	}{
		{
			"empty domain",
			[]string{},
			[]string{""},
			[]bool{false},
		},
		{
			"strict domain",
			[]string{"a.b"},
			[]string{"a.b", "b"},
			[]bool{true, false},
		},
		{
			"multimatch domains",
			[]string{"*.a"},
			[]string{"a", "b.a", "c.b.a", "a.b"},
			[]bool{true, true, true, false},
		},
		{
			"strict and multimatch domains",
			[]string{"*.b.a", "*.a", "c"},
			[]string{"c.b.a", "c.a", "b.a", "c", "d.c.d."},
			[]bool{true, true, true, true, false},
		},
	}

	for _, tt := range domainsTests {
		matcher, err := NewDomain(tt.domains)
		if err != nil {
			t.Fatalf("%s %s", tt.name, err)
		}
		for i := range tt.cases {
			if matcher.Match(tt.cases[i]) != tt.expected[i] {
				t.Fatalf("test %s - match(%s) = %t; want %t", tt.name, tt.cases[i], !tt.expected[i], tt.expected[i])
			}

		}
	}
}

func TestInvalidDomain(t *testing.T) {
	if _, err := NewDomain([]string{"$invalid_domain$"}); err == nil {
		t.Fatalf("got %s; expected <nil>", err)
	}
}
