package asoc

import "testing"
import "strings"
import "os"

func TestUname(t *testing.T) {
	u := uname()
	if u == "" {
		t.Errorf("uname(): returned empty string")
	}

	if strings.Contains(u, "\n") {
		t.Errorf("uname()=%q: string contains newline", u)
	}

	if !strings.Contains(u, "Linux") {
		t.Errorf("uname()=%q: expected to contain \"Linux\"", u)
	}

	if hostname, err := os.Hostname(); err != nil {
		if !strings.Contains(u, hostname) {
			t.Errorf("uname()=%q: expected to contain %q", u, hostname)
		}
	}
}
