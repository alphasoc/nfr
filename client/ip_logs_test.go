package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIps(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkMethodAndPath(t, r, http.MethodPost, "/logs/ip")
		json.NewEncoder(w).Encode(&IPResponse{})
	}))
	defer ts.Close()

	if _, err := New(ts.URL, "test-key").Ips(&IPRequest{Entries: []*IPEntry{{}, {}, {}}}); err != nil {
		t.Fatal(err)
	}
}

func TestIpsFail(t *testing.T) {
	if _, err := New(internalServerErrorServer.URL, "test-key").Ips(nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestIpsNoKey(t *testing.T) {
	if _, err := New("", "").Ips(nil); err != ErrNoAPIKey {
		t.Fatalf("expected error %s", ErrNoAPIKey)
	}
}

func TestIpsInvalidJSON(t *testing.T) {
	if _, err := New(noopServer.URL, "test-key").Ips(nil); err == nil {
		t.Fatal("expected error")
	}
}
