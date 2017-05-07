package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAccountStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkMethodAndPath(t, r, http.MethodGet, "/account/status")
		json.NewEncoder(w).Encode(&AccountStatusResponse{})
	}))
	defer ts.Close()

	if _, err := NewClient(ts.URL, "test-key").AccountStatus(); err != nil {
		t.Fatal(err)
	}
}

func TestAccountStatusFail(t *testing.T) {
	if _, err := NewClient(internalServerErrorServer.URL, "test-key").AccountStatus(); err == nil {
		t.Fatal("expected error")
	}
}

func TestAccountStatusNoKey(t *testing.T) {
	if _, err := NewClient("", "").AccountStatus(); err != ErrNoAPIKey {
		t.Fatalf("expected error %s", ErrNoAPIKey)
	}
}

func TestAccountStatusInvalidJSON(t *testing.T) {
	if _, err := NewClient(noopServer.URL, "test-key").AccountStatus(); err == nil {
		t.Fatal("expected error")
	}
}
