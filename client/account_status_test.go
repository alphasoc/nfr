package client

import (
	"encoding/json"
	"testing"
	"net/http"
	"net/http/httptest"
)

func TestAccountStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkMethodAndPath(t, r, http.MethodGet, "/account/status")
		json.NewEncoder(w).Encode(&AccountStatusResponse{})
	}))
	defer ts.Close()

	if _, err := newClientWithKey(t, ts.URL).AccountStatus(); err != nil {
		t.Fatal(err)
	}
}

func TestAccountStatusFail(t *testing.T) {
	if _, err := newClientWithKey(t, internalServerErrorServer.URL).AccountStatus(); err == nil {
		t.Fatal("expected error")
	}
}

func TestAccountStatusNoKey(t *testing.T) {
	if _, err := newClient(t, "").AccountStatus(); err != ErrNoAPIKey {
		t.Fatalf("expected error %s", ErrNoAPIKey)
	}
}

func TestAccountStatusInvalidJSON(t *testing.T) {
	if _, err := newClientWithKey(t, noopServer.URL).AccountStatus(); err == nil {
		t.Fatal("expected error")
	}
}
