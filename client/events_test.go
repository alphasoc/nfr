package client

import (
	"encoding/json"
	"testing"
	"net/http"
	"net/http/httptest"
)

func TestEvents(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkMethodAndPath(t, r, http.MethodGet, "/events")
                json.NewEncoder(w).Encode(&EventsResponse{})
	}))
	defer ts.Close()

	if _, err := newClientWithKey(t, ts.URL).Events(""); err != nil {
		t.Fatal(err)
	}
}

func TestEventsFollow(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkMethodAndPath(t, r, http.MethodGet, "/events")
		if r.URL.RawQuery != "follow=1" {
			t.Fatalf("invalid query %s", r.URL.Path)
			return
		}
                json.NewEncoder(w).Encode(&EventsResponse{})
	}))
	defer ts.Close()

	if _, err := newClientWithKey(t, ts.URL).Events("1"); err != nil {
		t.Fatal(err)
	}
}

func TestEventsFail(t *testing.T) {
        if _, err := newClientWithKey(t, internalServerErrorServer.URL).Events(""); err == nil {
                t.Fatal("expected error")
        }
}

func TestEventsNoKey(t *testing.T) {
        if _, err := newClient(t, "").Events(""); err != ErrNoAPIKey {
                t.Fatalf("expected error %s", ErrNoAPIKey)
        }
}

func TestEventsInvalidJSON(t *testing.T) {
        if _, err := newClientWithKey(t, noopServer.URL).Events(""); err == nil {
                t.Fatal("expected error")
        }
}
