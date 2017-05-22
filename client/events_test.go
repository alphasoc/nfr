package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEvents(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkMethodAndPath(t, r, http.MethodGet, "/events")
		json.NewEncoder(w).Encode(&EventsResponse{})
	}))
	defer ts.Close()

	if _, err := New(ts.URL, "test-key").Events(""); err != nil {
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

	if _, err := New(ts.URL, "test-key").Events("1"); err != nil {
		t.Fatal(err)
	}
}

func TestEventsFail(t *testing.T) {
	if _, err := New(internalServerErrorServer.URL, "test-key").Events(""); err == nil {
		t.Fatal("expected error")
	}
}

func TestEventsNoKey(t *testing.T) {
	if _, err := New("", "").Events(""); err != ErrNoAPIKey {
		t.Fatalf("expected error %s", ErrNoAPIKey)
	}
}

func TestEventsInvalidJSON(t *testing.T) {
	if _, err := New(noopServer.URL, "test-key").Events(""); err == nil {
		t.Fatal("expected error")
	}
}
