package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestQueries(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkMethodAndPath(t, r, http.MethodPost, "/queries")
		json.NewEncoder(w).Encode(&QueriesResponse{})
	}))
	defer ts.Close()

	if _, err := NewClient(ts.URL, "test-key").Queries(&QueriesRequest{}); err != nil {
		t.Fatal(err)
	}
}

func TestQueriesFail(t *testing.T) {
	if _, err := NewClient(internalServerErrorServer.URL, "test-key").Queries(nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestQueriesNoKey(t *testing.T) {
	if _, err := NewClient("", "").Queries(nil); err != ErrNoAPIKey {
		t.Fatalf("expected error %s", ErrNoAPIKey)
	}
}

func TestQueriesInvalidJSON(t *testing.T) {
	if _, err := NewClient(noopServer.URL, "test-key").Queries(nil); err == nil {
		t.Fatal("expected error")
	}
}
