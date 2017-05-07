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

	if _, err := newClientWithKey(t, ts.URL).Queries(&QueriesRequest{}); err != nil {
		t.Fatal(err)
	}
}

func TestQueriesFail(t *testing.T) {
	if _, err := newClientWithKey(t, internalServerErrorServer.URL).Queries(nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestQueriesNoKey(t *testing.T) {
	if _, err := newClient(t, "").Queries(nil); err != ErrNoAPIKey {
		t.Fatalf("expected error %s", ErrNoAPIKey)
	}
}

func TestQueriesInvalidJSON(t *testing.T) {
	if _, err := newClientWithKey(t, noopServer.URL).Queries(nil); err == nil {
		t.Fatal("expected error")
	}
}
