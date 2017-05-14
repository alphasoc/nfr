package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestKeyRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkMethodAndPath(t, r, http.MethodPost, "/key/request")
		json.NewEncoder(w).Encode(&KeyRequestResponse{})
	}))
	defer ts.Close()

	if _, err := New(ts.URL, "").KeyRequest(); err != nil {
		t.Fatal(err)
	}
}

func TestKeyRequestFail(t *testing.T) {
	if _, err := New(internalServerErrorServer.URL, "").KeyRequest(); err == nil {
		t.Fatal("expected error")
	}
}

func TestKeyRequestInvalidJSON(t *testing.T) {
	if _, err := New(noopServer.URL, "").KeyRequest(); err == nil {
		t.Fatal("expected error")
	}
}
