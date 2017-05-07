package client

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestKeyReset(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkMethodAndPath(t, r, http.MethodPost, "/key/reset")
	}))
	defer ts.Close()

	if err := NewClient(ts.URL, "").KeyReset(&KeyResetRequest{}); err != nil {
		t.Fatal(err)
	}
}

func TestResetFail(t *testing.T) {
	if err := NewClient(internalServerErrorServer.URL, "").KeyReset(nil); err == nil {
		t.Fatal("expected error")
	}
}
