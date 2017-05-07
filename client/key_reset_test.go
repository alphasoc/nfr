package client

import (
	"testing"
	"net/http"
	"net/http/httptest"
)

func TestKeyReset(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkMethodAndPath(t, r, http.MethodPost, "/key/reset")
	}))
	defer ts.Close()

	if err := newClient(t, ts.URL).KeyReset(&KeyResetRequest{}); err != nil {
		t.Fatal(err)
	}
}

func TestResetFail(t *testing.T) {
	if err := newClientWithKey(t, internalServerErrorServer.URL).KeyReset(nil); err == nil {
		t.Fatal("expected error")
	}
}
