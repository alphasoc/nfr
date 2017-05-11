package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAccountRegister(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkMethodAndPath(t, r, http.MethodPost, "/account/register")
	}))
	defer ts.Close()

	if err := New(ts.URL, "test-key").AccountRegister(&AccountRegisterRequest{}); err != nil {
		t.Fatal(err)
	}
}

func TestAccountRegisterFail(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkMethodAndPath(t, r, http.MethodPost, "/account/register")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(&ErrorResponse{"invalid email"})
	}))
	defer ts.Close()

	if err := New(ts.URL, "test-key").AccountRegister(&AccountRegisterRequest{}); err == nil {
		t.Fatal("expected error")
	}
}
