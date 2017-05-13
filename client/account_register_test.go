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

	var accountRegisterRequest = &AccountRegisterRequest{}
	accountRegisterRequest.Details.Name = "test-name"
	accountRegisterRequest.Details.Email = "test-email@alphasoc.com"

	if err := New(ts.URL, "test-key").AccountRegister(accountRegisterRequest); err != nil {
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

	var accountRegisterRequest = &AccountRegisterRequest{}
	accountRegisterRequest.Details.Name = "test-name"
	accountRegisterRequest.Details.Email = "test-email@alphasoc.com"

	if err := New(ts.URL, "test-key").AccountRegister(accountRegisterRequest); err == nil {
		t.Fatal("expected error")
	}
}
