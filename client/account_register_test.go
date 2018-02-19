package client

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAccountRegister(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkMethodAndPath(t, r, http.MethodPost, "/account/register")
	}))
	defer ts.Close()

	var accountRegisterRequest = &AccountRegisterRequest{}
	accountRegisterRequest.Details.Name = "test-name"
	accountRegisterRequest.Details.Email = "test-email@alphasoc.com"

	require.NoError(t, New(ts.URL, "test-key").AccountRegister(accountRegisterRequest))
}

func TestAccountRegisterFail(t *testing.T) {
	var accountRegisterRequest = &AccountRegisterRequest{}

	require.Error(t, New(noopServer.URL, "test-key").AccountRegister(accountRegisterRequest))

	accountRegisterRequest.Details.Name = "test-name"
	require.Error(t, New(noopServer.URL, "test-key").AccountRegister(accountRegisterRequest))

	accountRegisterRequest.Details.Email = "test-emailalphasoc.com"
	require.Error(t, New(noopServer.URL, "test-key").AccountRegister(accountRegisterRequest))
}
