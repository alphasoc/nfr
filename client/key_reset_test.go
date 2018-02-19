package client

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKeyReset(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkMethodAndPath(t, r, http.MethodPost, "/key/reset")
	}))
	defer ts.Close()

	require.NoError(t, New(ts.URL, "").KeyReset(&KeyResetRequest{}))
}

func TestResetFail(t *testing.T) {
	require.Error(t, New(internalServerErrorServer.URL, "").KeyReset(nil))
}
