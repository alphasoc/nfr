package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKeyRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkMethodAndPath(t, r, http.MethodPost, "/key/request")
		json.NewEncoder(w).Encode(&KeyRequestResponse{})
	}))
	defer ts.Close()

	_, err := New(ts.URL, "").KeyRequest()
	require.NoError(t, err)
}

func TestKeyRequestFail(t *testing.T) {
	_, err := New(internalServerErrorServer.URL, "").KeyRequest()
	require.Error(t, err)
}

func TestKeyRequestInvalidJSON(t *testing.T) {
	_, err := New(noopServer.URL, "").KeyRequest()
	require.Error(t, err)
}
