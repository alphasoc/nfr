package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAccountStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkMethodAndPath(t, r, http.MethodGet, "/account/status")
		json.NewEncoder(w).Encode(&AccountStatusResponse{})
	}))
	defer ts.Close()
	_, err := New(ts.URL, "test-key").AccountStatus()
	require.NoError(t, err)
}

func TestAccountStatusFail(t *testing.T) {
	_, err := New(internalServerErrorServer.URL, "test-key").AccountStatus()
	require.Error(t, err)
}

func TestAccountStatusNoKey(t *testing.T) {
	_, err := New("", "").AccountStatus()
	require.Error(t, err)
}

func TestAccountStatusInvalidJSON(t *testing.T) {
	_, err := New(noopServer.URL, "test-key").AccountStatus()
	require.Error(t, err)
}
