package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEventsDNS(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkMethodAndPath(t, r, http.MethodPost, "/events/dns")
		json.NewEncoder(w).Encode(&EventsDNSResponse{})
	}))
	defer ts.Close()

	_, err := New(ts.URL, "test-key").EventsDNS(&EventsDNSRequest{Entries: []*DNSEntry{{}, {}}})
	require.NoError(t, err)
}

func TestEventsDNSFail(t *testing.T) {
	_, err := New(internalServerErrorServer.URL, "test-key").EventsDNS(nil)
	require.Error(t, err)
}

func TestEventsDNSNoKey(t *testing.T) {
	_, err := New("", "").EventsDNS(nil)
	require.Equal(t, ErrNoAPIKey, err)
}

func TestEventsDNSInvalidJSON(t *testing.T) {
	_, err := New(noopServer.URL, "test-key").EventsDNS(nil)
	require.Error(t, err)
}
