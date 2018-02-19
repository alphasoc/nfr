package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEventsIP(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkMethodAndPath(t, r, http.MethodPost, "/events/ip")
		json.NewEncoder(w).Encode(&EventsIPResponse{})
	}))
	defer ts.Close()

	_, err := New(ts.URL, "test-key").EventsIP(&EventsIPRequest{})
	require.NoError(t, err)
}

func TestEventsIPFail(t *testing.T) {
	_, err := New(internalServerErrorServer.URL, "test-key").EventsIP(nil)
	require.Error(t, err)
}

func TestEventsIPNoKey(t *testing.T) {
	_, err := New("", "").EventsIP(nil)
	require.Error(t, err)
}

func TestEventsIPInvalidJSON(t *testing.T) {
	_, err := New(noopServer.URL, "test-key").EventsIP(nil)
	require.Error(t, err)
}
