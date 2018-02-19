package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAlerts(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkMethodAndPath(t, r, http.MethodGet, "/alerts")
		json.NewEncoder(w).Encode(&AlertsResponse{})
	}))
	defer ts.Close()

	_, err := New(ts.URL, "test-key").Alerts("")
	require.NoError(t, err)
}

func TestAlertsFollow(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "follow=1" {
			t.Fatalf("invalid query %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(&AlertsResponse{})
	}))
	defer ts.Close()

	_, err := New(ts.URL, "test-key").Alerts("1")
	require.NoError(t, err)
}

func TestAlertsFail(t *testing.T) {
	_, err := New(internalServerErrorServer.URL, "test-key").Alerts("")
	require.Error(t, err)
}

func TestAlertsNoKey(t *testing.T) {
	_, err := New("", "").Alerts("")
	require.Equal(t, ErrNoAPIKey, err)
}

func TestAlertsInvalidJSON(t *testing.T) {
	_, err := New(noopServer.URL, "test-key").Alerts("")
	require.Error(t, err)
}
