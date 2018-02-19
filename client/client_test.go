package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// noop server and handler for testing
var (
	noopServer  *httptest.Server
	noopHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	internalServerErrorHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(&ErrorResponse{"no key"})
	})
	internalServerErrorServer *httptest.Server
)

func checkMethodAndPath(t *testing.T, r *http.Request, method string, path string) {
	require.Equal(t, method, r.Method, "method not found")
	require.Equal(t, "/"+DefaultVersion+path, r.URL.Path, "invalid url path")
}

func TestMain(m *testing.M) {
	noopServer = httptest.NewServer(noopHandler)
	internalServerErrorServer = httptest.NewServer(internalServerErrorHandler)

	defer noopServer.Close()
	defer internalServerErrorServer.Close()
	os.Exit(m.Run())
}

func TestCheckKey(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkMethodAndPath(t, r, http.MethodGet, "/account/status")
		json.NewEncoder(w).Encode(&AccountStatusResponse{})
	}))
	defer ts.Close()

	require.NoError(t, New(ts.URL, "test-key").CheckKey())
}

func TestSetKey(t *testing.T) {
	c := New("", "")
	c.SetKey("test-api-key")
	require.Equal(t, "test-api-key", c.key)
}

func TestBasicAuth(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if username, password, ok := r.BasicAuth(); !ok || username != "test-key" || password != "" {
			t.Fatalf("invalid basic auth")
		}
	}))
	defer ts.Close()

	_, err := New(ts.URL, "test-key").post(context.Background(), "/", nil, nil)
	require.NoError(t, err)
}

func TestUserAgent(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, defaultUserAgent, r.UserAgent(), "invalid user agent")
	}))
	defer ts.Close()

	_, err := New(ts.URL, "test-key").get(context.Background(), "/", nil)
	require.NoError(t, err)
}

func TestResponseStatusNotOk(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	_, err := New(ts.URL, "").get(context.Background(), "/", nil)
	require.Error(t, err)
}

func TestResponseErrorMessage(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(&ErrorResponse{Message: "test-error"})
	}))
	defer ts.Close()

	_, err := New(ts.URL, "").get(context.Background(), "/", nil)
	require.Error(t, err)
	require.Equal(t, err.Error(), "test-error")
}

func TestDoInvalidMethod(t *testing.T) {
	if _, err := New("", "").do(context.Background(), "/", "/", nil, nil, nil); err == nil {
		t.Fatal("exptected invalid method error")
	}
}

func TestPostMarshalError(t *testing.T) {
	_, err := New(noopServer.URL, "").post(context.Background(), "/", nil, func() {})
	require.Error(t, err, "exptected json marshal error")
}

func TestDoInvalidRequest(t *testing.T) {
	_, err := New("", "").do(context.Background(), "noop", "/", nil, nil, nil)
	require.Error(t, err, "exptected invalid method error")
}
