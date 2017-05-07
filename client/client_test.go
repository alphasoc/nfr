package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
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
	if r.Method != method {
		t.Fatalf("method %s not found", method)
		return
	}
	if r.URL.Path != "/"+DefaultVersion+path {
		t.Fatalf("invalid url path %s", r.URL.Path)
		return
	}
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

	if err := NewClient(ts.URL, "test-key").CheckKey(); err != nil {
		t.Fatal(err)
	}
}

func TestSetKey(t *testing.T) {
	c := NewClient("", "")
	if c.SetKey("test-api-key"); c.key != "test-api-key" {
		t.Fatalf("invalid key")
	}
}

func TestBasicAuth(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if username, password, ok := r.BasicAuth(); !ok || username != "test-key" || password != "" {
			t.Fatalf("invalid basic auth")
		}
	}))
	defer ts.Close()

	if _, err := NewClient(ts.URL, "test-key").post(context.Background(), "/", nil, nil); err != nil {
		t.Fatal(err)
	}
}

func TestUserAgent(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.UserAgent() != defaultUserAgent {
			t.Fatalf("invalid user agent")
		}
	}))
	defer ts.Close()

	if _, err := NewClient(ts.URL, "test-key").get(context.Background(), "/", nil); err != nil {
		t.Fatal(err)
	}
}

func TestResponseStatusNotOk(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	if _, err := NewClient(ts.URL, "").get(context.Background(), "/", nil); err == nil {
		t.Fatal("exptected error")
	}
}

func TestResponseErrorMessage(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(&ErrorResponse{Message: "test-error"})
	}))
	defer ts.Close()

	if _, err := NewClient(ts.URL, "").get(context.Background(), "/", nil); err == nil || err.Error() != "test-error" {
		t.Fatal("exptected error")
	}
}

func TestDoInvalidMethod(t *testing.T) {
	if _, err := NewClient("", "").do(context.Background(), "/", "/", nil, nil, nil); err == nil {
		t.Fatal("exptected invalid method error")
	}
}

func TestPostMarshalError(t *testing.T) {
	if _, err := NewClient(noopServer.URL, "").post(context.Background(), "/", nil, func() {}); err == nil {
		t.Fatal("exptected json marshal error")
	}
}

func TestDoInvalidRequest(t *testing.T) {
	if _, err := NewClient("", "").do(context.Background(), "noop", "/", nil, nil, nil); err == nil {
		t.Fatal("exptected invalid method error")
	}
}
