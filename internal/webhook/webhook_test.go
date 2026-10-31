package webhook

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jojin1709/idoraider/internal/engine"
)

func TestSend_Generic(t *testing.T) {
	received := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = true
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	sum := engine.Summary{
		Target:      "https://target.com",
		TotalTested: 10,
		Vulnerable:  1,
		Duration:    time.Second,
	}

	err := Send(context.Background(), ts.URL, sum)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !received {
		t.Errorf("expected webhook to be received by test server")
	}
}

func TestSend_Empty(t *testing.T) {
	err := Send(context.Background(), "", engine.Summary{})
	if err != nil {
		t.Errorf("expected nil error for empty webhook url, got: %v", err)
	}
}
