package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jojin1709/idoraider/internal/template"
)

func TestRun_SingleToken_Vulnerable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer tokenA" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"user_id": 1, "email": "test@example.com"}`))
	}))
	defer ts.Close()

	tmpl := &template.Template{
		ID:          "test-profile",
		Path:        "/api/users/{id}",
		Method:      "GET",
		IDs:         []string{"1", "2"},
		MatchStatus: []int{200},
		MatchWords:  []string{"email"},
		Severity:    template.SeverityHigh,
	}

	cfg := Config{
		TargetBaseURL: ts.URL,
		PrimaryToken:  "tokenA",
		Concurrency:   2,
		Timeout:       2 * time.Second,
	}

	sum := Run(context.Background(), cfg, []*template.Template{tmpl}, nil)

	if sum.TotalTested != 2 {
		t.Fatalf("expected 2 tested, got %d", sum.TotalTested)
	}
	if sum.Vulnerable != 2 {
		t.Errorf("expected 2 vulnerable, got %d", sum.Vulnerable)
	}
	if sum.High != 2 {
		t.Errorf("expected 2 high severity findings, got %d", sum.High)
	}
}

func TestRun_DualToken_AccessControl(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "Bearer ownerToken" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id": 1, "data": "secret"}`))
			return
		}
		// Secondary token correctly gets 403 Forbidden
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer ts.Close()

	tmpl := &template.Template{
		ID:          "test-sec",
		Path:        "/api/items/{id}",
		Method:      "GET",
		IDs:         []string{"1"},
		MatchStatus: []int{200},
		MatchWords:  []string{"secret"},
		Severity:    template.SeverityHigh,
	}

	cfg := Config{
		TargetBaseURL:  ts.URL,
		PrimaryToken:   "ownerToken",
		SecondaryToken: "otherToken",
		Concurrency:    1,
		Timeout:        2 * time.Second,
	}

	sum := Run(context.Background(), cfg, []*template.Template{tmpl}, nil)

	if sum.TotalTested != 1 {
		t.Fatalf("expected 1 tested, got %d", sum.TotalTested)
	}
	if sum.Vulnerable != 0 {
		t.Errorf("expected 0 vulnerable, got %d", sum.Vulnerable)
	}
	if sum.NotVulnerable != 1 {
		t.Errorf("expected 1 not vulnerable, got %d", sum.NotVulnerable)
	}
}

func TestRun_DualToken_BOLAFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Both tokens get access -> BOLA!
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id": 1, "data": "secret"}`))
	}))
	defer ts.Close()

	tmpl := &template.Template{
		ID:          "test-bola",
		Path:        "/api/items/{id}",
		Method:      "GET",
		IDs:         []string{"1"},
		MatchStatus: []int{200},
		MatchWords:  []string{"secret"},
		Severity:    template.SeverityCritical,
	}

	cfg := Config{
		TargetBaseURL:  ts.URL,
		PrimaryToken:   "ownerToken",
		SecondaryToken: "otherToken",
		Concurrency:    1,
		Timeout:        2 * time.Second,
	}

	sum := Run(context.Background(), cfg, []*template.Template{tmpl}, nil)

	if sum.TotalTested != 1 {
		t.Fatalf("expected 1 tested, got %d", sum.TotalTested)
	}
	if sum.Vulnerable != 1 {
		t.Errorf("expected 1 vulnerable, got %d", sum.Vulnerable)
	}
	if sum.Critical != 1 {
		t.Errorf("expected 1 critical, got %d", sum.Critical)
	}
}

func TestRun_CustomIDs(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data": "found"}`))
	}))
	defer ts.Close()

	tmpl := &template.Template{
		ID:          "test-tmpl",
		Path:        "/api/resource/{id}",
		Method:      "GET",
		IDs:         []string{"1", "2"}, // would be 2 probes
		MatchStatus: []int{200},
	}

	cfg := Config{
		TargetBaseURL: ts.URL,
		CustomIDs:     []string{"uuid-1", "uuid-2", "uuid-3"}, // override with 3 probes
		Concurrency:   1,
		Timeout:       2 * time.Second,
	}

	sum := Run(context.Background(), cfg, []*template.Template{tmpl}, nil)

	if sum.TotalTested != 3 {
		t.Errorf("expected 3 probes from CustomIDs override, got %d", sum.TotalTested)
	}
}

func TestRun_RedirectControl(t *testing.T) {
	// Server redirects /api/target/1 to /login (which returns 200)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<html>login page</html>`))
			return
		}
		http.Redirect(w, r, "/login", http.StatusFound)
	}))
	defer ts.Close()

	tmpl := &template.Template{
		ID:          "test-redirect",
		Path:        "/api/target/{id}",
		Method:      "GET",
		IDs:         []string{"1"},
		MatchStatus: []int{200},
	}

	// 1. With FollowRedirects = false (default): does NOT follow redirect, gets 302, NOT vulnerable
	cfgNoFollow := Config{
		TargetBaseURL:   ts.URL,
		FollowRedirects: false,
		Concurrency:     1,
		Timeout:         2 * time.Second,
	}
	sumNoFollow := Run(context.Background(), cfgNoFollow, []*template.Template{tmpl}, nil)
	if sumNoFollow.Vulnerable != 0 {
		t.Errorf("expected 0 vulnerable with default redirect suppression, got %d", sumNoFollow.Vulnerable)
	}

	// 2. With FollowRedirects = true: follows to /login which returns 200, triggers match
	cfgFollow := Config{
		TargetBaseURL:   ts.URL,
		FollowRedirects: true,
		Concurrency:     1,
		Timeout:         2 * time.Second,
	}
	sumFollow := Run(context.Background(), cfgFollow, []*template.Template{tmpl}, nil)
	if sumFollow.Vulnerable != 1 {
		t.Errorf("expected 1 vulnerable when following redirects, got %d", sumFollow.Vulnerable)
	}
}
