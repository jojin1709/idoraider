package openapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_LocalFile(t *testing.T) {
	schema := `{
		"openapi": "3.0.0",
		"paths": {
			"/api/v1/users/{userId}": {
				"get": { "summary": "Get user" },
				"delete": { "summary": "Delete user" }
			},
			"/api/v1/health": {
				"get": { "summary": "Health check" }
			}
		}
	}`

	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "openapi.json")
	if err := os.WriteFile(filePath, []byte(schema), 0o600); err != nil {
		t.Fatal(err)
	}

	templates, err := Load(context.Background(), filePath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should extract only the parameterized path (/api/v1/users/{id}) for GET and DELETE
	if len(templates) != 2 {
		t.Fatalf("expected 2 templates, got %d", len(templates))
	}

	for _, tmpl := range templates {
		if tmpl.Path != "/api/v1/users/{id}" {
			t.Errorf("expected normalized path '/api/v1/users/{id}', got %q", tmpl.Path)
		}
	}
}

func TestLoad_RemoteURL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"swagger": "2.0",
			"paths": {
				"/orders/{orderId}": {
					"get": {}
				}
			}
		}`))
	}))
	defer ts.Close()

	templates, err := Load(context.Background(), ts.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(templates) != 1 {
		t.Fatalf("expected 1 template from remote url, got %d", len(templates))
	}
	if templates[0].Path != "/orders/{id}" {
		t.Errorf("expected '/orders/{id}', got %q", templates[0].Path)
	}
}
