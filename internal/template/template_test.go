package template

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFile(t *testing.T) {
	content := `id: test-tmpl
name: Test Template
severity: high
description: A test description
method: GET
path: /api/v1/test/{id}
headers:
  Authorization: Bearer {token}
  X-Custom: test-val
ids:
  - 10
  - 20
match_status:
  - 200
  - 201
match_words:
  - success
  - verified
`
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.yaml")
	if err := os.WriteFile(filePath, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	tmpl, err := LoadFile(filePath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tmpl.ID != "test-tmpl" {
		t.Errorf("expected ID 'test-tmpl', got %q", tmpl.ID)
	}
	if tmpl.Severity != "HIGH" {
		t.Errorf("expected Severity 'HIGH', got %q", tmpl.Severity)
	}
	if tmpl.Path != "/api/v1/test/{id}" {
		t.Errorf("expected Path '/api/v1/test/{id}', got %q", tmpl.Path)
	}
	if len(tmpl.IDs) != 2 || tmpl.IDs[0] != "10" || tmpl.IDs[1] != "20" {
		t.Errorf("expected IDs [10, 20], got %v", tmpl.IDs)
	}
	if len(tmpl.MatchStatus) != 2 || tmpl.MatchStatus[0] != 200 || tmpl.MatchStatus[1] != 201 {
		t.Errorf("expected MatchStatus [200, 201], got %v", tmpl.MatchStatus)
	}
	if len(tmpl.MatchWords) != 2 || tmpl.MatchWords[0] != "success" || tmpl.MatchWords[1] != "verified" {
		t.Errorf("expected MatchWords [success, verified], got %v", tmpl.MatchWords)
	}
	if tmpl.Headers["X-Custom"] != "test-val" {
		t.Errorf("expected Header X-Custom=test-val, got %q", tmpl.Headers["X-Custom"])
	}
}

func TestLoadFile_Defaults(t *testing.T) {
	content := `path: /api/v1/resource/{id}
`
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "minimal.yaml")
	if err := os.WriteFile(filePath, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	tmpl, err := LoadFile(filePath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tmpl.ID != "minimal" {
		t.Errorf("expected default ID 'minimal', got %q", tmpl.ID)
	}
	if tmpl.Severity != SeverityMedium {
		t.Errorf("expected default severity 'MEDIUM', got %q", tmpl.Severity)
	}
	if tmpl.Method != "GET" {
		t.Errorf("expected default method 'GET', got %q", tmpl.Method)
	}
	if len(tmpl.IDs) != 1 || tmpl.IDs[0] != "1" {
		t.Errorf("expected default IDs [1], got %v", tmpl.IDs)
	}
	if len(tmpl.MatchStatus) != 1 || tmpl.MatchStatus[0] != 200 {
		t.Errorf("expected default MatchStatus [200], got %v", tmpl.MatchStatus)
	}
}

func TestLoadFile_MissingPath(t *testing.T) {
	content := `id: no-path
name: Missing Path
`
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "no-path.yaml")
	if err := os.WriteFile(filePath, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	_, err := LoadFile(filePath)
	if err == nil {
		t.Fatalf("expected error for missing path, got nil")
	}
}

func TestLoadDir(t *testing.T) {
	tmpDir := t.TempDir()
	t1 := "id: b-template\npath: /b/{id}\n"
	t2 := "id: a-template\npath: /a/{id}\n"

	if err := os.WriteFile(filepath.Join(tmpDir, "b.yaml"), []byte(t1), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "a.yaml"), []byte(t2), 0o600); err != nil {
		t.Fatal(err)
	}

	list, err := LoadDir(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 templates, got %d", len(list))
	}
	if list[0].ID != "a-template" || list[1].ID != "b-template" {
		t.Errorf("expected sorted templates [a-template, b-template], got [%s, %s]", list[0].ID, list[1].ID)
	}
}

