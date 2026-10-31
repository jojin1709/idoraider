package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jojin1709/idoraider/internal/engine"
)

func TestWriteJSON(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "report.json")

	sum := engine.Summary{
		Target:        "https://api.example.com",
		TotalTested:   2,
		Vulnerable:    1,
		Critical:      1,
		High:          0,
		Medium:        0,
		Low:           0,
		NotVulnerable: 1,
		Errors:        0,
		Duration:      150 * time.Millisecond,
		Results: []engine.Result{
			{
				Template:    "test.yaml",
				Endpoint:    "https://api.example.com/api/users/1",
				Status:      engine.StatusVulnerable,
				Severity:    "CRITICAL",
				StatusCode:  200,
				Mode:        "single-token",
				Description: "User IDOR",
				Detail:      "Accessible",
			},
			{
				Template:    "test.yaml",
				Endpoint:    "https://api.example.com/api/users/2",
				Status:      engine.StatusNotVulnerable,
				Severity:    "CRITICAL",
				StatusCode:  404,
				Mode:        "single-token",
				Description: "User IDOR",
				Detail:      "Not found",
			},
		},
	}

	if err := WriteJSON(outPath, sum); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed reading output report: %v", err)
	}

	var parsed jsonReport
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed parsing report JSON: %v", err)
	}

	if parsed.Target != "https://api.example.com" {
		t.Errorf("expected Target 'https://api.example.com', got %q", parsed.Target)
	}
	if parsed.TotalTested != 2 || parsed.Vulnerable != 1 || parsed.Critical != 1 {
		t.Errorf("summary counts mismatch: %+v", parsed)
	}
	if len(parsed.Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(parsed.Results))
	}
}

func TestWriteMarkdown(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "report.md")

	sum := engine.Summary{
		Target:        "https://api.example.com",
		TotalTested:   1,
		Vulnerable:    1,
		Critical:      1,
		Duration:      50 * time.Millisecond,
		Results: []engine.Result{
			{
				Template:    "test.yaml",
				Endpoint:    "https://api.example.com/api/users/1",
				Status:      engine.StatusVulnerable,
				Severity:    "CRITICAL",
				StatusCode:  200,
				Mode:        "single-token",
				Description: "User IDOR",
				Detail:      "Accessible",
			},
		},
	}

	if err := WriteMarkdown(outPath, sum); err != nil {
		t.Fatalf("WriteMarkdown failed: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed reading output report: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "# IDORaider Scan Report") {
		t.Errorf("missing title in markdown report")
	}
	if !strings.Contains(content, "**VULNERABLE**") {
		t.Errorf("missing VULNERABLE status in markdown report")
	}
	if !strings.Contains(content, "https://api.example.com/api/users/1") {
		t.Errorf("missing endpoint in markdown report")
	}
}
