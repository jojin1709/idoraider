// Package report writes scan output to disk.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/jojin1709/idoraider/internal/engine"
)

type jsonResult struct {
	Template    string `json:"template"`
	Endpoint    string `json:"endpoint"`
	Status      string `json:"status"`
	Severity    string `json:"severity,omitempty"`
	StatusCode  int    `json:"status_code"`
	Mode        string `json:"mode"`
	Description string `json:"description,omitempty"`
	Detail      string `json:"detail,omitempty"`
	Error       string `json:"error,omitempty"`
}

type jsonReport struct {
	Target        string       `json:"target"`
	ScannedAt     string       `json:"scanned_at"`
	DurationMS    int64        `json:"duration_ms"`
	TotalTested   int          `json:"total_tested"`
	Vulnerable    int          `json:"vulnerable"`
	Critical      int          `json:"critical"`
	High          int          `json:"high"`
	Medium        int          `json:"medium"`
	Low           int          `json:"low"`
	NotVulnerable int          `json:"not_vulnerable"`
	Errors        int          `json:"errors"`
	Results       []jsonResult `json:"results"`
}

// WriteJSON serializes a scan summary to path.
func WriteJSON(path string, sum engine.Summary) error {
	rep := jsonReport{
		Target:        sum.Target,
		ScannedAt:     time.Now().Format(time.RFC3339),
		DurationMS:    sum.Duration.Milliseconds(),
		TotalTested:   sum.TotalTested,
		Vulnerable:    sum.Vulnerable,
		Critical:      sum.Critical,
		High:          sum.High,
		Medium:        sum.Medium,
		Low:           sum.Low,
		NotVulnerable: sum.NotVulnerable,
		Errors:        sum.Errors,
	}
	for _, r := range sum.Results {
		jr := jsonResult{
			Template:    r.Template,
			Endpoint:    r.Endpoint,
			Status:      r.Status,
			Severity:    r.Severity,
			StatusCode:  r.StatusCode,
			Mode:        r.Mode,
			Description: r.Description,
			Detail:      r.Detail,
		}
		if r.Err != nil {
			jr.Error = r.Err.Error()
		}
		rep.Results = append(rep.Results, jr)
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating report file: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

// WriteMarkdown writes a human-readable Markdown scan report to path.
func WriteMarkdown(path string, sum engine.Summary) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating markdown report file: %w", err)
	}
	defer f.Close()

	fmt.Fprintf(f, "# IDORaider Scan Report\n\n")
	fmt.Fprintf(f, "- **Target:** `%s`\n", sum.Target)
	fmt.Fprintf(f, "- **Date:** %s\n", time.Now().Format(time.RFC1123))
	fmt.Fprintf(f, "- **Duration:** %s\n", sum.Duration.Round(time.Millisecond))
	fmt.Fprintf(f, "- **Endpoints Tested:** %d\n", sum.TotalTested)
	fmt.Fprintf(f, "- **Vulnerabilities Found:** %d (Critical: %d, High: %d, Medium: %d, Low: %d)\n",
		sum.Vulnerable, sum.Critical, sum.High, sum.Medium, sum.Low)
	fmt.Fprintf(f, "- **Not Vulnerable:** %d\n", sum.NotVulnerable)
	if sum.Errors > 0 {
		fmt.Fprintf(f, "- **Errors / Timeouts:** %d\n", sum.Errors)
	}
	fmt.Fprintf(f, "\n---\n\n")

	fmt.Fprintf(f, "## Findings\n\n")
	if len(sum.Results) == 0 {
		fmt.Fprintf(f, "No results recorded.\n")
		return nil
	}

	fmt.Fprintf(f, "| # | Status | Severity | Endpoint | Mode | Details |\n")
	fmt.Fprintf(f, "|---|---|---|---|---|---|\n")

	for i, r := range sum.Results {
		status := r.Status
		if status == engine.StatusVulnerable {
			status = "**VULNERABLE**"
		}
		desc := r.Detail
		if desc == "" {
			desc = r.Description
		}
		if r.Err != nil {
			desc = r.Err.Error()
		}
		// Escape pipes for markdown table
		desc = fmt.Sprintf("`%s`", desc)

		fmt.Fprintf(f, "| %d | %s | %s | `%s` | %s | %s |\n",
			i+1, status, r.Severity, r.Endpoint, r.Mode, desc)
	}

	return nil
}
