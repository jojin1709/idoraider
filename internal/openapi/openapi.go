// Package openapi parses OpenAPI 2.0 / 3.0+ (Swagger) specifications
// and generates IDORaider scan templates automatically.
package openapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/jojin1709/idoraider/internal/template"
)

var paramRegex = regexp.MustCompile(`\{[^}]+\}`)

// Load parses an OpenAPI JSON spec from a file path or URL and returns
// scan templates for all parameterized endpoints.
func Load(ctx context.Context, source string) ([]*template.Template, error) {
	data, err := readSource(ctx, source)
	if err != nil {
		return nil, err
	}

	var root struct {
		Paths map[string]map[string]interface{} `json:"paths"`
	}
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parsing OpenAPI JSON schema: %w", err)
	}

	var templates []*template.Template
	seen := make(map[string]bool)

	for rawPath, methods := range root.Paths {
		// Only care about endpoints with parameterized path variables like {id}, {userId}, {accountId}
		if !strings.Contains(rawPath, "{") {
			continue
		}

		// Normalize any {param} to {id} so IDORaider can substitute candidate values
		normalizedPath := paramRegex.ReplaceAllString(rawPath, "{id}")

		for method := range methods {
			m := strings.ToUpper(strings.TrimSpace(method))
			switch m {
			case "GET", "POST", "PUT", "DELETE", "PATCH":
			default:
				continue
			}

			key := fmt.Sprintf("%s:%s", m, normalizedPath)
			if seen[key] {
				continue
			}
			seen[key] = true

			cleanID := strings.Trim(normalizedPath, "/")
			cleanID = strings.ReplaceAll(cleanID, "/", "-")
			cleanID = strings.ReplaceAll(cleanID, "{id}", "id")
			tmplID := fmt.Sprintf("openapi-%s-%s", strings.ToLower(m), cleanID)

			t := &template.Template{
				ID:             tmplID,
				Name:           fmt.Sprintf("OpenAPI %s %s", m, normalizedPath),
				Severity:       template.SeverityHigh,
				Description:    fmt.Sprintf("OpenAPI auto-generated probe for %s %s", m, rawPath),
				Method:         m,
				Path:           normalizedPath,
				IDs:            []string{"1", "2", "3", "100"},
				MatchStatus:    []int{200},
				MatchNotStatus: []int{401, 403, 404},
				MatchCondition: "any",
				SourceFile:     "openapi",
			}
			templates = append(templates, t)
		}
	}

	return templates, nil
}

func readSource(ctx context.Context, src string) ([]byte, error) {
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		client := &http.Client{Timeout: 15 * time.Second}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "IDORaider-OpenAPI/1.0")
		req.Header.Set("Accept", "application/json, */*")

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("fetching OpenAPI URL %q: %w", src, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 400 {
			return nil, fmt.Errorf("fetching OpenAPI URL returned HTTP %d", resp.StatusCode)
		}
		return io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10MB limit
	}

	// Local file
	return os.ReadFile(src)
}

