// Package template loads IDORaider scan templates.
//
// Templates use a small, intentionally restricted YAML-like syntax so the
// whole project can build with zero external dependencies. Each template
// describes one endpoint pattern to probe for broken object level
// authorization (BOLA) / insecure direct object reference (IDOR) issues.
package template

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Severity levels used for reporting/sorting.
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
)

// Template describes a single endpoint probe.
//
// Example template file (templates/idor-user-profile.yaml):
//
//	id: idor-user-profile
//	name: User Profile IDOR
//	severity: critical
//	description: User profile accessible with a modified ID
//	method: GET
//	path: /api/v1/users/{id}
//	headers:
//	  Authorization: Bearer {token}
//	ids:
//	  - 1
//	  - 2
//	  - 123
//	match_status:
//	  - 200
//	match_words:
//	  - email
//	  - username
type Template struct {
	ID             string
	Name           string
	Severity       string
	Description    string
	Method         string
	Path           string            // may contain {id} and {token} placeholders
	Headers        map[string]string // values may contain {id} and {token}
	Body           string            // optional request body, may contain {id}
	IDs            []string          // candidate ID values to substitute for {id}
	MatchStatus    []int             // status codes considered "accessible"
	MatchNotStatus []int             // status codes considered "restricted" (negative match)
	MatchWords     []string          // response-body substrings considered "accessible"
	MatchCondition string            // "any" (default) or "all"
	SourceFile     string
}

// LoadDir reads every *.yaml / *.yml file in dir and returns the parsed
// templates, sorted by ID for stable, reproducible scan ordering.
func LoadDir(dir string) ([]*Template, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading template dir %q: %w", dir, err)
	}

	var templates []*Template
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		full := filepath.Join(dir, name)
		t, err := LoadFile(full)
		if err != nil {
			return nil, fmt.Errorf("parsing template %s: %w", full, err)
		}
		templates = append(templates, t)
	}

	sort.Slice(templates, func(i, j int) bool { return templates[i].ID < templates[j].ID })
	return templates, nil
}

// LoadFile parses a single template file.
func LoadFile(path string) (*Template, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	t := &Template{
		Method:      "GET",
		Headers:     map[string]string{},
		MatchStatus: []int{200},
		SourceFile:  filepath.Base(path),
	}

	scanner := bufio.NewScanner(f)
	var (
		curList   *[]string
		curInts   *[]int
		curMap    map[string]string
		listIsInt bool
	)

	flushList := func() {
		curList = nil
		curInts = nil
		curMap = nil
		listIsInt = false
	}

	for scanner.Scan() {
		raw := scanner.Text()
		line := strings.TrimRight(raw, " \t\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		indented := strings.HasPrefix(raw, "  ") || strings.HasPrefix(raw, "\t")

		if indented && strings.HasPrefix(trimmed, "- ") {
			val := unquote(strings.TrimSpace(trimmed[2:]))
			if curInts != nil {
				n, err := strconv.Atoi(val)
				if err != nil {
					return nil, fmt.Errorf("expected integer in list, got %q", val)
				}
				*curInts = append(*curInts, n)
			} else if curList != nil {
				*curList = append(*curList, val)
			}
			continue
		}

		if indented && curMap != nil && strings.Contains(trimmed, ":") {
			k, v := splitKV(trimmed)
			curMap[k] = unquote(v)
			continue
		}

		if indented {
			continue
		}

		// Top-level "key:" or "key: value"
		if !strings.Contains(trimmed, ":") {
			continue
		}
		key, val := splitKV(trimmed)
		val = unquote(val)

		if val != "" {
			flushList()
			switch key {
			case "id":
				t.ID = val
			case "name":
				t.Name = val
			case "severity":
				t.Severity = strings.ToUpper(val)
			case "description":
				t.Description = val
			case "method":
				t.Method = strings.ToUpper(val)
			case "path":
				t.Path = val
			case "body":
				t.Body = val
			case "match_condition", "condition":
				t.MatchCondition = strings.ToLower(val)
			}
			continue
		}

		// "key:" with no inline value -> a list or map follows on indented lines
		switch key {
		case "headers":
			t.Headers = map[string]string{}
			curMap = t.Headers
			curList, curInts = nil, nil
		case "ids":
			t.IDs = nil
			curList = &t.IDs
			curInts, curMap = nil, nil
			listIsInt = false
		case "match_status":
			t.MatchStatus = nil
			curInts = &t.MatchStatus
			curList, curMap = nil, nil
			listIsInt = true
		case "match_not_status":
			t.MatchNotStatus = nil
			curInts = &t.MatchNotStatus
			curList, curMap = nil, nil
			listIsInt = true
		case "match_words":
			t.MatchWords = nil
			curList = &t.MatchWords
			curInts, curMap = nil, nil
			listIsInt = false
		default:
			flushList()
		}
		_ = listIsInt
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if t.ID == "" {
		t.ID = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	if t.Severity == "" {
		t.Severity = SeverityMedium
	}
	if t.Path == "" {
		return nil, fmt.Errorf("template %s missing required field: path", path)
	}
	if t.MatchCondition == "" {
		t.MatchCondition = "any"
	}
	if len(t.IDs) == 0 {
		t.IDs = []string{"1"}
	}
	if len(t.MatchStatus) == 0 {
		t.MatchStatus = []int{200}
	}

	return t, nil
}

func splitKV(line string) (key, val string) {
	idx := strings.Index(line, ":")
	key = strings.TrimSpace(line[:idx])
	val = strings.TrimSpace(line[idx+1:])
	return key, val
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
