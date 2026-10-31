// Package engine runs IDORaider templates against a target and classifies
// the results.
//
// Detection logic mirrors the standard manual BOLA/IDOR testing technique
// (the same one Burp Suite's "Autorize" extension automates):
//
//   - Single-token mode: replay a request with the tester's own token
//     against OTHER candidate resource IDs. If an id the tester doesn't
//     own returns an "accessible" response, that's a strong IDOR signal
//     (horizontal privilege escalation via ID enumeration).
//
//   - Dual-token mode: send the same request first with token A (the
//     resource owner) and then with token B (a different, lower-privileged
//     account). If both come back "accessible" for the same resource ID,
//     token B should not have been able to see it -> confirmed BOLA.
//
// This package only sends requests you configure it to send, against
// targets and with credentials you supply. Use it only on systems you are
// authorized to test (your own infrastructure, or in-scope bug bounty /
// pentest engagements).
package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jojin1709/idoraider/internal/template"
)

// Status values for a single probe.
const (
	StatusVulnerable    = "VULNERABLE"
	StatusNotVulnerable = "NOT VULNERABLE"
	StatusError         = "ERROR"
)

// Config controls how a scan is executed.
type Config struct {
	TargetBaseURL   string
	PrimaryToken    string // required: the tester's own, authorized token
	SecondaryToken  string // optional: a second, lower-privileged token for dual-token replay
	AuthHeader      string // header name for tokens, default "Authorization"
	AuthScheme      string // prefix before the token, default "Bearer"
	Concurrency     int
	Timeout         time.Duration
	ExtraHeaders    map[string]string
	ProxyURL        string        // optional HTTP/HTTPS/SOCKS5 proxy, e.g. http://127.0.0.1:8080
	InsecureTLS     bool          // skip TLS cert verification (useful for Burp proxy or staging)
	FollowRedirects bool          // follow HTTP redirects (default false to prevent false positives)
	Delay           time.Duration // delay between probes (rate limiting)
	CustomIDs       []string      // override template candidate IDs
}

// Result is the outcome of probing one (template, id) pair.
type Result struct {
	Template    string
	Endpoint    string
	Status      string
	Severity    string
	Description string
	Detail      string
	StatusCode  int
	Mode        string // "single-token" or "dual-token"
	Err         error
}

// Summary aggregates results for the final report.
type Summary struct {
	Target        string
	TotalTested   int
	Vulnerable    int
	Critical      int
	High          int
	Medium        int
	Low           int
	NotVulnerable int
	Errors        int
	Duration      time.Duration
	Results       []Result
}

// Run executes every template against the target and returns a Summary.
// onResult, if non-nil, is called synchronously as each result completes
// (useful for live progress output); it may be called from any goroutine
// belonging to the worker pool, so callers must synchronize if needed.
func Run(ctx context.Context, cfg Config, templates []*template.Template, onResult func(Result)) Summary {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 10
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.AuthHeader == "" {
		cfg.AuthHeader = "Authorization"
	}
	if cfg.AuthScheme == "" {
		cfg.AuthScheme = "Bearer"
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.InsecureTLS,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
	}

	if cfg.ProxyURL != "" {
		pURL, err := url.Parse(cfg.ProxyURL)
		if err == nil {
			transport.Proxy = http.ProxyURL(pURL)
		}
	} else {
		transport.Proxy = http.ProxyFromEnvironment
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
	}

	if !cfg.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	type job struct {
		t  *template.Template
		id string
	}

	var jobs []job
	for _, t := range templates {
		ids := t.IDs
		if len(cfg.CustomIDs) > 0 {
			ids = cfg.CustomIDs
		}
		for _, id := range ids {
			jobs = append(jobs, job{t: t, id: id})
		}
	}

	jobCh := make(chan job)
	resCh := make(chan Result, len(jobs))

	var wg sync.WaitGroup
	start := time.Now()

	for w := 0; w < cfg.Concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobCh {
				if cfg.Delay > 0 {
					time.Sleep(cfg.Delay)
				}
				r := probe(ctx, client, cfg, j.t, j.id)
				resCh <- r
				if onResult != nil {
					onResult(r)
				}
			}
		}()
	}

	go func() {
		defer close(jobCh)
		for _, j := range jobs {
			select {
			case jobCh <- j:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(resCh)
	}()

	sum := Summary{Target: cfg.TargetBaseURL}
	for r := range resCh {
		sum.Results = append(sum.Results, r)
		sum.TotalTested++
		switch {
		case r.Err != nil:
			sum.Errors++
		case r.Status == StatusVulnerable:
			sum.Vulnerable++
			switch r.Severity {
			case template.SeverityCritical:
				sum.Critical++
			case template.SeverityHigh:
				sum.High++
			case template.SeverityMedium:
				sum.Medium++
			default:
				sum.Low++
			}
		default:
			sum.NotVulnerable++
		}
	}
	sum.Duration = time.Since(start)
	return sum
}

func probe(ctx context.Context, client *http.Client, cfg Config, t *template.Template, id string) Result {
	mode := "single-token"
	if cfg.SecondaryToken != "" {
		mode = "dual-token"
	}

	path := strings.ReplaceAll(t.Path, "{id}", id)
	url := cfg.TargetBaseURL + path

	res := Result{
		Template:    t.SourceFile,
		Endpoint:    url,
		Severity:    t.Severity,
		Description: t.Description,
		Mode:        mode,
	}

	// Dual-token replay: owner request, then lower-priv request.
	if cfg.SecondaryToken != "" {
		ownerCode, ownerBody, err := doRequest(ctx, client, cfg, t, id, cfg.PrimaryToken)
		if err != nil {
			res.Status, res.Err = StatusError, err
			return res
		}
		ownerOK := matches(t, ownerCode, ownerBody)

		testCode, testBody, err := doRequest(ctx, client, cfg, t, id, cfg.SecondaryToken)
		if err != nil {
			res.Status, res.Err = StatusError, err
			return res
		}
		testOK := matches(t, testCode, testBody)
		res.StatusCode = testCode

		if ownerOK && testOK {
			res.Status = StatusVulnerable
			res.Detail = fmt.Sprintf("Owner token: %d (accessible). Secondary token: %d (also accessible) — object-level authorization check missing", ownerCode, testCode)
		} else if ownerOK && !testOK {
			res.Status = StatusNotVulnerable
			res.Detail = fmt.Sprintf("Owner token: %d (accessible). Secondary token: %d — access correctly restricted", ownerCode, testCode)
		} else if !ownerOK && testOK {
			res.Status = StatusVulnerable
			res.Detail = fmt.Sprintf("Owner token: %d (inaccessible) but secondary token: %d (accessible) — privilege anomaly / unauthorized access", ownerCode, testCode)
		} else {
			res.Status = StatusNotVulnerable
			res.Detail = fmt.Sprintf("Owner token: %d, Secondary token: %d — resource not accessible", ownerCode, testCode)
		}
		return res
	}

	// Single-token enumeration mode.
	code, body, err := doRequest(ctx, client, cfg, t, id, cfg.PrimaryToken)
	if err != nil {
		res.Status, res.Err = StatusError, err
		return res
	}
	res.StatusCode = code
	if matches(t, code, body) {
		res.Status = StatusVulnerable
		res.Detail = fmt.Sprintf("Resource id=%s accessible (HTTP %d) without ownership verification", id, code)
	} else {
		res.Status = StatusNotVulnerable
		res.Detail = fmt.Sprintf("HTTP %d — proper access control", code)
	}
	return res
}

func doRequest(ctx context.Context, client *http.Client, cfg Config, t *template.Template, id, token string) (int, string, error) {
	path := strings.ReplaceAll(t.Path, "{id}", id)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	url := cfg.TargetBaseURL + path
	body := strings.ReplaceAll(t.Body, "{id}", id)
	body = strings.ReplaceAll(body, "{token}", token)

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, t.Method, url, bodyReader)
	if err != nil {
		return 0, "", err
	}

	if token != "" {
		scheme := cfg.AuthScheme
		if scheme != "" {
			scheme += " "
		}
		req.Header.Set(cfg.AuthHeader, scheme+token)
	}
	for k, v := range cfg.ExtraHeaders {
		req.Header.Set(k, v)
	}
	for k, v := range t.Headers {
		v = strings.ReplaceAll(v, "{id}", id)
		v = strings.ReplaceAll(v, "{token}", token)
		if strings.TrimSpace(v) == "Bearer" || (token == "" && strings.Contains(t.Headers[k], "{token}")) {
			continue
		}
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	buf, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // cap at 1MB
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(buf), nil
}

func matches(t *template.Template, statusCode int, body string) bool {
	statusOK := false
	for _, s := range t.MatchStatus {
		if s == statusCode {
			statusOK = true
			break
		}
	}
	if !statusOK {
		return false
	}
	if len(t.MatchWords) == 0 {
		return true
	}
	lower := strings.ToLower(body)
	for _, w := range t.MatchWords {
		if strings.Contains(lower, strings.ToLower(w)) {
			return true
		}
	}
	return false
}
