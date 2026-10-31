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
	"strconv"
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

func formatErr(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if strings.Contains(msg, "context deadline exceeded") || strings.Contains(msg, "Client.Timeout exceeded") {
		return "Request timeout (server too slow)"
	}
	if strings.Contains(msg, "connection refused") || strings.Contains(msg, "connectex:") {
		return "Connection refused"
	}
	if strings.Contains(msg, "no such host") {
		return "DNS lookup failed"
	}
	if strings.Contains(msg, "connection reset") {
		return "Connection reset (possible rate limit)"
	}
	if len(msg) > 42 {
		return msg[:39] + "..."
	}
	return msg
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
			res.Detail = formatErr(err)
			return res
		}
		ownerOK := matches(t, ownerCode, ownerBody)

		testCode, testBody, err := doRequest(ctx, client, cfg, t, id, cfg.SecondaryToken)
		if err != nil {
			res.Status, res.Err = StatusError, err
			res.Detail = formatErr(err)
			return res
		}
		testOK := matches(t, testCode, testBody)
		res.StatusCode = testCode

		if ownerOK && testOK {
			res.Status = StatusVulnerable
			res.Detail = fmt.Sprintf("HTTP %d: Owner token accessible, Secondary token also accessible — BOLA confirmed", testCode)
		} else if ownerOK && !testOK {
			res.Status = StatusNotVulnerable
			res.Detail = fmt.Sprintf("HTTP %d: Owner accessible, Secondary denied (proper access control)", testCode)
		} else if !ownerOK && testOK {
			res.Status = StatusVulnerable
			res.Detail = fmt.Sprintf("HTTP %d: Owner inaccessible (HTTP %d), but secondary token accessible", testCode, ownerCode)
		} else {
			res.Status = StatusNotVulnerable
			if ownerCode == 404 && testCode == 404 {
				res.Detail = "HTTP 404: Endpoint not found for both tokens"
			} else {
				res.Detail = fmt.Sprintf("Owner: HTTP %d, Secondary: HTTP %d — resource not accessible", ownerCode, testCode)
			}
		}
		return res
	}

	// Single-token enumeration mode.
	code, body, err := doRequest(ctx, client, cfg, t, id, cfg.PrimaryToken)
	if err != nil {
		res.Status, res.Err = StatusError, err
		res.Detail = formatErr(err)
		return res
	}
	res.StatusCode = code
	if matches(t, code, body) {
		res.Status = StatusVulnerable
		res.Detail = fmt.Sprintf("HTTP %d: Resource id=%s accessible with sensitive keywords", code, id)
	} else {
		res.Status = StatusNotVulnerable
		switch code {
		case 404:
			res.Detail = "HTTP 404: Endpoint not found"
		case 401:
			res.Detail = "HTTP 401: Unauthorized (auth required)"
		case 403:
			res.Detail = "HTTP 403: Forbidden (access restricted)"
		case 301, 302, 307, 308:
			res.Detail = fmt.Sprintf("HTTP %d: Redirected", code)
		case 200:
			res.Detail = "HTTP 200: Response did not match keywords"
		default:
			res.Detail = fmt.Sprintf("HTTP %d: Inaccessible", code)
		}
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

	// Realistic browser User-Agent so WAFs don't block Go-http-client by default
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")

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

	// Smart 429 Rate-Limit Auto-Backoff (single retry on rate-limit)
	if resp.StatusCode == http.StatusTooManyRequests {
		retryAfter := resp.Header.Get("Retry-After")
		backoff := 2 * time.Second
		if retryAfter != "" {
			if sec, parseErr := strconv.Atoi(retryAfter); parseErr == nil && sec > 0 && sec <= 10 {
				backoff = time.Duration(sec) * time.Second
			}
		}
		resp.Body.Close()

		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return http.StatusTooManyRequests, "", ctx.Err()
		}

		if body != "" {
			bodyReader = strings.NewReader(body)
		}
		reqRetry, errRetry := http.NewRequestWithContext(ctx, t.Method, url, bodyReader)
		if errRetry == nil {
			reqRetry.Header = req.Header.Clone()
			respRetry, errDo := client.Do(reqRetry)
			if errDo == nil {
				defer respRetry.Body.Close()
				buf, errRead := io.ReadAll(io.LimitReader(respRetry.Body, 1<<20))
				if errRead == nil {
					return respRetry.StatusCode, string(buf), nil
				}
			}
		}
		return http.StatusTooManyRequests, "429 Too Many Requests (Rate Limited)", nil
	}

	defer resp.Body.Close()

	buf, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // cap at 1MB
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(buf), nil
}

func matches(t *template.Template, statusCode int, body string) bool {
	// 1. Negative status check (if status is in match_not_status, it cannot be a match)
	for _, s := range t.MatchNotStatus {
		if s == statusCode {
			return false
		}
	}

	// 2. Positive status check
	if len(t.MatchStatus) > 0 {
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
	}

	// 3. Match words check
	if len(t.MatchWords) == 0 {
		return true
	}

	lower := strings.ToLower(body)
	if strings.EqualFold(t.MatchCondition, "all") || strings.EqualFold(t.MatchCondition, "and") {
		for _, w := range t.MatchWords {
			if !strings.Contains(lower, strings.ToLower(w)) {
				return false
			}
		}
		return true
	}

	// Default: "any" / "or"
	for _, w := range t.MatchWords {
		if strings.Contains(lower, strings.ToLower(w)) {
			return true
		}
	}
	return false
}
