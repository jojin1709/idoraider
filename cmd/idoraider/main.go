// IDORaider — template-driven BOLA/IDOR & business-logic scanner.
//
// LEGAL / ETHICS: Only run this against systems you own or are explicitly
// authorized to test (e.g. an in-scope bug bounty program, a signed pentest
// engagement, or your own infrastructure). Unauthorized testing of systems
// you don't have permission to test is illegal in most jurisdictions and
// will get you banned from bounty platforms.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jojin1709/idoraider/internal/engine"
	"github.com/jojin1709/idoraider/internal/report"
	"github.com/jojin1709/idoraider/internal/template"
)

const version = "1.0.0"

// ANSI colors — degrade gracefully (just shows codes) on terminals that
// don't support them, which is acceptable for a v1 CLI tool.
const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	cyan   = "\033[36m"
	grey   = "\033[90m"
)

type stringSlice []string

func (s *stringSlice) String() string {
	return strings.Join(*s, ", ")
}

func (s *stringSlice) Set(val string) error {
	*s = append(*s, val)
	return nil
}

func main() {
	var (
		target          = flag.String("u", "", "Target base URL, e.g. https://target.com (required)")
		urlAlias        = flag.String("url", "", "Alias for -u")
		tmplDir         = flag.String("t", "templates/", "Directory of .yaml templates")
		concurrent      = flag.Int("c", 20, "Concurrency (parallel workers)")
		token           = flag.String("token", os.Getenv("IDORAIDER_TOKEN"), "Primary (your own, authorized) auth token")
		secToken        = flag.String("secondary-token", os.Getenv("IDORAIDER_SECONDARY_TOKEN"), "Optional second, lower-privileged token for owner-vs-other replay testing")
		authHeader      = flag.String("auth-header", "Authorization", "Header name used to send the token")
		authScheme      = flag.String("auth-scheme", "Bearer", "Scheme prefix before the token (use \"\" for none)")
		timeoutSec      = flag.Int("timeout", 10, "Per-request timeout in seconds")
		outDir          = flag.String("o", "results/", "Directory to write reports into")
		noBanner        = flag.Bool("no-banner", false, "Suppress the startup banner")
		quiet           = flag.Bool("silent", false, "Only print vulnerable findings and the final summary")
		proxy           = flag.String("x", "", "HTTP/HTTPS/SOCKS5 proxy, e.g. http://127.0.0.1:8080")
		proxyAlias      = flag.String("proxy", "", "Alias for -x")
		insecure        = flag.Bool("k", false, "Skip TLS certificate verification (useful with Burp Suite)")
		insecureAlias   = flag.Bool("insecure", false, "Alias for -k")
		followRedirects = flag.Bool("follow-redirects", false, "Follow HTTP redirects (default false to prevent false positives)")
		delay           = flag.Duration("d", 0, "Delay between requests, e.g. 100ms, 1s")
		delayAlias      = flag.Duration("delay", 0, "Alias for -d")
		idsFlag         = flag.String("ids", "", "Comma-separated list of IDs to probe, overriding template defaults (e.g. 1,2,3 or uuid1,uuid2)")
		headersFlag     stringSlice
	)
	flag.Var(&headersFlag, "H", "Custom request header (format 'Key: Value'), repeatable")
	flag.Var(&headersFlag, "header", "Alias for -H")
	flag.Parse()

	if *target == "" && *urlAlias != "" {
		*target = *urlAlias
	}
	if *proxy == "" && *proxyAlias != "" {
		*proxy = *proxyAlias
	}
	if !*insecure && *insecureAlias {
		*insecure = *insecureAlias
	}
	if *delay == 0 && *delayAlias != 0 {
		*delay = *delayAlias
	}

	if *target == "" {
		fmt.Fprintln(os.Stderr, red+"error:"+reset+" -u/--url target is required")
		flag.Usage()
		os.Exit(2)
	}
	*target = strings.TrimRight(*target, "/")
	if !strings.HasPrefix(*target, "http://") && !strings.HasPrefix(*target, "https://") {
		*target = "https://" + *target
	}

	if !*noBanner {
		printBanner(*target, *tmplDir, *concurrent, *proxy)
	}

	templates, err := template.LoadDir(*tmplDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, red+"error loading templates: "+reset+err.Error())
		os.Exit(1)
	}
	if len(templates) == 0 {
		fmt.Fprintln(os.Stderr, yellow+"no templates found in "+*tmplDir+reset)
		os.Exit(1)
	}

	var customIDs []string
	if *idsFlag != "" {
		for _, part := range strings.Split(*idsFlag, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				customIDs = append(customIDs, part)
			}
		}
	}

	totalProbes := 0
	for _, t := range templates {
		if len(customIDs) > 0 {
			totalProbes += len(customIDs)
		} else {
			totalProbes += len(t.IDs)
		}
	}

	extraHeaders := make(map[string]string)
	for _, h := range headersFlag {
		idx := strings.Index(h, ":")
		if idx > 0 {
			k := strings.TrimSpace(h[:idx])
			v := strings.TrimSpace(h[idx+1:])
			extraHeaders[k] = v
		}
	}

	log("INF", fmt.Sprintf("Loaded %d YAML templates from %s", len(templates), *tmplDir))
	log("INF", fmt.Sprintf("Target: %s", *target))
	log("INF", fmt.Sprintf("Concurrency: %d workers", *concurrent))
	if *token == "" && *secToken == "" {
		log("WRN", "No auth token provided (--token). Probing endpoints without authentication.")
	}
	if *proxy != "" {
		log("INF", fmt.Sprintf("Proxy: %s", *proxy))
	}
	if *insecure {
		log("INF", "TLS verification disabled (--insecure)")
	}
	if *delay > 0 {
		log("INF", fmt.Sprintf("Request delay: %s", *delay))
	}
	if len(customIDs) > 0 {
		log("INF", fmt.Sprintf("Custom IDs override: %v", customIDs))
	}
	log("INF", "Beginning scan...")
	fmt.Println()

	cfg := engine.Config{
		TargetBaseURL:   *target,
		PrimaryToken:    *token,
		SecondaryToken:  *secToken,
		AuthHeader:      *authHeader,
		AuthScheme:      *authScheme,
		Concurrency:     *concurrent,
		Timeout:         time.Duration(*timeoutSec) * time.Second,
		ExtraHeaders:    extraHeaders,
		ProxyURL:        *proxy,
		InsecureTLS:     *insecure,
		FollowRedirects: *followRedirects,
		Delay:           *delay,
		CustomIDs:       customIDs,
	}

	var (
		mu   sync.Mutex
		done int
	)
	printHeader()
	sum := engine.Run(context.Background(), cfg, templates, func(r engine.Result) {
		mu.Lock()
		done++
		cur := done
		if !*quiet || r.Status == engine.StatusVulnerable {
			printResult(cur, totalProbes, r)
		}
		mu.Unlock()
	})

	fmt.Println()
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, red+"error creating output dir: "+reset+err.Error())
		os.Exit(1)
	}
	baseName := time.Now().Format("2006-01-02_150405")
	jsonPath := filepath.Join(*outDir, fmt.Sprintf("%s.json", baseName))
	mdPath := filepath.Join(*outDir, fmt.Sprintf("%s.md", baseName))

	if err := report.WriteJSON(jsonPath, sum); err != nil {
		fmt.Fprintln(os.Stderr, red+"error writing json report: "+reset+err.Error())
	}
	if err := report.WriteMarkdown(mdPath, sum); err != nil {
		fmt.Fprintln(os.Stderr, red+"error writing markdown report: "+reset+err.Error())
	}

	printSummary(sum, jsonPath, mdPath)

	if sum.Vulnerable > 0 {
		os.Exit(3) // non-zero exit so CI pipelines can fail the build on findings
	}
}

func printBanner(target, tmplDir string, concurrency int, proxy string) {
	fmt.Println(cyan + bold + `
 ██╗██████╗  ██████╗ ██████╗  █████╗ ██╗██████╗ ███████╗██████╗ 
 ██║██╔══██╗██╔═══██╗██╔══██╗██╔══██╗██║██╔══██╗██╔════╝██╔══██╗
 ██║██║  ██║██║   ██║██████╔╝███████║██║██║  ██║█████╗  ██████╔╝
 ██║██║  ██║██║   ██║██╔══██╗██╔══██║██║██║  ██║██╔══╝  ██╔══██╗
 ██║██████╔╝╚██████╔╝██║  ██║██║  ██║██║██████╔╝███████╗██║  ██║
 ╚═╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝
` + reset)
	fmt.Println(dim + "       HUNTING BROKEN ACCESS CONTROL" + strings.Repeat(" ", 22) + "v" + version + reset)
	fmt.Println()
	fmt.Println(grey + "  Go-based BOLA/IDOR Vulnerability Scanner" + reset)
	fmt.Printf("  %-12s: Jojin John\n", "Author")
	fmt.Printf("  %-12s: Go\n", "Language")
	fmt.Printf("  %-12s: Find IDOR / BOLA vulnerabilities\n", "Purpose")
	fmt.Printf("  %-12s: Template-based scanning\n", "Mode")
	fmt.Printf("  %-12s: %s\n", "Target", target)
	fmt.Printf("  %-12s: %s\n", "Templates", tmplDir)
	fmt.Printf("  %-12s: %d\n", "Concurrency", concurrency)
	if proxy != "" {
		fmt.Printf("  %-12s: %s\n", "Proxy", proxy)
	}
	fmt.Printf("  %-12s: %s\n", "Time", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println()
}

func log(level, msg string) {
	fmt.Printf("%s[%s]%s %s[%s]%s %s\n", grey, time.Now().Format("15:04:05"), reset, cyan, level, reset, msg)
}

func printHeader() {
	fmt.Printf("%-10s %-5s %-6s %-16s %-12s %-50s %s\n", "PROGRESS", "#", "CODE", "STATUS", "SEVERITY", "ENDPOINT", "RESULT")
	fmt.Println(grey + strings.Repeat("─", 145) + reset)
}

func printResult(n, total int, r engine.Result) {
	var statusColor, statusText string
	codeStr := fmt.Sprintf("%d", r.StatusCode)
	sevStr := "-"

	switch r.Status {
	case engine.StatusVulnerable:
		statusColor = red + bold
		statusText = "VULNERABLE"
		sevStr = r.Severity
	case engine.StatusError:
		statusColor = yellow
		statusText = "ERROR"
		codeStr = "ERR"
	default:
		if r.StatusCode == 404 {
			statusText = "NOT FOUND"
			statusColor = grey
		} else if r.StatusCode == 401 || r.StatusCode == 403 {
			statusText = "RESTRICTED"
			statusColor = cyan
		} else {
			statusText = "NOT VULNERABLE"
			statusColor = green
		}
	}

	endpoint := r.Endpoint
	if len(endpoint) > 48 {
		endpoint = endpoint[:45] + "..."
	}
	progress := fmt.Sprintf("[%d/%d]", n, total)

	line := fmt.Sprintf("%-10s %-5d %-6s %s%-16s%s %-12s %-50s %s",
		progress, n, codeStr, statusColor, statusText, reset, sevStr, endpoint, r.Detail)
	fmt.Println(line)
}

func printSummary(sum engine.Summary, jsonPath, mdPath string) {
	bar := grey + strings.Repeat("─", 70) + reset
	fmt.Println(bar)
	status := green + "✓ Scan completed" + reset
	if sum.Vulnerable > 0 {
		status = red + bold + "✗ Scan completed — vulnerabilities found" + reset
	}
	fmt.Printf("%s in %s\n", status, sum.Duration.Round(time.Millisecond))
	fmt.Printf("  %d endpoints tested   ", sum.TotalTested)
	fmt.Printf("%s%d vulnerable%s   ", red, sum.Vulnerable, reset)
	fmt.Printf("%d critical   %d high   %d medium   %d low   ", sum.Critical, sum.High, sum.Medium, sum.Low)
	fmt.Printf("%s%d not vulnerable%s\n", green, sum.NotVulnerable, reset)
	if sum.Errors > 0 {
		fmt.Printf("  %s%d requests errored%s\n", yellow, sum.Errors, reset)
	}
	fmt.Println(bar)
	log("INF", "JSON report: "+jsonPath)
	log("INF", "Markdown report: "+mdPath)
}
