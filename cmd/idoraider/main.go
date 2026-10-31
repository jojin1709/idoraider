// IDORaider — template-driven BOLA/IDOR & business-logic scanner.
//
// LEGAL / ETHICS: Only run this against systems you own or are explicitly
// authorized to test (e.g. an in-scope bug bounty program, a signed pentest
// engagement, or your own infrastructure). Unauthorized testing of systems
// you don't have permission to test is illegal in most jurisdictions and
// will get you banned from bounty platforms.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jojin1709/idoraider/internal/engine"
	"github.com/jojin1709/idoraider/internal/openapi"
	"github.com/jojin1709/idoraider/internal/report"
	"github.com/jojin1709/idoraider/internal/template"
	"github.com/jojin1709/idoraider/internal/webhook"
)

const version = "1.0.0"

// ANSI colors
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
		target          = flag.String("u", "", "Target base URL, e.g. https://target.com")
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
		onlyVuln        = flag.Bool("only-vulnerable", false, "Only print confirmed vulnerable findings in table")
		proxy           = flag.String("x", "", "HTTP/HTTPS/SOCKS5 proxy, e.g. http://127.0.0.1:8080")
		proxyAlias      = flag.String("proxy", "", "Alias for -x")
		insecure        = flag.Bool("k", false, "Skip TLS certificate verification (useful with Burp Suite)")
		insecureAlias   = flag.Bool("insecure", false, "Alias for -k")
		followRedirects = flag.Bool("follow-redirects", false, "Follow HTTP redirects (default false to prevent false positives)")
		delay           = flag.Duration("d", 0, "Delay between requests, e.g. 100ms, 1s")
		delayAlias      = flag.Duration("delay", 0, "Alias for -d")
		idsFlag         = flag.String("ids", "", "Candidate IDs or ranges (e.g. 1-100 or 1,2,uuid-1)")
		openapiFlag     = flag.String("openapi", "", "OpenAPI / Swagger spec URL or file to auto-generate scan templates")
		swaggerFlag     = flag.String("swagger", "", "Alias for --openapi")
		webhookURL      = flag.String("webhook", os.Getenv("IDORAIDER_WEBHOOK"), "Discord, Slack, or generic webhook URL to receive scan alerts")
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
	if *openapiFlag == "" && *swaggerFlag != "" {
		*openapiFlag = *swaggerFlag
	}

	// 1. Gather Target(s): Flag or STDIN Pipe
	var targets []string
	if *target != "" && *target != "-" {
		targets = append(targets, normalizeTarget(*target))
	} else {
		// Check if STDIN is piped
		stat, err := os.Stdin.Stat()
		if err == nil && (stat.Mode()&os.ModeCharDevice) == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					targets = append(targets, normalizeTarget(line))
				}
			}
		}
	}

	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, red+"error:"+reset+" -u/--url target or piped STDIN is required")
		flag.Usage()
		os.Exit(2)
	}

	if !*noBanner {
		printBanner(targets[0], *tmplDir, *concurrent, *proxy)
	}

	// 2. Load Templates: YAML Directory and/or OpenAPI Schema
	var templates []*template.Template
	if *openapiFlag != "" {
		log("INF", fmt.Sprintf("Importing endpoints from OpenAPI spec: %s", *openapiFlag))
		oTemplates, err := openapi.Load(context.Background(), *openapiFlag)
		if err != nil {
			fmt.Fprintln(os.Stderr, red+"error loading openapi spec: "+reset+err.Error())
			os.Exit(1)
		}
		templates = append(templates, oTemplates...)
		log("INF", fmt.Sprintf("Generated %d templates from OpenAPI spec", len(oTemplates)))
	}

	if *tmplDir != "" && len(templates) == 0 {
		tList, err := template.LoadDir(*tmplDir)
		if err != nil && *openapiFlag == "" {
			fmt.Fprintln(os.Stderr, red+"error loading templates: "+reset+err.Error())
			os.Exit(1)
		}
		templates = append(templates, tList...)
	}

	if len(templates) == 0 {
		fmt.Fprintln(os.Stderr, yellow+"no scan templates found"+reset)
		os.Exit(1)
	}

	// 3. Parse candidate IDs (support numeric ranges e.g. 1-100)
	customIDs := parseCandidateIDs(*idsFlag)

	totalProbesPerTarget := 0
	for _, t := range templates {
		if len(customIDs) > 0 {
			totalProbesPerTarget += len(customIDs)
		} else {
			totalProbesPerTarget += len(t.IDs)
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

	log("INF", fmt.Sprintf("Loaded %d scan templates", len(templates)))
	log("INF", fmt.Sprintf("Target count: %d", len(targets)))
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
		log("INF", fmt.Sprintf("Custom IDs override: %d candidate IDs loaded", len(customIDs)))
	}
	log("INF", "Beginning scan...")
	fmt.Println()

	var overallVulnerable int

	for tIdx, curTarget := range targets {
		if len(targets) > 1 {
			fmt.Printf("\n%s[%d/%d] Scanning target: %s%s\n", cyan+bold, tIdx+1, len(targets), curTarget, reset)
		}

		cfg := engine.Config{
			TargetBaseURL:   curTarget,
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
			shouldPrint := true
			if *quiet || *onlyVuln {
				shouldPrint = (r.Status == engine.StatusVulnerable)
			}
			if shouldPrint {
				printResult(cur, totalProbesPerTarget, r)
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

		_ = report.WriteJSON(jsonPath, sum)
		_ = report.WriteMarkdown(mdPath, sum)

		printSummary(sum, jsonPath, mdPath)

		if sum.Vulnerable > 0 {
			overallVulnerable += sum.Vulnerable
		}

		// Webhook Alert delivery
		if *webhookURL != "" {
			if err := webhook.Send(context.Background(), *webhookURL, sum); err != nil {
				fmt.Fprintln(os.Stderr, yellow+"warning: sending webhook: "+reset+err.Error())
			} else {
				log("INF", "Webhook delivered successfully.")
			}
		}
	}

	if overallVulnerable > 0 {
		os.Exit(3) // non-zero exit so CI pipelines can fail the build on findings
	}
}

func normalizeTarget(t string) string {
	t = strings.TrimRight(strings.TrimSpace(t), "/")
	if !strings.HasPrefix(t, "http://") && !strings.HasPrefix(t, "https://") {
		t = "https://" + t
	}
	return t
}

func parseCandidateIDs(raw string) []string {
	var ids []string
	if raw == "" {
		return ids
	}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// Check for integer range: "1-100"
		if strings.Contains(part, "-") {
			dashIdx := strings.Index(part, "-")
			startStr := part[:dashIdx]
			endStr := part[dashIdx+1:]
			start, err1 := strconv.Atoi(startStr)
			end, err2 := strconv.Atoi(endStr)
			if err1 == nil && err2 == nil && start <= end && (end-start) <= 10000 {
				for i := start; i <= end; i++ {
					ids = append(ids, strconv.Itoa(i))
				}
				continue
			}
		}
		ids = append(ids, part)
	}
	return ids
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
	fmt.Printf("  %-12s: Template & OpenAPI scanning\n", "Mode")
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
		if sum.Errors > (sum.TotalTested / 3) {
			fmt.Printf("  %sTip: High error count detected. Target may rate-limit; try -c 5 and -d 100ms%s\n", yellow, reset)
		}
	}
	fmt.Println(bar)
	log("INF", "JSON report: "+jsonPath)
	log("INF", "Markdown report: "+mdPath)
}
