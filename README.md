<div align="center">

<img src="./assets/banner.png" alt="IDORaider - Hunting Broken Access Control" width="100%">

<br><br>

<p align="center">
  <a href="https://jojin1709.github.io/idoraider/"><img src="https://img.shields.io/badge/Docs-Interactive%20Website-00f5a0.svg?style=for-the-badge&logo=googlechrome&logoColor=black" alt="Documentation Website"></a>
  <a href="https://github.com/jojin1709/idoraider/actions"><img src="https://img.shields.io/github/actions/workflow/status/jojin1709/idoraider/ci.yml?branch=main&style=for-the-badge&label=CI&logo=githubactions&logoColor=white" alt="CI Status"></a>
  <a href="https://golang.org/"><img src="https://img.shields.io/badge/Language-Go%201.22+-00ADD8.svg?style=for-the-badge&logo=go" alt="Go 1.22+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/Dependencies-Zero%20(Stdlib)-success.svg?style=for-the-badge" alt="Zero External Dependencies">
  <a href="https://github.com/jojin1709/idoraider/releases/tag/v1.0.0"><img src="https://img.shields.io/badge/Release-v1.0.0-purple.svg?style=for-the-badge&logo=github" alt="Release v1.0.0"></a>
</p>

### High-Performance, Template-Driven BOLA / IDOR Vulnerability Scanner

**Built with precision by [JOJIN JOHN](https://github.com/jojin1709)**

<p align="center">
  <strong>IDORaider</strong> hunts Broken Object Level Authorization (BOLA / IDOR) and business-logic flaws across APIs using YAML templates and automated dual-token authorization replay.
</p>

---

</div>

> [!WARNING]
> **Authorized Testing Only:** IDORaider performs active security testing and HTTP replay against target endpoints. Only run this tool against systems you own or have explicit, signed written authorization to test (e.g., bug bounty programs in scope or authorized pentests). Unauthorized testing is illegal.

> [!NOTE]
> **Zero External Dependencies:** Built 100% on the Go standard library. Compiles cleanly offline with zero supply-chain risk and no `go mod download` network requirements.

---

## Table of Contents

- [What is IDORaider?](#what-is-idoraider)
  - [Why IDORaider Exists](#why-idoraider-exists)
  - [How Detection Works](#how-detection-works)
- [Quick Start](#quick-start)
  - [Installation & Build](#1-installation--build)
  - [Usage Examples](#2-usage-examples)
    - [Single-Token Scanning](#single-token-mode-id-enumeration)
    - [Dual-Token BOLA Replay](#dual-token-mode-owner-vs-other--recommended)
    - [Proxy & Burp Suite](#routing-through-burp-suite--owasp-zap)
- [Key Capabilities](#key-capabilities)
- [Terminal Output Preview](#terminal-output-preview)
- [CLI Reference](#cli-reference)
- [Writing Scan Templates](#writing-scan-templates)
  - [Template Syntax](#template-syntax)
  - [Condition & Matching Logic](#condition--matching-logic)
  - [Included Starter Templates](#included-starter-templates)
- [Architecture & Replay Flow](#architecture--replay-flow)
- [Reporting](#reporting)
- [Contributing](#contributing)
- [Security Policy](#security-policy)
- [Code of Conduct](#code-of-conduct)
- [Developer](#developer)
- [License](#license)

---

## What is IDORaider?

**IDORaider** is an automated, template-driven security scanner designed specifically to discover **Broken Object Level Authorization (BOLA)** and **Insecure Direct Object References (IDOR)** — the #1 API security vulnerability in the OWASP API Security Top 10.

Instead of relying on simple URL fuzzing, IDORaider adopts the methodology used by elite penetration testers and tools like Burp Suite's *Autorize*: it executes requests under verified authentication contexts, validates responses against criteria, and compares access permissions between different user privileges.

### Why IDORaider Exists

* **Zero-Noise Detection:** Single-token scanning flags accessible endpoints, while dual-token replay confirms whether a low-privileged user can view resources owned by another user.
* **Modern Tooling Compatibility:** Built-in Burp Suite proxy routing (`-x`), self-signed TLS support (`-k`), custom session headers (`-H`), and redirect suppression to eliminate false-positive login pages.
* **Fast & Lightweight:** Concurrently replays dozens of endpoints in milliseconds with worker pools and graceful rate-limiting controls.

### How Detection Works

1. **Single-Token Mode (ID Enumeration):**
   Replays requests with your authorized token across candidate IDs. An accessible response (`200 OK` matching content keywords) indicates potential horizontal access without ownership checks.
2. **Dual-Token Mode (Owner vs. Attacker — Recommended):**
   Replays the target endpoint with Token A (Resource Owner) to verify valid access, then immediately replays with Token B (Unrelated Account). If Token B also gains full access to Token A's resource, **BOLA is confirmed**.

---

## Quick Start

### 1. Installation & Build

Clone the repository and build the binary for your platform:

#### Linux / macOS
```bash
git clone https://github.com/jojin1709/idoraider.git
cd idoraider
go build -o idoraider ./cmd/idoraider
```

#### Windows (PowerShell / Command Prompt)
```powershell
git clone https://github.com/jojin1709/idoraider.git
cd idoraider
go build -o idoraider.exe ./cmd/idoraider
```
*(Or simply run `.\build.bat` or `.\build.ps1`)*

#### Docker
```bash
docker build -t idoraider .
docker run --rm idoraider -u https://api.target.com -t /templates/
```

> [!IMPORTANT]
> **Windows Note:** On Windows, always build with the `.exe` extension (`-o idoraider.exe`). If built without `.exe`, Windows will not recognize it as an executable and will show an "Open with..." dialog. To run it, use `.\idoraider.exe`.

---

### 2. Practice Lab (Test Locally)

IDORaider includes a self-contained mock vulnerable API for offline practice and verification:

1. **Start the mock server:**
   ```powershell
   go run ./cmd/idoraider-lab
   ```
2. **In a second terminal, run IDORaider against it:**
   ```powershell
   .\idoraider.exe -u http://127.0.0.1:8888 -t templates/ --token "token_alice" --secondary-token "token_bob"
   ```
   *Watch IDORaider accurately identify BOLA leaks on `/api/v1/users/` and `/api/v1/invoices/`, while verifying `/api/v1/admin/` is properly restricted (403 Forbidden).*

---

### 3. Usage Examples

#### Single-Token Mode (ID Enumeration)
Test candidate IDs using your own authorized user token:

* **Linux / macOS:**
  ```bash
  ./idoraider -u https://api.target.com -t templates/ -c 20 --token "YOUR_PRIMARY_JWT_TOKEN"
  ```
* **Windows (PowerShell):**
  ```powershell
  .\idoraider.exe -u https://api.target.com -t templates/ -c 20 --token "YOUR_PRIMARY_JWT_TOKEN"
  ```

#### Dual-Token Mode (Owner vs. Other — Recommended)
The gold standard for BOLA testing. Supply two separate test accounts you control:

* **Linux / macOS:**
  ```bash
  ./idoraider -u https://api.target.com -t templates/ -c 20 --token "ACCOUNT_A_OWNER_TOKEN" --secondary-token "ACCOUNT_B_OTHER_TOKEN"
  ```
* **Windows (PowerShell):**
  ```powershell
  .\idoraider.exe -u https://api.target.com -t templates/ -c 20 --token "ACCOUNT_A_OWNER_TOKEN" --secondary-token "ACCOUNT_B_OTHER_TOKEN"
  ```

#### Routing Through Burp Suite / OWASP ZAP
Inspect all outbound probes directly in your interception proxy:

* **Linux / macOS:**
  ```bash
  ./idoraider -u https://api.target.com -t templates/ --token "TOKEN_A" --secondary-token "TOKEN_B" -x http://127.0.0.1:8080 -k
  ```
* **Windows (PowerShell):**
  ```powershell
  .\idoraider.exe -u https://api.target.com -t templates/ --token "TOKEN_A" --secondary-token "TOKEN_B" -x http://127.0.0.1:8080 -k
  ```

---

## Key Capabilities

* 🔒 **Owner-vs-Other Dual Token Replay**: Automatically proves authorization bypass with two test tokens.
* 🚦 **Redirect Loop Protection**: Does not follow 302 redirects by default, preventing false-positive login pages from triggering alerts.
* 🛡️ **Burp Suite & ZAP Ready**: Route traffic through proxies with `-x` and ignore self-signed certificates with `-k`.
* ⚡ **Zero External Dependencies**: Pure Go standard library. Easy build on Linux, macOS, and Windows.
* 🎛️ **Runtime Candidate ID Override**: Inject target-specific UUIDs or numeric ranges on the fly using `--ids`.
* ⏱️ **Rate Limiting & Delay**: Prevent WAF rate-limiting and account lockout with `-d / --delay`.
* 📊 **Multi-Format Output**: Automatically generates both timestamped structured JSON and ready-to-report GitHub Flavored Markdown files.

---

## Terminal Output Preview

```text
 ██╗██████╗  ██████╗ ██████╗  █████╗ ██╗██████╗ ███████╗██████╗ 
 ██║██╔══██╗██╔═══██╗██╔══██╗██╔══██╗██║██╔══██╗██╔════╝██╔══██╗
 ██║██║  ██║██║   ██║██████╔╝███████║██║██║  ██║█████╗  ██████╔╝
 ██║██║  ██║██║   ██║██╔══██╗██╔══██║██║██║  ██║██╔══╝  ██╔══██╗
 ██║██████╔╝╚██████╔╝██║  ██║██║  ██║██║██████╔╝███████╗██║  ██║
 ╚═╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝

       HUNTING BROKEN ACCESS CONTROL                      v1.0.0

  Go-based BOLA/IDOR Vulnerability Scanner
  Author      : Jojin John
  Language    : Go
  Purpose     : Find IDOR / BOLA vulnerabilities
  Mode        : Template-based scanning
  Target      : https://api.target.com
  Templates   : templates/
  Concurrency : 20
  Time        : 2026-10-31 16:30:00

[16:30:00] [INF] Loaded 10 YAML templates from templates/
[16:30:00] [INF] Target: https://api.target.com
[16:30:00] [INF] Concurrency: 20 workers
[16:30:00] [INF] Beginning scan...

PROGRESS   #     CODE   STATUS           SEVERITY     ENDPOINT                                           RESULT
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
[1/42]     1     200    VULNERABLE       CRITICAL     https://api.target.com/api/v1/users/2              HTTP 200: Resource id=2 accessible with sensitive keywords
[2/42]     2     403    RESTRICTED       -            https://api.target.com/api/v1/admin/2              HTTP 403: Forbidden (access restricted)
[3/42]     3     404    NOT FOUND        -            https://api.target.com/api/v1/invoices/999         HTTP 404: Endpoint not found
──────────────────────────────────────────────────────────────────────
✓ Scan completed in 1.42s
  42 endpoints tested   1 vulnerable   1 critical   0 high   0 medium   0 low   41 not vulnerable
──────────────────────────────────────────────────────────────────────
[16:30:02] [INF] JSON report: results/2026-10-31_163002.json
[16:30:02] [INF] Markdown report: results/2026-10-31_163002.md
```

---

## CLI Reference

| Flag | Default | Description |
|---|---|---|
| `-u`, `--url` | *(required)* | Target base URL (e.g. `https://api.target.com`) |
| `-t` | `templates/` | Directory containing YAML scan templates |
| `-c` | `20` | Concurrent worker routines |
| `--token` | `$IDORAIDER_TOKEN` | Primary authentication token (owner account) |
| `--secondary-token` | `$IDORAIDER_SECONDARY_TOKEN` | Secondary authentication token (attacker / lower-priv account) |
| `--auth-header` | `Authorization` | Header used to send the token |
| `--auth-scheme` | `Bearer` | Prefix before the token (`""` for raw token/cookies) |
| `-H`, `--header` | — | Custom HTTP request header (`'Key: Value'`), repeatable |
| `-x`, `--proxy` | — | HTTP/HTTPS/SOCKS5 proxy (e.g. `http://127.0.0.1:8080`) |
| `-k`, `--insecure` | `false` | Skip TLS certificate verification (useful for Burp Suite) |
| `--follow-redirects` | `false` | Follow HTTP redirects (default false to prevent false positives) |
| `-d`, `--delay` | `0s` | Delay between requests for rate limiting (e.g. `50ms`, `1s`) |
| `--ids` | — | Comma-separated list of IDs to probe, overriding template defaults |
| `--timeout` | `10` | Per-request timeout in seconds |
| `-o` | `results/` | Output directory for JSON and Markdown reports |
| `--silent` | `false` | Only print vulnerable findings and final summary |
| `--no-banner` | `false` | Suppress startup banner |

> [!TIP]
> **CI/CD Integration:** IDORaider exits with code `3` if any vulnerability is detected, and `0` when clean, making it simple to break builds on authorization regressions.

---

## Writing Scan Templates

Templates are defined in readable YAML files located in `templates/*.yaml`. Zero external YAML dependencies are required — IDORaider includes a fast, native parser.

### Template Syntax

```yaml
id: idor-user-profile
name: User Profile IDOR
severity: critical
description: User profile accessible with a modified ID
method: GET
path: /api/v1/users/{id}
headers:
  Authorization: Bearer {token}
  Accept: application/json
ids:
  - 1
  - 2
  - 3
  - 123
match_status:
  - 200
match_not_status:
  - 401
  - 403
  - 404
match_condition: all
match_words:
  - email
  - username
```

### Condition & Matching Logic

| Field | Type | Description |
|---|---|---|
| `path` | `string` | Target endpoint path. `{id}` is replaced with candidate IDs. |
| `headers` | `map` | Request headers. `{token}` is dynamically substituted with the active replay token. |
| `ids` | `list` | Candidate ID values to substitute into `{id}`. |
| `match_status` | `list[int]` | HTTP status codes considered an accessible response (default: `[200]`). |
| `match_not_status` | `list[int]` | HTTP status codes considered restricted/non-vulnerable (negative match). |
| `match_condition` | `string` | Keyword evaluation mode: `any` (default, matches if ANY keyword is found) or `all` (requires ALL keywords). |
| `match_words` | `list[string]` | Substrings that must appear in the response body to confirm data exposure. |

### Included Starter Templates

IDORaider comes pre-packaged with 14 templates covering high-impact attack surfaces:

1. `idor-user-profile.yaml` — User profiles, emails, usernames
2. `idor-admin.yaml` — Administrative control endpoints
3. `idor-order-access.yaml` — E-commerce orders & shipping records
4. `idor-invoice.yaml` — Financial invoices & billing details
5. `idor-message.yaml` — Private direct messages
6. `idor-file.yaml` — Uploaded documents & file storage
7. `idor-project.yaml` — Multi-tenant project data
8. `idor-team.yaml` — Team rosters & workspaces
9. `idor-comment.yaml` — User comments & edit permissions
10. `idor-report.yaml` — Internal generated analytics & exports
11. `idor-uuid.yaml` — UUIDv4-based object identifier enumeration
12. `idor-delete.yaml` — Unauthorized object deletion (DELETE method)
13. `idor-password-reset.yaml` — Sensitive password reset token exposure
14. `idor-payment-method.yaml` — Customer payment methods & wallet data

---

## Architecture & Replay Flow

```mermaid
flowchart TD
    CLI["CLI Input<br/>-u target --token A --secondary-token B"] --> LOAD["Template Loader<br/>(templates/*.yaml)"]
    LOAD --> QUEUE["Probe Dispatcher<br/>Worker Pool (-c Concurrency)"]

    subgraph Replay Engine
        QUEUE --> REQ1["1. Request with Owner Token A"]
        REQ1 --> CHK1{"Owner Access<br/>Valid?"}
        CHK1 -- Yes --> REQ2["2. Replay with Secondary Token B"]
        CHK1 -- No --> SKIP["Not Accessible / Inconclusive"]
        REQ2 --> CHK2{"Secondary Access<br/>Granted?"}
        CHK2 -- Yes --> VULN["🚨 VULNERABLE: BOLA Confirmed"]
        CHK2 -- No --> SAFE["✅ NOT VULNERABLE: Restricted"]
    end

    VULN --> REP["Report Generator"]
    SAFE --> REP
    SKIP --> REP

    REP --> JSON["results/*.json"]
    REP --> MD["results/*.md"]
```

---

## Reporting

Reports are saved to `results/` after every run:

1. **JSON Report (`results/*.json`)**: Full programmatic audit data with timestamps, HTTP status codes, request URLs, and exact vulnerability details.
2. **Markdown Report (`results/*.md`)**: Clean GitHub Flavored Markdown summary with status badges and finding tables ready for pentest deliverables and bug bounty submissions.

---

## Contributing

Contributions, template submissions, and feature suggestions are welcome! Please check out our [Contributing Guidelines](CONTRIBUTING.md) to get started.

## Security Policy

If you discover a security issue or vulnerability, please consult our [Security Policy](SECURITY.md) for responsible disclosure.

## Code of Conduct

This project is governed by the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).

---

## Developer

<p align="left">
  <img src="./assets/icon.png" width="68" height="71" alt="IDORaider Icon" align="left" style="margin-right: 16px; border-radius: 12px;">
  <strong>Developed with ❤️ by JOJIN JOHN.</strong><br>
  Security Researcher & Software Engineer<br>
  GitHub: <a href="https://github.com/jojin1709">@jojin1709</a> &bull; Project: <a href="https://github.com/jojin1709/idoraider">IDORaider</a>
</p>
<br clear="left">

---

## License

This project is licensed under the [MIT License](LICENSE).
