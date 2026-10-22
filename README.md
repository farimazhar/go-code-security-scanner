# GoSentry - Go Code Security Scanner (SAST)

A high-performance, zero-dependency Go Static Application Security Testing (SAST) scanner and analyzer. Scans Go source code for critical security vulnerabilities, bad practices, and potential exploits.

## 🚀 Key Features

- **14 Built-in SAST Rules**: Detects SQL injection, command injection, hardcoded credentials, cloud API keys, insecure TLS, weak cryptography, unbounded reads (DoS), weak random generators, unchecked type assertions, path traversal, goroutine leaks, and SSRF.
- **One-Click Quick Fix**: Automatically patches vulnerable code in the editor with secure alternatives.
- **Line-Level Pinpointing & Jump**: Accurately pinpoints line numbers and code snippets; click a finding to jump straight to the line.
- **Security Audit Reports**: Export comprehensive reports in Markdown (`.md`), JSON, or copy summaries to clipboard.
- **Drag-and-Drop File Scanning**: Drop any local `.go` file directly into the browser.
- **Actionable Remediation Guidance**: Every detected issue includes recommended fixes and best practices.
- **Robust Comment Filter**: Tokenizer ignores single-line (`//`) and multi-line (`/* ... */`) comments while preserving string literals and exact line counts.
- **Three Modes of Operation**:
  1. **Serverless HTTP API**: Deployable directly to Vercel or cloud functions (`api/scan.go`).
  2. **Standalone Local Server & Web Playground**: Interactive dark-mode web UI for live testing (`cmd/server`).
  3. **Standalone CLI Tool**: Terminal file & recursive directory scanner with CI/CD score gates (`cmd/cli`).
- **100% Pure Go**: Zero third-party dependencies; uses only standard Go libraries.


---

## 🛡️ Supported Detection Rules

| Rule ID | Severity | Deduction | Description |
| :--- | :--- | :--- | :--- |
| `sql_concat` | **CRITICAL** | -35 | SQL Injection via string concatenation (`db.Query("..." + id)`) |
| `sql_sprintf` | **HIGH** | -25 | Possible SQL Injection via formatted string (`fmt.Sprintf`) |
| `cmd_injection` | **CRITICAL** | -35 | Command Injection in `exec.Command` / `exec.CommandContext` |
| `cloud_secret` | **CRITICAL** | -35 | Exposed AWS keys (`AKIA...`), Private Keys (`BEGIN PRIVATE KEY`), or JWT tokens |
| `hardcoded_secret` | **CRITICAL** | -30 | Hardcoded passwords, API keys, or tokens (`password = "..."`) |
| `insecure_tls` | **CRITICAL** | -30 | Insecure TLS certificate verification disabled (`InsecureSkipVerify: true`) |
| `weak_crypto` | **HIGH** | -20 | Use of weak cryptographic algorithms (`md5`, `sha1`, `des`) |
| `unbounded_read` | **HIGH** | -20 | Unbounded read on HTTP request body (`io.ReadAll(r.Body)` DoS risk) |
| `weak_random` | **HIGH** | -20 | Weak pseudo-random number generator (`math/rand` in security context) |
| `unchecked_type_assert` | **MEDIUM** | -15 | Unchecked type assertion without comma-ok idiom (runtime panic risk) |
| `path_traversal` | **HIGH** | -25 | File operations with unvalidated string concatenation (`os.ReadFile`) |
| `open_redirect_ssrf` | **MEDIUM** | -15 | HTTP request with dynamic URL concatenation (`http.Get`) |
| `db_no_err_check` | **CRITICAL** | -25 | Database query without verifying the error response |
| `goroutine_no_context` | **HIGH** | -20 | Goroutine leak risk (`go func()` without cancellation context) |

---


## 📡 API Usage

### Endpoint: `POST /api/scan`

**Request Headers:** `Content-Type: application/json`

**Request Body:**
```json
{
  "code": "func Run(id string) { db.Query(\"SELECT * FROM users WHERE id = \" + id) }"
}
```

**Response Payload:**
```json
{
  "score": 65,
  "status": "RISKY",
  "issues": [
    "CRITICAL: SQL Injection via string concat"
  ],
  "findings": [
    {
      "rule_id": "sql_concat",
      "severity": "CRITICAL",
      "title": "SQL Injection via String Concatenation",
      "description": "CRITICAL: SQL Injection via string concat",
      "line": 1,
      "snippet": "func Run(id string) { db.Query(\"SELECT * FROM users WHERE id = \" + id) }",
      "remedy": "Use parameterized queries with placeholder arguments ($1, ?, etc.) instead of concatenating strings into SQL queries."
    }
  ],
  "stats": {
    "critical_issues": 1,
    "findings_count": 1,
    "high_issues": 0,
    "lines": 1,
    "low_issues": 0,
    "medium_issues": 0
  }
}
```

---

## 💻 CLI Scanner

Scan a single Go file, an entire directory tree, or piped code directly from your terminal:

```bash
# Scan current directory recursively
go run ./cmd/cli .

# Scan specific directory or file
go run ./cmd/cli ./api/

# Output JSON for CI/CD pipelines
go run ./cmd/cli -format json ./api/

# Enforce a minimum score gate (fails with exit code 1 if score < 80)
go run ./cmd/cli -min-score 80 ./api/

# Pipe code via stdin
cat main.go | go run ./cmd/cli
```

---

## 🌐 Local Server & Web Playground

Start the local server to access the live API and interactive web UI:

```bash
go run ./cmd/server
```

Open your browser to:
- **Web UI Playground:** `http://localhost:8080/`
- **Scan API:** `http://localhost:8080/api/scan`
- **Health Check:** `http://localhost:8080/health`

---

## 🧪 Running Tests

```bash
go test -v ./...
```

---

## 📂 Project Structure

```text
go-code-security-scanner/
├── api/
│   ├── scan.go          # Core scanner engine, rules, comment tokenizer, and HTTP handler
│   └── scan_test.go     # Comprehensive unit tests for all SAST rules and comment stripping
├── cmd/
│   ├── cli/
│   │   └── main.go      # Standalone terminal CLI scanner
│   └── server/
│       ├── main.go      # Standalone HTTP server
│       └── index_fallback.html # Embedded web UI fallback
├── public/
│   └── index.html       # Modern dark-mode web playground UI
├── go.mod               # Standard Go module definition
└── README.md            # Documentation
```
