package handler

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
)

// Finding represents a detailed vulnerability finding.
type Finding struct {
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	Title       string `json:"title"`
	Description string `json:"description"`
	Line        int    `json:"line"`
	Snippet     string `json:"snippet"`
	Remedy      string `json:"remedy"`
	FixTarget   string `json:"fix_target,omitempty"`
	FixReplace  string `json:"fix_replace,omitempty"`
}

// Response represents the security scan result payload.
type Response struct {
	Score    int            `json:"score"`
	Status   string         `json:"status"` // SAFE, RISKY, UNSAFE
	Issues   []string       `json:"issues"`  // Legacy string issues (backwards compatible)
	Findings []Finding      `json:"findings,omitempty"`
	Stats    map[string]int `json:"stats"`
}

// Rule defines a static security rule to be evaluated against code.
type Rule struct {
	ID          string
	Severity    string
	Title       string
	Description string
	Deduct      int
	Remedy      string
	Fixer       func(line string) (string, string)
	Check       func(cleanCode string, originalLines []string, cleanLines []string) (bool, int, string)
}

var (
	reSQLConcat           = regexp.MustCompile(`db\.(Query|QueryRow|Exec)\(.*\+`)
	reSQLSprintf          = regexp.MustCompile(`(?i)db\.(Query|QueryRow|Exec)\(.*fmt\.Sprintf`)
	reHardcodedSecret     = regexp.MustCompile(`(?i)(password|api_key|secret|token|access_key)\s*[:=]+\s*["'][^"']+["']`)
	reCloudSecret         = regexp.MustCompile(`(AKIA[0-9A-Z]{16}|-----BEGIN (?:RSA |EC )?PRIVATE KEY-----|eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})`)
	reCmdConcat           = regexp.MustCompile(`exec\.(Command|CommandContext)\([^)]*\+`)
	reCmdSprintf          = regexp.MustCompile(`(?i)exec\.(Command|CommandContext)\([^)]*fmt\.Sprintf`)
	reInsecureTLS         = regexp.MustCompile(`InsecureSkipVerify\s*:\s*true`)
	reWeakCrypto          = regexp.MustCompile(`(md5\.(New|Sum)|sha1\.(New|Sum)|des\.NewCipher)`)
	rePathTraversal       = regexp.MustCompile(`os\.(Open|OpenFile|ReadFile|WriteFile|Create)\([^)]*\+`)
	reSSRF                = regexp.MustCompile(`http\.(Get|Post|Head)\([^)]*\+`)
	reUnboundedRead       = regexp.MustCompile(`(io|ioutil)\.ReadAll\(\s*(r\.Body|req\.Body)`)
	reWeakRandom          = regexp.MustCompile(`(rand\.Int|rand\.Intn|rand\.Read|rand\.Float)\(`)
	reUncheckedTypeAssert = regexp.MustCompile(`[a-zA-Z0-9_]+\s*:=\s*[a-zA-Z0-9_]+\.\([a-zA-Z0-9_.*]+\)`)
)

func matchLineRegex(re *regexp.Regexp, cleanLines, originalLines []string) (bool, int, string) {
	for i, cLine := range cleanLines {
		if re.MatchString(cLine) {
			snippet := ""
			if i < len(originalLines) {
				snippet = strings.TrimSpace(originalLines[i])
			}
			return true, i + 1, snippet
		}
	}
	return false, 0, ""
}

// DefaultRules contains all security rules evaluated by ScanCode.
var DefaultRules = []Rule{
	{
		ID:          "sql_concat",
		Severity:    "CRITICAL",
		Title:       "SQL Injection via String Concatenation",
		Description: "CRITICAL: SQL Injection via string concat",
		Deduct:      35,
		Remedy:      "Use parameterized queries with placeholder arguments ($1, ?, etc.) instead of concatenating strings into SQL queries.",
		Fixer: func(line string) (string, string) {
			if strings.Contains(line, " + ") {
				return line, strings.Replace(line, " + ", ", ", 1)
			}
			return "", ""
		},
		Check: func(cleanCode string, originalLines, cleanLines []string) (bool, int, string) {
			return matchLineRegex(reSQLConcat, cleanLines, originalLines)
		},
	},
	{
		ID:          "sql_sprintf",
		Severity:    "HIGH",
		Title:       "Possible SQL Injection via Formatted String",
		Description: "HIGH: Possible SQL Injection via formatted string",
		Deduct:      25,
		Remedy:      "Pass query parameters as direct arguments to db.Query/QueryRow rather than formatting query strings with fmt.Sprintf.",
		Check: func(cleanCode string, originalLines, cleanLines []string) (bool, int, string) {
			matched, line, snip := matchLineRegex(reSQLSprintf, cleanLines, originalLines)
			if matched {
				return true, line, snip
			}
			for i, cLine := range cleanLines {
				if strings.Contains(cLine, "fmt.Sprintf") && strings.Contains(cLine, "Query") {
					snippet := ""
					if i < len(originalLines) {
						snippet = strings.TrimSpace(originalLines[i])
					}
					return true, i + 1, snippet
				}
			}
			return false, 0, ""
		},
	},
	{
		ID:          "cmd_injection",
		Severity:    "CRITICAL",
		Title:       "Command Injection in exec.Command",
		Description: "CRITICAL: Potential Command Injection in exec.Command",
		Deduct:      35,
		Remedy:      "Pass arguments as separate command line elements to exec.Command rather than concatenating user input or using shell wrappers.",
		Check: func(cleanCode string, originalLines, cleanLines []string) (bool, int, string) {
			if matched, line, snip := matchLineRegex(reCmdConcat, cleanLines, originalLines); matched {
				return true, line, snip
			}
			return matchLineRegex(reCmdSprintf, cleanLines, originalLines)
		},
	},
	{
		ID:          "cloud_secret",
		Severity:    "CRITICAL",
		Title:       "Exposed Cloud Secret, Private Key, or JWT",
		Description: "CRITICAL: Exposed AWS key, Private Key, or JWT token",
		Deduct:      35,
		Remedy:      "Immediately revoke this secret and manage sensitive credentials using environment variables or a secrets manager.",
		Check: func(cleanCode string, originalLines, cleanLines []string) (bool, int, string) {
			return matchLineRegex(reCloudSecret, cleanLines, originalLines)
		},
	},
	{
		ID:          "hardcoded_secret",
		Severity:    "CRITICAL",
		Title:       "Hardcoded Secret or Credential",
		Description: "CRITICAL: Hardcoded secret detected",
		Deduct:      30,
		Remedy:      "Load sensitive credentials from environment variables (os.Getenv) or secure vaults instead of hardcoding them in source code.",
		Check: func(cleanCode string, originalLines, cleanLines []string) (bool, int, string) {
			return matchLineRegex(reHardcodedSecret, cleanLines, originalLines)
		},
	},
	{
		ID:          "insecure_tls",
		Severity:    "CRITICAL",
		Title:       "Insecure TLS Verification Disabled",
		Description: "CRITICAL: InsecureSkipVerify is set to true",
		Deduct:      30,
		Remedy:      "Do not disable TLS verification in production. It exposes traffic to Man-in-the-Middle (MITM) attacks. Configure custom trusted CAs if needed.",
		Fixer: func(line string) (string, string) {
			if strings.Contains(line, "InsecureSkipVerify: true") {
				return "InsecureSkipVerify: true", "InsecureSkipVerify: false"
			}
			return "", ""
		},
		Check: func(cleanCode string, originalLines, cleanLines []string) (bool, int, string) {
			return matchLineRegex(reInsecureTLS, cleanLines, originalLines)
		},
	},
	{
		ID:          "weak_crypto",
		Severity:    "HIGH",
		Title:       "Weak Cryptographic Algorithm Detected",
		Description: "HIGH: Use of weak hash or cipher (MD5, SHA-1, DES)",
		Deduct:      20,
		Remedy:      "MD5, SHA-1, and DES are vulnerable to collision and attack. Use crypto/sha256, crypto/sha512, or crypto/aes (GCM mode).",
		Fixer: func(line string) (string, string) {
			if strings.Contains(line, "md5.New()") {
				return "md5.New()", "sha256.New()"
			}
			if strings.Contains(line, "sha1.New()") {
				return "sha1.New()", "sha256.New()"
			}
			return "", ""
		},
		Check: func(cleanCode string, originalLines, cleanLines []string) (bool, int, string) {
			return matchLineRegex(reWeakCrypto, cleanLines, originalLines)
		},
	},
	{
		ID:          "unbounded_read",
		Severity:    "HIGH",
		Title:       "Unbounded Read on HTTP Request Body (DoS Risk)",
		Description: "HIGH: io.ReadAll on request body without length limit",
		Deduct:      20,
		Remedy:      "Limit the maximum bytes read from HTTP requests using http.MaxBytesReader or io.LimitReader to protect against resource exhaustion.",
		Fixer: func(line string) (string, string) {
			if strings.Contains(line, "io.ReadAll(r.Body)") {
				return "io.ReadAll(r.Body)", "io.ReadAll(io.LimitReader(r.Body, 10<<20)) // 10MB limit"
			}
			return "", ""
		},
		Check: func(cleanCode string, originalLines, cleanLines []string) (bool, int, string) {
			return matchLineRegex(reUnboundedRead, cleanLines, originalLines)
		},
	},
	{
		ID:          "weak_random",
		Severity:    "HIGH",
		Title:       "Weak Random Number Generator (math/rand)",
		Description: "HIGH: math/rand used instead of crypto/rand",
		Deduct:      20,
		Remedy:      "math/rand generates predictable pseudo-random numbers. Use crypto/rand for cryptographic operations, tokens, salts, or passwords.",
		Fixer: func(line string) (string, string) {
			if strings.Contains(line, "math/rand") {
				return "math/rand", "crypto/rand"
			}
			return "", ""
		},
		Check: func(cleanCode string, originalLines, cleanLines []string) (bool, int, string) {
			if strings.Contains(cleanCode, "math/rand") || (strings.Contains(cleanCode, "rand.") && strings.Contains(cleanCode, "token")) {
				return matchLineRegex(reWeakRandom, cleanLines, originalLines)
			}
			return false, 0, ""
		},
	},
	{
		ID:          "unchecked_type_assert",
		Severity:    "MEDIUM",
		Title:       "Unchecked Type Assertion (Runtime Panic Risk)",
		Description: "MEDIUM: Type assertion without comma-ok idiom",
		Deduct:      15,
		Remedy:      "Use the comma-ok idiom (v, ok := x.(Type)) to safely handle unexpected types and avoid runtime panics.",
		Check: func(cleanCode string, originalLines, cleanLines []string) (bool, int, string) {
			return matchLineRegex(reUncheckedTypeAssert, cleanLines, originalLines)
		},
	},
	{
		ID:          "path_traversal",
		Severity:    "HIGH",
		Title:       "Potential Path Traversal in File Operation",
		Description: "HIGH: File operation with string concatenation",
		Deduct:      25,
		Remedy:      "Sanitize and validate paths using filepath.Clean and ensure the target remains within the authorized root directory.",
		Check: func(cleanCode string, originalLines, cleanLines []string) (bool, int, string) {
			return matchLineRegex(rePathTraversal, cleanLines, originalLines)
		},
	},
	{
		ID:          "open_redirect_ssrf",
		Severity:    "MEDIUM",
		Title:       "Potential SSRF or Unvalidated HTTP Request",
		Description: "MEDIUM: HTTP request with dynamic URL concatenation",
		Deduct:      15,
		Remedy:      "Validate URL schemes and whitelist allowed hosts before initiating outbound HTTP requests.",
		Check: func(cleanCode string, originalLines, cleanLines []string) (bool, int, string) {
			return matchLineRegex(reSSRF, cleanLines, originalLines)
		},
	},
	{
		ID:          "db_no_err_check",
		Severity:    "CRITICAL",
		Title:       "Database Operation Without Error Handling",
		Description: "CRITICAL: DB without error check",
		Deduct:      25,
		Remedy:      "Always inspect the returned error from database operations before using results.",
		Check: func(cleanCode string, originalLines, cleanLines []string) (bool, int, string) {
			if strings.Contains(cleanCode, "db.Query") && !strings.Contains(cleanCode, "err") {
				for i, line := range cleanLines {
					if strings.Contains(line, "db.Query") {
						snip := ""
						if i < len(originalLines) {
							snip = strings.TrimSpace(originalLines[i])
						}
						return true, i + 1, snip
					}
				}
				return true, 1, ""
			}
			return false, 0, ""
		},
	},
	{
		ID:          "goroutine_no_context",
		Severity:    "HIGH",
		Title:       "Goroutine Leak Risk Without Context",
		Description: "HIGH: Goroutine leak risk - no context",
		Deduct:      20,
		Remedy:      "Pass a context.Context to background goroutines and listen for ctx.Done() to ensure proper cleanup on cancellation.",
		Check: func(cleanCode string, originalLines, cleanLines []string) (bool, int, string) {
			if strings.Contains(cleanCode, "go func()") && !strings.Contains(cleanCode, "context") {
				for i, line := range cleanLines {
					if strings.Contains(line, "go func()") {
						snip := ""
						if i < len(originalLines) {
							snip = strings.TrimSpace(originalLines[i])
						}
						return true, i + 1, snip
					}
				}
				return true, 1, ""
			}
			return false, 0, ""
		},
	},
}

// StripComments removes single-line (//) and block (/* ... */) comments from Go code
// while preserving string literals and maintaining exact newline counts.
func StripComments(code string) string {
	var sb strings.Builder
	n := len(code)
	i := 0

	for i < n {
		// Raw string literal `...`
		if code[i] == '`' {
			sb.WriteByte(code[i])
			i++
			for i < n && code[i] != '`' {
				sb.WriteByte(code[i])
				i++
			}
			if i < n {
				sb.WriteByte(code[i])
				i++
			}
			continue
		}

		// Double-quoted string literal "..."
		if code[i] == '"' {
			sb.WriteByte(code[i])
			i++
			for i < n {
				if code[i] == '\\' && i+1 < n {
					sb.WriteByte(code[i])
					sb.WriteByte(code[i+1])
					i += 2
					continue
				}
				if code[i] == '"' {
					sb.WriteByte(code[i])
					i++
					break
				}
				sb.WriteByte(code[i])
				i++
			}
			continue
		}

		// Rune literal '...'
		if code[i] == '\'' {
			sb.WriteByte(code[i])
			i++
			for i < n {
				if code[i] == '\\' && i+1 < n {
					sb.WriteByte(code[i])
					sb.WriteByte(code[i+1])
					i += 2
					continue
				}
				if code[i] == '\'' {
					sb.WriteByte(code[i])
					i++
					break
				}
				sb.WriteByte(code[i])
				i++
			}
			continue
		}

		// Single-line comment //...
		if i+1 < n && code[i] == '/' && code[i+1] == '/' {
			i += 2
			for i < n && code[i] != '\n' {
				i++
			}
			if i < n && code[i] == '\n' {
				sb.WriteByte('\n')
				i++
			}
			continue
		}

		// Block comment /* ... */
		if i+1 < n && code[i] == '/' && code[i+1] == '*' {
			i += 2
			for i+1 < n && !(code[i] == '*' && code[i+1] == '/') {
				if code[i] == '\n' {
					sb.WriteByte('\n')
				}
				i++
			}
			if i+1 < n {
				i += 2
			} else {
				i = n
			}
			continue
		}

		sb.WriteByte(code[i])
		i++
	}

	return sb.String()
}

// ScanCode analyzes the provided Go source code and returns a security Response.
func ScanCode(code string) Response {
	cleanCode := StripComments(code)
	originalLines := strings.Split(code, "\n")
	cleanLines := strings.Split(cleanCode, "\n")

	score := 100
	issues := []string{}
	findings := []Finding{}

	critCount, highCount, medCount, lowCount := 0, 0, 0, 0

	for _, rule := range DefaultRules {
		matched, line, snippet := rule.Check(cleanCode, originalLines, cleanLines)
		if matched {
			issues = append(issues, rule.Description)

			fixTarget, fixReplace := "", ""
			if rule.Fixer != nil && snippet != "" {
				fixTarget, fixReplace = rule.Fixer(snippet)
			}

			findings = append(findings, Finding{
				RuleID:      rule.ID,
				Severity:    rule.Severity,
				Title:       rule.Title,
				Description: rule.Description,
				Line:        line,
				Snippet:     snippet,
				Remedy:      rule.Remedy,
				FixTarget:   fixTarget,
				FixReplace:  fixReplace,
			})
			score -= rule.Deduct

			switch rule.Severity {
			case "CRITICAL":
				critCount++
			case "HIGH":
				highCount++
			case "MEDIUM":
				medCount++
			case "LOW":
				lowCount++
			}
		}
	}

	if len(issues) == 0 {
		issues = append(issues, "✅ SAFE - No critical vulnerabilities")
	}

	if score < 0 {
		score = 0
	}

	status := "SAFE"
	if score < 70 {
		status = "RISKY"
	}
	if score < 40 {
		status = "UNSAFE"
	}

	stats := map[string]int{
		"lines":           len(originalLines),
		"findings_count":  len(findings),
		"critical_issues": critCount,
		"high_issues":     highCount,
		"medium_issues":   medCount,
		"low_issues":      lowCount,
	}

	return Response{
		Score:    score,
		Status:   status,
		Issues:   issues,
		Findings: findings,
		Stats:    stats,
	}
}

// Handler handles HTTP requests to the scan endpoint.
func Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed. Use POST."})
		return
	}

	var req struct {
		Code string `json:"code"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON request body"})
		return
	}

	res := ScanCode(req.Code)
	_ = json.NewEncoder(w).Encode(res)
}
