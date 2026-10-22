package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStripComments(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "single line comment",
			input:    "var a = 1 // this is a comment\nvar b = 2",
			expected: "var a = 1 \nvar b = 2",
		},
		{
			name:     "multi line block comment",
			input:    "var a = /* block comment */ 1\nvar b = 2",
			expected: "var a =  1\nvar b = 2",
		},
		{
			name:     "preserve string literals with slashes",
			input:    `var url = "http://example.com/api" // ignore this`,
			expected: "var url = \"http://example.com/api\" ",
		},
		{
			name:     "preserve raw string literals",
			input:    "var query = `SELECT * FROM users // not a comment`\n// comment",
			expected: "var query = `SELECT * FROM users // not a comment`\n",
		},
		{
			name:     "escaped quotes in strings",
			input:    `var s = "escaped \" quote // not comment" // comment`,
			expected: `var s = "escaped \" quote // not comment" `,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := StripComments(tc.input)
			if got != tc.expected {
				t.Errorf("StripComments() mismatch.\nGot:      %q\nExpected: %q", got, tc.expected)
			}
		})
	}
}

func TestScanCode_Safe(t *testing.T) {
	safeCode := `package main

import (
	"context"
	"database/sql"
	"fmt"
)

func getUser(ctx context.Context, db *sql.DB, id int) error {
	row := db.QueryRowContext(ctx, "SELECT name FROM users WHERE id = $1", id)
	var name string
	err := row.Scan(&name)
	if err != nil {
		return err
	}
	fmt.Println(name)
	return nil
}
`
	res := ScanCode(safeCode)
	if res.Score != 100 {
		t.Errorf("Expected score 100, got %d", res.Score)
	}
	if res.Status != "SAFE" {
		t.Errorf("Expected status SAFE, got %s", res.Status)
	}
	if len(res.Issues) != 1 || !strings.Contains(res.Issues[0], "SAFE") {
		t.Errorf("Unexpected issues for safe code: %v", res.Issues)
	}
	if len(res.Findings) != 0 {
		t.Errorf("Expected 0 findings for safe code, got %d", len(res.Findings))
	}
}

func TestScanCode_NewVulnerabilityRules(t *testing.T) {
	testCases := []struct {
		name         string
		code         string
		expectedRule string
		minDeduction int
	}{
		{
			name: "Command Injection via Concat",
			code: `package main
import "os/exec"
func run(arg string) {
	exec.Command("sh", "-c", "echo " + arg)
}`,
			expectedRule: "cmd_injection",
			minDeduction: 35,
		},
		{
			name: "Insecure TLS Skip Verify",
			code: `package main
import "crypto/tls"
func conf() {
	cfg := &tls.Config{
		InsecureSkipVerify: true,
	}
	_ = cfg
}`,
			expectedRule: "insecure_tls",
			minDeduction: 30,
		},
		{
			name: "Weak Crypto MD5",
			code: `package main
import "crypto/md5"
func hash(s []byte) {
	h := md5.New()
	h.Write(s)
}`,
			expectedRule: "weak_crypto",
			minDeduction: 20,
		},
		{
			name: "Path Traversal Concat",
			code: `package main
import "os"
func read(filename string) {
	os.ReadFile("/var/data/" + filename)
}`,
			expectedRule: "path_traversal",
			minDeduction: 25,
		},
		{
			name: "Cloud Secret AWS Key",
			code: `package main
var awsKey = "AKIA1234567890ABCDEF"
`,
			expectedRule: "cloud_secret",
			minDeduction: 35,
		},
		{
			name: "SSRF Dynamic HTTP Get",
			code: `package main
import "net/http"
func fetch(domain string) {
	http.Get("https://" + domain)
}`,
			expectedRule: "open_redirect_ssrf",
			minDeduction: 15,
		},
		{
			name: "Unbounded Read on Body",
			code: `package main
import (
	"io"
	"net/http"
)
func handle(w http.ResponseWriter, r *http.Request) {
	data, _ := io.ReadAll(r.Body)
	_ = data
}`,
			expectedRule: "unbounded_read",
			minDeduction: 20,
		},
		{
			name: "Weak Random in Token Generator",
			code: `package main
import "math/rand"
func makeToken() int {
	return rand.Int()
}`,
			expectedRule: "weak_random",
			minDeduction: 20,
		},
		{
			name: "Unchecked Type Assertion",
			code: `package main
func process(i interface{}) {
	val := i.(string)
	_ = val
}`,
			expectedRule: "unchecked_type_assert",
			minDeduction: 15,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res := ScanCode(tc.code)
			found := false
			for _, f := range res.Findings {
				if f.RuleID == tc.expectedRule {
					found = true
					if f.Line == 0 {
						t.Errorf("Finding for %s has line 0", tc.expectedRule)
					}
					if f.Remedy == "" {
						t.Errorf("Finding for %s is missing remedy guidance", tc.expectedRule)
					}
					break
				}
			}
			if !found {
				t.Errorf("Expected rule %q to trigger for code:\n%s\nGot findings: %+v", tc.expectedRule, tc.code, res.Findings)
			}
			if res.Score > 100-tc.minDeduction {
				t.Errorf("Expected score <= %d, got %d", 100-tc.minDeduction, res.Score)
			}
		})
	}
}

func TestScanCode_QuickFixMetadata(t *testing.T) {
	code := `package main
import "crypto/tls"
func conf() {
	cfg := &tls.Config{
		InsecureSkipVerify: true,
	}
	_ = cfg
}
`
	res := ScanCode(code)
	var tlsFinding *Finding
	for _, f := range res.Findings {
		if f.RuleID == "insecure_tls" {
			tlsFinding = &f
			break
		}
	}

	if tlsFinding == nil {
		t.Fatalf("Expected insecure_tls finding")
	}

	if tlsFinding.FixTarget != "InsecureSkipVerify: true" {
		t.Errorf("Expected fix target 'InsecureSkipVerify: true', got %q", tlsFinding.FixTarget)
	}
	if tlsFinding.FixReplace != "InsecureSkipVerify: false" {
		t.Errorf("Expected fix replace 'InsecureSkipVerify: false', got %q", tlsFinding.FixReplace)
	}
}

func TestHandler_PostValid(t *testing.T) {
	payload := map[string]string{
		"code": `package main; func main() { println("hello") }`,
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/scan", bytes.NewBuffer(body))
	w := httptest.NewRecorder()

	Handler(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 OK on POST, got %d", resp.StatusCode)
	}

	var res Response
	if err := json.NewDecoder(w.Body).Decode(&res); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if res.Score != 100 || res.Status != "SAFE" {
		t.Errorf("Expected score 100 & SAFE, got %d & %s", res.Score, res.Status)
	}
}
