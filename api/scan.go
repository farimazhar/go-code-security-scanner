package handler

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
)

type Response struct {
	Score  int      `json:"score"`
	Status string   `json:"status"`
	Issues []string `json:"issues"`
	Stats  map[string]int `json:"stats"`
}

func Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	if r.Method == "OPTIONS" { w.WriteHeader(200); return }

	var req struct{ Code string `json:"code"` }
	json.NewDecoder(r.Body).Decode(&req)
	code := req.Code

	score := 100
	issues := []string{}
	stats := map[string]int{"lines": len(strings.Split(code, "\n"))}

	checks := map[string]struct{
		pattern string
		msg string
		deduct int
	}{
		"sql": {`db\.Query\(.*\+`, "CRITICAL: SQL Injection via string concat", 35},
		"secret": {`(?i)(password|api_key|secret)\s*=\s*".+"`, "CRITICAL: Hardcoded secret detected", 30},
		"err": {`db\.(Query|Exec)\(`, "HIGH: DB call without error handling", 20},
		"context": {`func.*\(.*\)`, "MEDIUM: Consider context.Context for cancellation", 10},
	}

	if strings.Contains(code, "db.Query") && !strings.Contains(code, "err") {
		issues = append(issues, "CRITICAL: DB without error check")
		score -= 25
	}
	if regexp.MustCompile(`(?i)password.*=.*".+"`).MatchString(code) {
		issues = append(issues, "CRITICAL: Hardcoded password")
		score -= 30
	}
	if strings.Contains(code, "go func()") && !strings.Contains(code, "context") {
		issues = append(issues, "HIGH: Goroutine leak risk - no context")
		score -= 20
	}
	if strings.Contains(code, "fmt.Sprintf") && strings.Contains(code, "Query") {
		issues = append(issues, "HIGH: Possible SQL Injection")
		score -= 25
	}

	if len(issues) == 0 {
		issues = append(issues, "✅ SAFE - No critical vulnerabilities")
	}
	if score < 0 { score = 0 }
	status := "SAFE"
	if score < 70 { status = "RISKY" }
	if score < 40 { status = "UNSAFE" }

	json.NewEncoder(w).Encode(Response{score, status, issues, stats})
}
