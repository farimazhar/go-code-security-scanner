# GoSentry - Go Code Security Scanner

A pure Go API that scans Go code for security vulnerabilities.

Features:
- SQL Injection detection
- Hardcoded secrets detection
- Ignores comments to avoid fake results
- Pure Go, zero dependencies

How to use:
POST /api/scan with { "code": "your go code" }

Response:
{ "score": 65, "status": "RISKY", "issues": ["CRITICAL: SQL Injection"] }

Structure: go.mod, api/scan.go, README.md
API-only project, no frontend.
