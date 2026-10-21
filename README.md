# GoSentry - Go Code Security Scanner (Pure Go)

A lightweight Go API that scans Go code for security vulnerabilities. Built for Vercel Serverless.

**Live API:** `https://go-ai-guard.vercel.app/api/scan`

## What it does
- Detects SQL Injection (`db.Query("..." + id)`)
- Detects Hardcoded Secrets
- Detects Goroutine leak risk
- Ignores comments to avoid fake results

## How to use

**POST /api/scan**
```bash
curl -X POST https://go-ai-guard.vercel.app/api/scan \
-H "Content-Type: application/json" \
-d '{"code": "func GetUser(id string) { db.Query(\"SELECT * FROM users WHERE id = \"+id) }"}'
