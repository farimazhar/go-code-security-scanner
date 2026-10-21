package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	handler "go-ai-guard/api"
)

//go:embed index_fallback.html
var defaultIndexHTML []byte

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mux := http.NewServeMux()

	// API scan endpoint
	mux.HandleFunc("/api/scan", handler.Handler)

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":      "ok",
			"service":     "GoSentry Security Scanner",
			"rules_count": len(handler.DefaultRules),
			"version":     "2.0.0",
		})
	})

	// Static Assets & UI Playground
	if _, err := os.Stat("public"); err == nil {
		fileServer := http.FileServer(http.Dir("public"))
		mux.Handle("/", fileServer)
	} else {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(defaultIndexHTML)
		})
	}

	addr := ":" + port
	fmt.Printf("====================================================\n")
	fmt.Printf("🛡️  GoSentry Security Scanner Server Running\n")
	fmt.Printf("   URL: http://localhost%s/\n", addr)
	fmt.Printf("   API: http://localhost%s/api/scan\n", addr)
	fmt.Printf("   Health: http://localhost%s/health\n", addr)
	fmt.Printf("   Active Rules: %d\n", len(handler.DefaultRules))
	fmt.Printf("====================================================\n")

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
