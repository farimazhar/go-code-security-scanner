package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	handler "go-ai-guard/api"
)

type FileScanResult struct {
	Path     string           `json:"path"`
	Response handler.Response `json:"result"`
}

func main() {
	formatFlag := flag.String("format", "text", "Output format: text, json, summary")
	minScoreFlag := flag.Int("min-score", 70, "Minimum acceptable score before failing with non-zero exit code")
	verboseFlag := flag.Bool("v", false, "Verbose output")
	flag.Parse()

	targetPath := "."
	args := flag.Args()
	if len(args) > 0 {
		targetPath = args[0]
	}

	// Check if stdin has data
	stat, _ := os.Stdin.Stat()
	isPipe := (stat.Mode() & os.ModeCharDevice) == 0

	var results []FileScanResult
	failed := false

	if isPipe && len(args) == 0 {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
			os.Exit(1)
		}
		res := handler.ScanCode(string(data))
		results = append(results, FileScanResult{
			Path:     "<stdin>",
			Response: res,
		})
		if res.Score < *minScoreFlag {
			failed = true
		}
	} else {
		// Collect all .go files
		info, err := os.Stat(targetPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error accessing target path %q: %v\n", targetPath, err)
			os.Exit(1)
		}

		var filesToScan []string
		if !info.IsDir() {
			if strings.HasSuffix(targetPath, ".go") {
				filesToScan = append(filesToScan, targetPath)
			}
		} else {
			_ = filepath.Walk(targetPath, func(path string, f os.FileInfo, err error) error {
				if err != nil {
					return nil
				}
				if f.IsDir() {
					name := f.Name()
					if name == ".git" || name == "vendor" || name == "node_modules" {
						return filepath.SkipDir
					}
					return nil
				}
				if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
					filesToScan = append(filesToScan, path)
				}
				return nil
			})
		}

		if len(filesToScan) == 0 {
			fmt.Printf("No Go files found to scan in %q.\n", targetPath)
			return
		}

		for _, file := range filesToScan {
			content, err := os.ReadFile(file)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to read %s: %v\n", file, err)
				continue
			}
			res := handler.ScanCode(string(content))
			results = append(results, FileScanResult{
				Path:     file,
				Response: res,
			})
			if res.Score < *minScoreFlag {
				failed = true
			}
		}
	}

	switch strings.ToLower(*formatFlag) {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)

	case "summary":
		printSummary(results, *minScoreFlag)

	default: // text
		printTextReport(results, *verboseFlag)
		printSummary(results, *minScoreFlag)
	}

	if failed {
		os.Exit(1)
	}
}

func printTextReport(results []FileScanResult, verbose bool) {
	fmt.Println("================================================================================")
	fmt.Println("                        GoSentry Security Scanner Report                        ")
	fmt.Println("================================================================================")

	for _, item := range results {
		res := item.Response
		statusIcon := "🟢"
		if res.Status == "RISKY" {
			statusIcon = "🟡"
		} else if res.Status == "UNSAFE" {
			statusIcon = "🔴"
		}

		fmt.Printf("\n%s File: %s  [Score: %d/100 | Status: %s]\n", statusIcon, item.Path, res.Score, res.Status)

		if len(res.Findings) == 0 {
			fmt.Println("   ✅ No security vulnerabilities detected.")
			continue
		}

		for idx, f := range res.Findings {
			fmt.Printf("   [%d] %s (%s) - Line %d\n", idx+1, f.Title, f.Severity, f.Line)
			if f.Snippet != "" {
				fmt.Printf("       Code:   %s\n", f.Snippet)
			}
			if f.Remedy != "" {
				fmt.Printf("       Remedy: %s\n", f.Remedy)
			}
		}
	}
	fmt.Println()
}

func printSummary(results []FileScanResult, minScore int) {
	totalFiles := len(results)
	safeFiles, riskyFiles, unsafeFiles := 0, 0, 0
	totalScore := 0
	totalFindings := 0

	for _, r := range results {
		totalScore += r.Response.Score
		totalFindings += len(r.Response.Findings)
		switch r.Response.Status {
		case "SAFE":
			safeFiles++
		case "RISKY":
			riskyFiles++
		case "UNSAFE":
			unsafeFiles++
		}
	}

	avgScore := 0
	if totalFiles > 0 {
		avgScore = totalScore / totalFiles
	}

	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Println("                               SCAN SUMMARY                                     ")
	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Printf("Total Files Scanned : %d\n", totalFiles)
	fmt.Printf("Total Findings      : %d\n", totalFindings)
	fmt.Printf("Average Score       : %d/100\n", avgScore)
	fmt.Printf("Safe (100-70)       : %d\n", safeFiles)
	fmt.Printf("Risky (69-40)       : %d\n", riskyFiles)
	fmt.Printf("Unsafe (<40)        : %d\n", unsafeFiles)
	fmt.Printf("Passing Score Gate  : %d+\n", minScore)
	if avgScore >= minScore && unsafeFiles == 0 {
		fmt.Println("Result              : PASSED ✅")
	} else {
		fmt.Println("Result              : FAILED ❌ (Vulnerabilities found or score below threshold)")
	}
	fmt.Println("--------------------------------------------------------------------------------")
}
