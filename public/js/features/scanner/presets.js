/**
 * Feature: Scanner Presets
 * Pre-configured Go code samples demonstrating various vulnerability categories and safe patterns.
 */
export const ScannerPresets = {
  sqli: `package main

import (
	"database/sql"
	"fmt"
)

func getUser(db *sql.DB, id string) {
	// Vulnerable: user input concatenated directly into query
	query := "SELECT * FROM users WHERE id = " + id
	rows, err := db.Query(query)
	_ = rows
	_ = err
}`,

  cmd: `package main

import (
	"os/exec"
)

func runBackup(targetFolder string) {
	// Vulnerable: Command injection risk via unvalidated input
	cmd := exec.Command("sh", "-c", "tar -czf backup.tar.gz " + targetFolder)
	cmd.Run()
}`,

  tls: `package main

import (
	"crypto/tls"
	"net/http"
)

func createInsecureClient() *http.Client {
	// Critical: InsecureSkipVerify disables TLS certificate validation
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Transport: tr}
}`,

  secrets: `package main

// Critical: Exposed credentials committed to source code
var awsSecretKey = "AKIA1234567890ABCDEF"
var dbPassword = "SuperSecretPassword123!"

func connect() {
	println("connecting with credentials...")
}`,

  path: `package main

import (
	"os"
)

func readUserFile(userInput string) ([]byte, error) {
	// Vulnerable: arbitrary file read via directory traversal
	return os.ReadFile("/var/app/uploads/" + userInput)
}`,

  safe: `package main

import (
	"context"
	"database/sql"
	"fmt"
)

func getUser(ctx context.Context, db *sql.DB, id int) error {
	// Safe: parameterized query with error checking
	row := db.QueryRowContext(ctx, "SELECT name FROM users WHERE id = $1", id)
	var name string
	if err := row.Scan(&name); err != nil {
		return err
	}
	fmt.Println("Found user:", name)
	return nil
}`
};
