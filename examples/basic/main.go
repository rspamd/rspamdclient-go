package main

import (
	"context"
	"fmt"
	"log"

	rspamd "github.com/rspamd/rspamdclient-go"
)

func main() {
	// Create configuration
	cfg := rspamd.NewConfig("http://localhost:11333")
	cfg.WithTimeout(30.0).WithRetries(3)

	// Create envelope data
	envelope := rspamd.NewEnvelopeData().
		WithFrom("sender@example.com").
		WithRcpt("recipient@example.com").
		WithIP("192.168.1.100")

	// Example email
	email := []byte(`From: sender@example.com
To: recipient@example.com
Subject: Test Email

This is a test email for Rspamd scanning.
`)

	// Scan the email
	ctx := context.Background()
	response, err := rspamd.ScanAsync(ctx, cfg, email, envelope)
	if err != nil {
		log.Fatalf("Failed to scan email: %v", err)
	}

	// Print results
	fmt.Printf("Scan Results:\n")
	fmt.Printf("  Action: %s\n", response.Action)
	fmt.Printf("  Score: %.2f\n", response.Score)
	fmt.Printf("  Required Score: %.2f\n", response.RequiredScore)
	fmt.Printf("  Message ID: %s\n", response.MessageID)
	fmt.Printf("  Scan Time: %.4fs\n", response.ScanTime)

	if len(response.Symbols) > 0 {
		fmt.Printf("  Symbols:\n")
		for name, symbol := range response.Symbols {
			fmt.Printf("    %s: %.2f", name, symbol.Score)
			if symbol.Description != nil {
				fmt.Printf(" (%s)", *symbol.Description)
			}
			fmt.Println()
		}
	}

	if len(response.URLs) > 0 {
		fmt.Printf("  URLs: %v\n", response.URLs)
	}

	if len(response.Emails) > 0 {
		fmt.Printf("  Emails: %v\n", response.Emails)
	}
}
