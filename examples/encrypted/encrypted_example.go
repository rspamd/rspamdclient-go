package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	rspamd "github.com/rspamd/rspamdclient-go"
	"github.com/rspamd/rspamdclient-go/protocol"
)

func main() {
	// Command line flags
	var (
		serverURL     = flag.String("url", "http://localhost:11333", "Rspamd server URL")
		encryptionKey = flag.String("key", "", "Base32-encoded encryption key for HTTPCrypt")
		password      = flag.String("password", "", "Authentication password (optional)")
		useZSTD       = flag.Bool("zstd", true, "Enable ZSTD compression (default: true)")
		verbose       = flag.Bool("verbose", false, "Enable verbose output")
		help          = flag.Bool("help", false, "Show help message")
	)
	flag.Parse()

	if *help {
		fmt.Println("Rspamd Client - HTTPCrypt Encryption Example")
		fmt.Println("============================================")
		fmt.Println()
		fmt.Println("This example demonstrates how to use HTTPCrypt encryption")
		fmt.Println("to securely communicate with an Rspamd server.")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  go run encrypted_example.go --key <base32-key> [options]")
		fmt.Println()
		fmt.Println("Options:")
		flag.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  # Basic encrypted scan")
		fmt.Println("  go run encrypted_example.go --key 'your-base32-encoded-key' --url https://rspamd.example.com")
		fmt.Println()
		fmt.Println("  # Encrypted scan without compression")
		fmt.Println("  go run encrypted_example.go --key 'your-key' --zstd=false")
		fmt.Println()
		fmt.Println("  # Verbose encrypted scan with ZSTD compression")
		fmt.Println("  go run encrypted_example.go --key 'your-key' --verbose --zstd")
		fmt.Println()
		fmt.Println("Note: The encryption key should be a base32-encoded public key")
		fmt.Println("      that corresponds to the Rspamd server's configuration.")
		return
	}

	if *encryptionKey == "" {
		fmt.Fprintf(os.Stderr, "Error: --key parameter is required\n")
		fmt.Fprintf(os.Stderr, "Use --help for usage information\n")
		os.Exit(1)
	}

	// Validate the encryption key format
	if *verbose {
		fmt.Printf("Validating encryption key: %s\n", *encryptionKey)
	}

	// Test key decoding
	_, err := protocol.Base32Decode(*encryptionKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Invalid encryption key format: %v\n", err)
		fmt.Fprintf(os.Stderr, "The key should be base32-encoded (e.g., 'abc123def456...')\n")
		os.Exit(1)
	}

	if *verbose {
		fmt.Printf("✓ Encryption key validation passed\n")
	}

	// Create configuration with encryption
	cfg := rspamd.NewConfig(*serverURL).
		WithEncryptionKey(*encryptionKey).
		WithTimeout(30.0).
		WithRetries(3).
		WithZSTD(*useZSTD) // ZSTD compression (configurable)

	if *password != "" {
		cfg.WithPassword(*password)
		if *verbose {
			fmt.Printf("✓ Authentication password configured\n")
		}
	}

	if *verbose {
		fmt.Printf("✓ Client configured with HTTPCrypt encryption\n")
		fmt.Printf("  Server URL: %s\n", *serverURL)
		fmt.Printf("  Encryption: Enabled (HTTPCrypt)\n")
		if *useZSTD {
			fmt.Printf("  Compression: Enabled (ZSTD)\n")
		} else {
			fmt.Printf("  Compression: Disabled\n")
		}
		fmt.Printf("  Timeout: %.1fs\n", 30.0)
		fmt.Printf("  Retries: %d\n", 3)
	}

	// Create envelope data
	envelope := rspamd.NewEnvelopeData().
		WithFrom("encrypted-test@example.com").
		WithRcpt("recipient@example.com").
		WithIP("192.168.1.100").
		WithUser("test-user").
		WithHostname("test-client.example.com")

	// Build email content based on configuration
	emailContent := `From: encrypted-test@example.com
To: recipient@example.com
Subject: HTTPCrypt Encryption Test
Date: Mon, 15 Jun 2025 10:00:00 +0000
Message-ID: <test-encrypted@example.com>

This is a test email to demonstrate HTTPCrypt encryption
capabilities of the Rspamd Go client.

The entire HTTP request (including headers and body) will be
encrypted using the HTTPCrypt protocol before being sent to
the Rspamd server.

Features demonstrated:
- X25519 key exchange
- HChaCha20 key derivation 
- XChaCha20-Poly1305 encryption
- Custom base32 encoding`

	if *useZSTD {
		emailContent += `
- ZSTD compression (enabled)`
	} else {
		emailContent += `
- ZSTD compression (disabled)`
	}

	emailContent += `

Test data: Hello, encrypted world! 🔐
`

	email := []byte(emailContent)

	fmt.Println("Rspamd HTTPCrypt Encryption Example")
	fmt.Println("===================================")
	fmt.Printf("Server: %s\n", *serverURL)
	fmt.Printf("Encryption: HTTPCrypt (enabled)\n")
	if *useZSTD {
		fmt.Printf("Compression: ZSTD (enabled)\n")
	} else {
		fmt.Printf("Compression: Disabled\n")
	}
	fmt.Printf("Email size: %d bytes\n\n", len(email))

	// Scan the email with encryption
	ctx := context.Background()

	if *verbose {
		fmt.Println("🔐 Encrypting request using HTTPCrypt...")
		fmt.Println("   - Generating ephemeral keypair")
		fmt.Println("   - Performing X25519 key exchange")
		fmt.Println("   - Deriving shared secret with HChaCha20")
		fmt.Println("   - Encrypting with XChaCha20-Poly1305")
		fmt.Println("   - Sending encrypted request...")
	}

	response, err := rspamd.ScanAsync(ctx, cfg, email, envelope)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error scanning email: %v\n", err)

		// Provide helpful troubleshooting information
		fmt.Fprintf(os.Stderr, "\nTroubleshooting:\n")
		fmt.Fprintf(os.Stderr, "1. Verify the server URL is correct and accessible\n")
		fmt.Fprintf(os.Stderr, "2. Check that the encryption key matches the server's public key\n")
		fmt.Fprintf(os.Stderr, "3. Ensure the server supports HTTPCrypt encryption\n")
		fmt.Fprintf(os.Stderr, "4. Verify network connectivity and firewall settings\n")

		os.Exit(1)
	}

	if *verbose {
		fmt.Println("🔓 Response decrypted successfully")
	}

	// Display results
	fmt.Println("✅ Scan completed successfully!")
	fmt.Println("\nResults:")
	fmt.Println("========")
	fmt.Printf("Action:         %s\n", response.Action)
	fmt.Printf("Score:          %.2f\n", response.Score)
	fmt.Printf("Required Score: %.2f\n", response.RequiredScore)
	fmt.Printf("Message ID:     %s\n", response.MessageID)
	fmt.Printf("Scan Time:      %.4fs\n", response.ScanTime)

	if len(response.Symbols) > 0 {
		fmt.Printf("\nSymbols Detected (%d):\n", len(response.Symbols))
		fmt.Println("=====================")
		for name, symbol := range response.Symbols {
			fmt.Printf("  %-20s %6.2f", name, symbol.Score)
			if symbol.Description != nil {
				fmt.Printf("  (%s)", *symbol.Description)
			}
			if symbol.Options != nil && len(*symbol.Options) > 0 {
				fmt.Printf("  [%v]", *symbol.Options)
			}
			fmt.Println()
		}
	}

	if len(response.URLs) > 0 {
		fmt.Printf("\nURLs Found (%d):\n", len(response.URLs))
		fmt.Println("===============")
		for i, url := range response.URLs {
			fmt.Printf("  %d. %s\n", i+1, url)
		}
	}

	if len(response.Emails) > 0 {
		fmt.Printf("\nEmail Addresses (%d):\n", len(response.Emails))
		fmt.Println("====================")
		for i, email := range response.Emails {
			fmt.Printf("  %d. %s\n", i+1, email)
		}
	}

	if response.Milter != nil {
		if len(response.Milter.AddHeaders) > 0 {
			fmt.Printf("\nMilter Add Headers (%d):\n", len(response.Milter.AddHeaders))
			fmt.Println("=======================")
			for name, header := range response.Milter.AddHeaders {
				fmt.Printf("  %s: %s (order: %d)\n", name, header.Value, header.Order)
			}
		}

		if len(response.Milter.RemoveHeaders) > 0 {
			fmt.Printf("\nMilter Remove Headers (%d):\n", len(response.Milter.RemoveHeaders))
			fmt.Println("===========================")
			for name, count := range response.Milter.RemoveHeaders {
				fmt.Printf("  %s: %d\n", name, count)
			}
		}
	}

	fmt.Printf("\n🔐 HTTPCrypt encryption successfully used for secure communication!\n")

	if *verbose {
		fmt.Println("\nEncryption Details:")
		fmt.Println("==================")
		fmt.Println("✓ X25519 key exchange performed")
		fmt.Println("✓ HChaCha20 key derivation completed")
		fmt.Println("✓ XChaCha20-Poly1305 encryption applied")
		fmt.Println("✓ Request and response encrypted end-to-end")
		fmt.Println("✓ All cryptographic operations Rspamd-compatible")
	}
}
