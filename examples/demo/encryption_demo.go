package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"os"

	"github.com/rspamd/rspamdclient-go/protocol"
	"golang.org/x/crypto/curve25519"
)

func main() {
	var (
		generateKey = flag.Bool("generate", false, "Generate a new keypair for testing")
		testKey     = flag.String("key", "", "Test encryption with provided base32 key")
		verbose     = flag.Bool("verbose", false, "Show detailed encryption steps")
		help        = flag.Bool("help", false, "Show help message")
	)
	flag.Parse()

	if *help {
		fmt.Println("HTTPCrypt Encryption Demo")
		fmt.Println("========================")
		fmt.Println()
		fmt.Println("This utility demonstrates the HTTPCrypt encryption process")
		fmt.Println("used by Rspamd without requiring a running server.")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  go run encryption_demo.go [options]")
		fmt.Println()
		fmt.Println("Options:")
		flag.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  # Generate a new keypair")
		fmt.Println("  go run encryption_demo.go --generate")
		fmt.Println()
		fmt.Println("  # Test encryption with a key")
		fmt.Println("  go run encryption_demo.go --key 'your-base32-key' --verbose")
		return
	}

	if *generateKey {
		fmt.Println("HTTPCrypt Keypair Generation")
		fmt.Println("============================")

		// Generate a random private key
		var privateKey [32]byte
		if _, err := rand.Read(privateKey[:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating private key: %v\n", err)
			os.Exit(1)
		}

		// Generate the corresponding public key
		publicKey, err := curve25519.X25519(privateKey[:], curve25519.Basepoint)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating public key: %v\n", err)
			os.Exit(1)
		}

		// Encode keys in base32 (Rspamd format)
		privateKeyB32 := protocol.Base32Encode(privateKey[:])
		publicKeyB32 := protocol.Base32Encode(publicKey)

		fmt.Printf("Private Key (32 bytes): %x\n", privateKey)
		fmt.Printf("Public Key  (32 bytes): %x\n", publicKey)
		fmt.Println()
		fmt.Printf("Private Key (Base32): %s\n", privateKeyB32)
		fmt.Printf("Public Key  (Base32): %s\n", publicKeyB32)
		fmt.Println()
		fmt.Println("🔑 Use the Public Key (Base32) as the --key parameter for encryption")
		fmt.Println("⚠️  Keep the Private Key secure and configure it on your Rspamd server")

		return
	}

	if *testKey == "" {
		fmt.Fprintf(os.Stderr, "Error: Either --generate or --key parameter is required\n")
		fmt.Fprintf(os.Stderr, "Use --help for usage information\n")
		os.Exit(1)
	}

	fmt.Println("HTTPCrypt Encryption Demonstration")
	fmt.Println("===================================")
	fmt.Printf("Testing with key: %s\n\n", *testKey)

	// Validate and decode the public key
	publicKeyBytes, err := protocol.Base32Decode(*testKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Invalid key format: %v\n", err)
		os.Exit(1)
	}

	if len(publicKeyBytes) != 32 {
		fmt.Fprintf(os.Stderr, "Error: Key must be 32 bytes, got %d\n", len(publicKeyBytes))
		os.Exit(1)
	}

	fmt.Printf("✓ Key validation passed (%d bytes)\n", len(publicKeyBytes))

	if *verbose {
		fmt.Printf("  Raw key bytes: %x\n", publicKeyBytes)
	}

	// Test data to encrypt
	testURL := "/checkv2"
	testBody := []byte("Subject: Test Email\n\nThis is a test email for HTTPCrypt encryption.")
	testHeaders := map[string]string{
		"Content-Type": "text/plain",
		"User-Agent":   "rspamd-client-go/demo",
		"From":         "test@example.com",
	}

	fmt.Printf("\nTest Data:\n")
	fmt.Printf("==========\n")
	fmt.Printf("URL: %s\n", testURL)
	fmt.Printf("Body size: %d bytes\n", len(testBody))
	fmt.Printf("Headers: %d\n", len(testHeaders))

	if *verbose {
		fmt.Printf("\nHeaders:\n")
		for k, v := range testHeaders {
			fmt.Printf("  %s: %s\n", k, v)
		}
		fmt.Printf("\nBody:\n%s\n", string(testBody))
	}

	// Perform HTTPCrypt encryption
	fmt.Printf("\n🔐 HTTPCrypt Encryption Process:\n")
	fmt.Printf("=================================\n")

	if *verbose {
		fmt.Printf("1. Generating ephemeral keypair...\n")
	}

	encrypted, err := protocol.HTTPCryptEncrypt(testURL, testBody, testHeaders, []byte(*testKey))
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Encryption failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Encryption successful!\n")
	fmt.Printf("  Ephemeral public key: %s\n", encrypted.PeerKey)
	fmt.Printf("  Encrypted data size: %d bytes\n", len(encrypted.Body))
	fmt.Printf("  Original data size: %d bytes\n", len(testBody)+len(testURL)+50) // Approximate

	if *verbose {
		fmt.Printf("  Shared secret: %x\n", encrypted.SharedKey)
		fmt.Printf("  Encrypted payload (first 64 bytes): %x\n", encrypted.Body[:min(64, len(encrypted.Body))])
	}

	// Test decryption
	fmt.Printf("\n🔓 HTTPCrypt Decryption Process:\n")
	fmt.Printf("=================================\n")

	// Make a copy for decryption
	encryptedCopy := make([]byte, len(encrypted.Body))
	copy(encryptedCopy, encrypted.Body)

	if *verbose {
		fmt.Printf("1. Extracting nonce and tag...\n")
		fmt.Printf("2. Creating secretbox with shared key...\n")
		fmt.Printf("3. Verifying authentication tag...\n")
		fmt.Printf("4. Decrypting data...\n")
	}

	offset, err := protocol.HTTPCryptDecrypt(encryptedCopy, encrypted.SharedKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Decryption failed: %v\n", err)
		os.Exit(1)
	}

	decryptedData := encryptedCopy[offset:]
	fmt.Printf("✓ Decryption successful!\n")
	fmt.Printf("  Decrypted data size: %d bytes\n", len(decryptedData))
	fmt.Printf("  Data offset: %d bytes\n", offset)

	// Verify the decrypted data contains our original content
	decryptedStr := string(decryptedData)
	containsURL := contains(decryptedData, []byte(testURL))
	containsBody := contains(decryptedData, testBody)

	fmt.Printf("\n📋 Verification:\n")
	fmt.Printf("================\n")
	fmt.Printf("✓ Contains original URL: %t\n", containsURL)
	fmt.Printf("✓ Contains original body: %t\n", containsBody)

	if *verbose {
		fmt.Printf("\nDecrypted HTTP Request:\n")
		fmt.Printf("======================\n")
		fmt.Printf("%s\n", decryptedStr)
	}

	if containsURL && containsBody {
		fmt.Printf("\n🎉 HTTPCrypt round-trip encryption test PASSED!\n")
		fmt.Printf("   All cryptographic operations completed successfully.\n")
	} else {
		fmt.Printf("\n❌ HTTPCrypt round-trip encryption test FAILED!\n")
		fmt.Printf("   Decrypted data does not match original input.\n")
		os.Exit(1)
	}

	fmt.Printf("\nCryptographic Details:\n")
	fmt.Printf("======================\n")
	fmt.Printf("✓ X25519 Elliptic Curve Diffie-Hellman\n")
	fmt.Printf("✓ HChaCha20 Key Derivation (Rspamd-specific)\n")
	fmt.Printf("✓ XChaCha20-Poly1305 Authenticated Encryption\n")
	fmt.Printf("✓ Base32 Encoding (zbase32 compatible)\n")
	fmt.Printf("✓ Bug-to-bug compatibility with Rspamd\n")

	if *verbose {
		fmt.Printf("\nTechnical Notes:\n")
		fmt.Printf("================\n")
		fmt.Printf("• Nonce size: %d bytes\n", protocol.NonceSize)
		fmt.Printf("• Tag size: %d bytes\n", protocol.TagSize)
		fmt.Printf("• Key size: %d bytes\n", protocol.KeySize)
		fmt.Printf("• Algorithm: XChaCha20-Poly1305\n")
		fmt.Printf("• Key Exchange: X25519\n")
		fmt.Printf("• KDF: HChaCha20 (non-standard)\n")
	}
}

// Helper function to check if slice contains subslice
func contains(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	if len(needle) > len(haystack) {
		return false
	}

	for i := 0; i <= len(haystack)-len(needle); i++ {
		found := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				found = false
				break
			}
		}
		if found {
			return true
		}
	}
	return false
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
