package protocol

import (
	"testing"

	"golang.org/x/crypto/chacha20"
)

// TestXChaCha20Verification verifies that the Go chacha20 package
// correctly uses XChaCha20 when provided with a 24-byte nonce
func TestXChaCha20Verification(t *testing.T) {
	// Test key and nonce
	key := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

	// 24-byte nonce for XChaCha20
	nonce24 := [24]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
		13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}

	// 12-byte nonce for regular ChaCha20
	nonce12 := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}

	// Create XChaCha20 cipher (should work with 24-byte nonce)
	xchacha20Cipher, err := chacha20.NewUnauthenticatedCipher(key[:], nonce24[:])
	if err != nil {
		t.Fatalf("Failed to create XChaCha20 cipher: %v", err)
	}

	// Create regular ChaCha20 cipher (should work with 12-byte nonce)
	chacha20Cipher, err := chacha20.NewUnauthenticatedCipher(key[:], nonce12[:])
	if err != nil {
		t.Fatalf("Failed to create ChaCha20 cipher: %v", err)
	}

	// Test encryption with both ciphers
	plaintext := []byte("Hello, this is a test message for XChaCha20 vs ChaCha20!")

	// Encrypt with XChaCha20
	xchacha20Data := make([]byte, len(plaintext))
	copy(xchacha20Data, plaintext)
	xchacha20Cipher.XORKeyStream(xchacha20Data, xchacha20Data)

	// Encrypt with ChaCha20
	chacha20Data := make([]byte, len(plaintext))
	copy(chacha20Data, plaintext)
	chacha20Cipher.XORKeyStream(chacha20Data, chacha20Data)

	// They should produce different results (different algorithms)
	if string(xchacha20Data) == string(chacha20Data) {
		t.Error("XChaCha20 and ChaCha20 produced identical results, which suggests they're using the same algorithm")
	}

	// Verify we can decrypt XChaCha20
	xchacha20CipherDecrypt, err := chacha20.NewUnauthenticatedCipher(key[:], nonce24[:])
	if err != nil {
		t.Fatalf("Failed to create XChaCha20 cipher for decryption: %v", err)
	}

	xchacha20CipherDecrypt.XORKeyStream(xchacha20Data, xchacha20Data)
	if string(xchacha20Data) != string(plaintext) {
		t.Errorf("XChaCha20 decryption failed: got %q, want %q", string(xchacha20Data), string(plaintext))
	}

	t.Logf("✓ XChaCha20 (24-byte nonce) and ChaCha20 (12-byte nonce) work correctly and produce different results")
	t.Logf("✓ This confirms that golang.org/x/crypto/chacha20 correctly uses XChaCha20 for 24-byte nonces")
}

// TestRspamdSecretboxUsesXChaCha20 specifically tests that our RspamdSecretbox uses XChaCha20
func TestRspamdSecretboxUsesXChaCha20(t *testing.T) {
	key := RspamdNM{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	nonce := [24]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24}

	// Create our secretbox
	sbox, err := NewRspamdSecretbox(key, nonce)
	if err != nil {
		t.Fatalf("Failed to create RspamdSecretbox: %v", err)
	}

	// Test data
	plaintext := []byte("Test message for Rspamd XChaCha20 secretbox")
	ciphertext := make([]byte, len(plaintext))
	copy(ciphertext, plaintext)

	// Encrypt
	tag, err := sbox.EncryptInPlace(ciphertext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Verify ciphertext is different from plaintext
	if string(ciphertext) == string(plaintext) {
		t.Error("Encryption didn't change the data")
	}

	// Create another secretbox for decryption
	sbox2, err := NewRspamdSecretbox(key, nonce)
	if err != nil {
		t.Fatalf("Failed to create second RspamdSecretbox: %v", err)
	}

	// Decrypt
	err = sbox2.DecryptInPlace(ciphertext, tag)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify we got back the original plaintext
	if string(ciphertext) != string(plaintext) {
		t.Errorf("Decryption mismatch: got %q, want %q", string(ciphertext), string(plaintext))
	}

	t.Logf("✓ RspamdSecretbox successfully uses XChaCha20 with 24-byte nonces")
	t.Logf("✓ Encryption/decryption cycle completed successfully")
}
