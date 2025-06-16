package protocol

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/chacha20"
)

// Test vectors for Rspamd's XChaCha20-Poly1305 implementation
// These will be filled with values generated from Rspamd's C code

// TestRspamdXChaCha20Poly1305Compatibility tests our implementation against
// test vectors generated from Rspamd's C code to ensure exact compatibility
func TestRspamdXChaCha20Poly1305Compatibility(t *testing.T) {
	testCases := []struct {
		name           string
		key            string // hex-encoded 32-byte key
		nonce          string // hex-encoded 24-byte nonce
		plaintext      string // hex-encoded plaintext (at least 64 bytes)
		expectedCipher string // hex-encoded expected ciphertext
		expectedMAC    string // hex-encoded expected MAC tag (16 bytes)
	}{
		{
			name:  "all_zeros_64_bytes",
			key:   "0000000000000000000000000000000000000000000000000000000000000000", // 32 zero bytes
			nonce: "000000000000000000000000000000000000000000000000",                 // 24 zero bytes
			plaintext: "0000000000000000000000000000000000000000000000000000000000000000" + // 64 zero bytes (1 block)
				"0000000000000000000000000000000000000000000000000000000000000000",
			expectedCipher: "789e9689e5208d7fd9e1f3c5b5341f48ef18a13e418998adda" +
				"dd97a3693a987f8e82ecd5c1433bfed1af49750c0f1ff29c4174a05b119aa3a9e8333812e0c0fe",
			expectedMAC: "9c22bd8b7d6800ca3f9df1c03e313e68",
		},
		{
			name:  "all_zeros_128_bytes",
			key:   "0000000000000000000000000000000000000000000000000000000000000000",
			nonce: "000000000000000000000000000000000000000000000000",
			plaintext: "0000000000000000000000000000000000000000000000000000000000000000" + // 128 zero bytes (2 blocks)
				"0000000000000000000000000000000000000000000000000000000000000000" +
				"0000000000000000000000000000000000000000000000000000000000000000" +
				"0000000000000000000000000000000000000000000000000000000000000000",
			expectedCipher: "789e9689e5208d7fd9e1f3c5b5341f48ef18a13e418998adda" +
				"dd97a3693a987f8e82ecd5c1433bfed1af49750c0f1ff29c4174a05b119aa3a9e8333812e0c0fe" +
				"a49e1ee0134a70a9d49c24e0cbd8fc3ba27e97c3322ad487f778f8dc6a122fa5" +
				"9cbe33e778ea2e50bb5909c9971c4fec2f93523f77892d17caa58167dec4d6c7",
			expectedMAC: "cfe14ac33935d3631a06bf5588f412fa",
		},
		{
			name:  "test_pattern_64_bytes",
			key:   "0101010101010101010101010101010101010101010101010101010101010101", // Pattern key
			nonce: "010203040506070809101112131415161718192021222324",                 // Sequential nonce
			plaintext: "000102030405060708091011121314151617181920212223242526272829303132" + // Test pattern
				"333435363738394041424344454647484950515253545556575859606162636465",
			expectedCipher: "PLACEHOLDER_CIPHER_64_BYTES", // TODO: Fill from C code
			expectedMAC:    "PLACEHOLDER_MAC_16_BYTES",    // TODO: Fill from C code
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Skip placeholder tests until real values are provided
			if tc.expectedCipher == "PLACEHOLDER_CIPHER_64_BYTES" ||
				tc.expectedCipher == "PLACEHOLDER_CIPHER_128_BYTES" ||
				tc.expectedMAC == "PLACEHOLDER_MAC_16_BYTES" {
				t.Skip("Skipping test with placeholder values - waiting for C code test vectors")
				return
			}

			// Decode inputs
			keyBytes, err := hex.DecodeString(tc.key)
			if err != nil {
				t.Fatalf("Failed to decode key: %v", err)
			}
			var key RspamdNM
			copy(key[:], keyBytes)

			nonceBytes, err := hex.DecodeString(tc.nonce)
			if err != nil {
				t.Fatalf("Failed to decode nonce: %v", err)
			}
			var nonce [24]byte
			copy(nonce[:], nonceBytes)

			plaintextBytes, err := hex.DecodeString(tc.plaintext)
			if err != nil {
				t.Fatalf("Failed to decode plaintext: %v", err)
			}

			expectedCipherBytes, err := hex.DecodeString(tc.expectedCipher)
			if err != nil {
				t.Fatalf("Failed to decode expected cipher: %v", err)
			}

			expectedMACBytes, err := hex.DecodeString(tc.expectedMAC)
			if err != nil {
				t.Fatalf("Failed to decode expected MAC: %v", err)
			}
			var expectedMAC [16]byte
			copy(expectedMAC[:], expectedMACBytes)

			// Test encryption
			sbox, err := NewRspamdSecretbox(key, nonce)
			if err != nil {
				t.Fatalf("Failed to create secretbox: %v", err)
			}

			// Make a copy for encryption
			ciphertext := make([]byte, len(plaintextBytes))
			copy(ciphertext, plaintextBytes)

			// Encrypt
			actualMAC, err := sbox.EncryptInPlace(ciphertext)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Verify ciphertext matches expected
			if !bytes.Equal(ciphertext, expectedCipherBytes) {
				t.Errorf("Ciphertext mismatch:\nExpected: %x\nActual:   %x", expectedCipherBytes, ciphertext)
			}

			// Verify MAC matches expected
			if actualMAC != expectedMAC {
				t.Errorf("MAC mismatch:\nExpected: %x\nActual:   %x", expectedMAC, actualMAC)
			}

			// Test decryption
			sbox2, err := NewRspamdSecretbox(key, nonce)
			if err != nil {
				t.Fatalf("Failed to create secretbox for decryption: %v", err)
			}

			err = sbox2.DecryptInPlace(ciphertext, actualMAC)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			// Verify we got back the original plaintext
			if !bytes.Equal(ciphertext, plaintextBytes) {
				t.Errorf("Decryption result mismatch:\nExpected: %x\nActual:   %x", plaintextBytes, ciphertext)
			}

			t.Logf("✓ Test case '%s' passed", tc.name)
			t.Logf("  Key:        %x", keyBytes)
			t.Logf("  Nonce:      %x", nonceBytes)
			t.Logf("  Plaintext:  %x (%d bytes)", plaintextBytes, len(plaintextBytes))
			t.Logf("  Ciphertext: %x", expectedCipherBytes)
			t.Logf("  MAC:        %x", expectedMAC)
		})
	}
}

// TestRspamdMACKeyDerivation specifically tests the MAC key derivation process
func TestRspamdMACKeyDerivation(t *testing.T) {
	testCases := []struct {
		name           string
		key            string // hex-encoded 32-byte key
		nonce          string // hex-encoded 24-byte nonce
		expectedMACKey string // hex-encoded expected MAC key (32 bytes from first 32 of 64-byte subkey)
		expectedSubkey string // hex-encoded expected full 64-byte subkey (for debugging)
	}{
		{
			name:           "all_zeros",
			key:            "0000000000000000000000000000000000000000000000000000000000000000",
			nonce:          "000000000000000000000000000000000000000000000000",
			expectedMACKey: "PLACEHOLDER_MAC_KEY_32_BYTES", // TODO: Fill from C code
			expectedSubkey: "PLACEHOLDER_SUBKEY_64_BYTES",  // TODO: Fill from C code
		},
		{
			name:           "test_pattern",
			key:            "0101010101010101010101010101010101010101010101010101010101010101",
			nonce:          "010203040506070809101112131415161718192021222324",
			expectedMACKey: "PLACEHOLDER_MAC_KEY_32_BYTES", // TODO: Fill from C code
			expectedSubkey: "PLACEHOLDER_SUBKEY_64_BYTES",  // TODO: Fill from C code
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Skip placeholder tests
			if tc.expectedMACKey == "PLACEHOLDER_MAC_KEY_32_BYTES" ||
				tc.expectedSubkey == "PLACEHOLDER_SUBKEY_64_BYTES" {
				t.Skip("Skipping test with placeholder values - waiting for C code test vectors")
				return
			}

			// Decode inputs
			keyBytes, err := hex.DecodeString(tc.key)
			if err != nil {
				t.Fatalf("Failed to decode key: %v", err)
			}
			var key RspamdNM
			copy(key[:], keyBytes)

			nonceBytes, err := hex.DecodeString(tc.nonce)
			if err != nil {
				t.Fatalf("Failed to decode nonce: %v", err)
			}
			var nonce [24]byte
			copy(nonce[:], nonceBytes)

			expectedMACKeyBytes, err := hex.DecodeString(tc.expectedMACKey)
			if err != nil {
				t.Fatalf("Failed to decode expected MAC key: %v", err)
			}

			expectedSubkeyBytes, err := hex.DecodeString(tc.expectedSubkey)
			if err != nil {
				t.Fatalf("Failed to decode expected subkey: %v", err)
			}

			// Test MAC key derivation by creating secretbox and checking internal state
			sbox, err := NewRspamdSecretbox(key, nonce)
			if err != nil {
				t.Fatalf("Failed to create secretbox: %v", err)
			}

			// Verify MAC key matches expected
			if !bytes.Equal(sbox.macKey[:], expectedMACKeyBytes) {
				t.Errorf("MAC key mismatch:\nExpected: %x\nActual:   %x", expectedMACKeyBytes, sbox.macKey[:])
			}

			// For debugging: manually derive subkey to compare with expected
			debugCipher, err := NewUnauthenticatedCipher(key[:], nonce[:])
			if err != nil {
				t.Fatalf("Failed to create debug cipher: %v", err)
			}

			debugSubkey := make([]byte, 64)
			debugCipher.XORKeyStream(debugSubkey, debugSubkey)

			if !bytes.Equal(debugSubkey, expectedSubkeyBytes) {
				t.Errorf("Full subkey mismatch:\nExpected: %x\nActual:   %x", expectedSubkeyBytes, debugSubkey)
			}

			t.Logf("✓ MAC key derivation test '%s' passed", tc.name)
			t.Logf("  Key:       %x", keyBytes)
			t.Logf("  Nonce:     %x", nonceBytes)
			t.Logf("  MAC Key:   %x", expectedMACKeyBytes)
			t.Logf("  Full subkey: %x", expectedSubkeyBytes)
		})
	}
}

// Helper function for NewUnauthenticatedCipher (avoiding import issues)
func NewUnauthenticatedCipher(key, nonce []byte) (cipher.Stream, error) {
	return chacha20.NewUnauthenticatedCipher(key, nonce)
}
