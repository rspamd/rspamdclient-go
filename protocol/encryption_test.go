package protocol

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/crypto/blake2b"
)

// Test vectors from the Rust implementation
const (
	expectedPoint = "95,76,225,188,0,26,146,94,70,249,90,189,35,51,1,42,9,37,94,254,204,55,198,91,180,90,46,217,140,226,211,90"
	expectedNM    = "61,109,220,195,100,174,127,237,148,122,154,61,165,83,93,105,127,166,153,112,103,224,2,200,136,243,73,51,8,163,150,7"
)

func parseByteString(s string) []byte {
	// Simple parser for comma-separated byte values like "95,76,225,..."
	result := make([]byte, 0)
	current := 0
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			current = current*10 + int(s[i]-'0')
		} else if s[i] == ',' {
			result = append(result, byte(current))
			current = 0
		}
	}
	if current > 0 {
		result = append(result, byte(current))
	}
	return result
}

func TestRspamdX25519Scalarmult(t *testing.T) {
	// Test with zero secret key and known public key from Rust tests
	var sk [32]byte // Zero key
	pk := "k4nz984k36xmcynm1hr9kdbn6jhcxf4ggbrb1quay7f88rpm9kay"

	point, err := RspamdX25519Scalarmult([]byte(pk), sk)
	if err != nil {
		t.Fatalf("RspamdX25519Scalarmult failed: %v", err)
	}

	expected := parseByteString(expectedPoint)
	if !bytes.Equal(point[:], expected) {
		t.Errorf("Scalarmult result mismatch.\nExpected: %v\nGot: %v", expected, point[:])
	}
}

func TestRspamdX25519ECDH(t *testing.T) {
	// Use the expected point from the scalarmult test
	expectedPointBytes := parseByteString(expectedPoint)
	var point [32]byte
	copy(point[:], expectedPointBytes)

	nm := RspamdX25519ECDH(&point)

	expected := parseByteString(expectedNM)
	if !bytes.Equal(nm[:], expected) {
		t.Errorf("ECDH result mismatch.\nExpected: %v\nGot: %v", expected, nm[:])
	}
}

func TestBase32Encoding(t *testing.T) {
	// Test basic base32 encoding/decoding
	original := []byte("hello world")
	encoded := Base32Encode(original)
	decoded, err := Base32Decode(encoded)
	if err != nil {
		t.Fatalf("Base32 decode failed: %v", err)
	}

	if !bytes.Equal(original, decoded) {
		t.Errorf("Base32 round-trip failed.\nOriginal: %v\nDecoded: %v", original, decoded)
	}
}

func TestRspamdSecretbox(t *testing.T) {
	// Test the secretbox encryption/decryption
	key := RspamdNM{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	nonce := [24]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}

	sbox, err := NewRspamdSecretbox(key, nonce)
	if err != nil {
		t.Fatalf("NewRspamdSecretbox failed: %v", err)
	}

	plaintext := []byte("Hello, Rspamd!")
	ciphertext := make([]byte, len(plaintext))
	copy(ciphertext, plaintext)

	// Encrypt
	tag, err := sbox.EncryptInPlace(ciphertext)
	if err != nil {
		t.Fatalf("EncryptInPlace failed: %v", err)
	}

	// Verify ciphertext is different from plaintext
	if bytes.Equal(plaintext, ciphertext) {
		t.Error("Encryption did not change the data")
	}

	// Create another secretbox for decryption
	sbox2, err := NewRspamdSecretbox(key, nonce)
	if err != nil {
		t.Fatalf("NewRspamdSecretbox failed: %v", err)
	}

	// Decrypt
	err = sbox2.DecryptInPlace(ciphertext, tag)
	if err != nil {
		t.Fatalf("DecryptInPlace failed: %v", err)
	}

	// Verify plaintext is recovered
	if !bytes.Equal(plaintext, ciphertext) {
		t.Errorf("Decryption failed.\nExpected: %v\nGot: %v", plaintext, ciphertext)
	}
}

func TestHTTPCryptRoundTrip(t *testing.T) {
	// Test full HTTPCrypt encryption/decryption round trip
	url := "/checkv2"
	body := []byte("test message")
	headers := map[string]string{
		"Content-Type": "text/plain",
		"User-Agent":   "rspamd-client-go",
	}
	peerKey := []byte("k4nz984k36xmcynm1hr9kdbn6jhcxf4ggbrb1quay7f88rpm9kay")

	// Encrypt
	encrypted, err := HTTPCryptEncrypt(url, body, headers, peerKey)
	if err != nil {
		t.Fatalf("HTTPCryptEncrypt failed: %v", err)
	}

	// Verify encryption produced output
	if len(encrypted.Body) == 0 {
		t.Error("Encryption produced empty body")
	}
	if encrypted.PeerKey == "" {
		t.Error("Encryption produced empty peer key")
	}

	// Create a copy of the encrypted body for decryption
	encryptedBody := make([]byte, len(encrypted.Body))
	copy(encryptedBody, encrypted.Body)

	// Decrypt
	offset, err := HTTPCryptDecrypt(encryptedBody, encrypted.SharedKey)
	if err != nil {
		t.Fatalf("HTTPCryptDecrypt failed: %v", err)
	}

	// Extract the decrypted HTTP request
	decryptedData := encryptedBody[offset:]

	// Verify the decrypted data contains our original content
	decryptedStr := string(decryptedData)
	if !bytes.Contains(decryptedData, body) {
		t.Errorf("Decrypted data does not contain original body.\nDecrypted: %s", decryptedStr)
	}

	// Verify it contains the URL
	if !bytes.Contains(decryptedData, []byte(url)) {
		t.Errorf("Decrypted data does not contain URL.\nDecrypted: %s", decryptedStr)
	}
}

// TestHTTPCryptKeyHeader tests that HTTPCrypt does NOT include the Key header in inner request
// and that we can generate the correct Key header for the outer request
func TestHTTPCryptKeyHeader(t *testing.T) {
	// Create test data
	url := "/check"
	body := []byte("test email content")
	headers := map[string]string{
		"Content-Type": "text/plain",
	}

	// Use a valid base32-encoded peer key for testing (same as other tests)
	peerKey := []byte("k4nz984k36xmcynm1hr9kdbn6jhcxf4ggbrb1quay7f88rpm9kay")

	// Encrypt using HTTPCrypt
	encrypted, err := HTTPCryptEncrypt(url, body, headers, peerKey)
	if err != nil {
		t.Fatalf("HTTPCryptEncrypt failed: %v", err)
	}

	// Decrypt to get the HTTP request content
	offset, err := HTTPCryptDecrypt(encrypted.Body, encrypted.SharedKey)
	if err != nil {
		t.Fatalf("HTTPCryptDecrypt failed: %v", err)
	}

	// Parse the decrypted HTTP request
	decryptedRequest := string(encrypted.Body[offset:])
	t.Logf("Decrypted inner HTTP request:\n%s", decryptedRequest)

	// Verify that the inner request does NOT contain the Key header
	if strings.Contains(decryptedRequest, "Key: ") {
		t.Errorf("Inner HTTPCrypt request should NOT contain 'Key:' header - it belongs in outer request")
	}

	// Test generating the Key header for the outer request
	keyHeader, err := MakeKeyHeader(string(peerKey), encrypted.PeerKey)
	if err != nil {
		t.Fatalf("Failed to make key header: %v", err)
	}

	// Verify the Key header format: remote_pk_id=local_key
	parts := strings.Split(keyHeader, "=")
	if len(parts) != 2 {
		t.Errorf("Key header should be in format 'remote_pk_id=local_key', got: %s", keyHeader)
	}

	remotePkId := parts[0]
	localKey := parts[1]

	// Verify remote_pk_id is base32(blake2b(peerKey)[:5])
	expectedRemotePkId, err := generateExpectedRemotePkId(peerKey)
	if err != nil {
		t.Fatalf("Failed to generate expected remote pk id: %v", err)
	}

	if remotePkId != expectedRemotePkId {
		t.Errorf("Remote PK ID mismatch:\nExpected: %s\nGot:      %s", expectedRemotePkId, remotePkId)
	}

	// Verify local key matches the public key returned by HTTPCrypt
	if localKey != encrypted.PeerKey {
		t.Errorf("Local key mismatch:\nExpected: %s\nGot:      %s", encrypted.PeerKey, localKey)
	}

	t.Logf("✓ Key header format verified: %s", keyHeader)
	t.Logf("  Remote PK ID: %s", remotePkId)
	t.Logf("  Local Key:    %s", localKey)
	t.Logf("✓ Inner request correctly does NOT contain Key header")
}

// Helper function to generate expected remote PK ID for testing
func generateExpectedRemotePkId(peerKey []byte) (string, error) {
	// Decode the peer key from base32 first, just like MakeKeyHeader does
	peerKeyBytes, err := Base32Decode(string(peerKey))
	if err != nil {
		return "", err
	}

	hash := blake2b.Sum512(peerKeyBytes)
	return Base32Encode(hash[:ShortKeyIDSize]), nil
}
