package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rspamd/rspamdclient-go/config"
	"github.com/rspamd/rspamdclient-go/protocol"
)

// TestAsyncClientKeyHeader tests that the async client sets the Key header on the outer request
func TestAsyncClientKeyHeader(t *testing.T) {
	// Track the received headers
	var receivedHeaders http.Header

	// Create a test server that captures headers
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()

		// Return a dummy encrypted response
		w.WriteHeader(200)
		// Return some dummy encrypted data (nonce + tag + encrypted response)
		dummyResponse := make([]byte, 24+16+50) // nonce + tag + some data
		w.Write(dummyResponse)
	}))
	defer server.Close()

	// Create client config with encryption
	cfg := &config.Config{
		BaseURL:       server.URL,
		Timeout:       5.0,
		Retries:       0,
		EncryptionKey: stringPtr("k4nz984k36xmcynm1hr9kdbn6jhcxf4ggbrb1quay7f88rpm9kay"),
	}

	// Create async client
	client, err := NewAsyncClient(cfg)
	if err != nil {
		t.Fatalf("Failed to create async client: %v", err)
	}
	defer client.Close()

	// Create a request with empty envelope data
	testBody := []byte("test email content")
	envelopeData := &config.EnvelopeData{} // Empty but not nil
	request := NewRequest(client, testBody, protocol.Scan, envelopeData)

	// Execute the request
	ctx := context.Background()
	_, _, err = request.Execute(ctx)

	// We expect this to fail during decryption since we're sending dummy data,
	// but we should still be able to check that the Key header was set
	if err == nil {
		t.Log("Request succeeded (unexpected but not a problem for header test)")
	} else if !strings.Contains(err.Error(), "decryption failed") && !strings.Contains(err.Error(), "invalid body size") {
		t.Logf("Request failed with error: %v (expected due to dummy response)", err)
	}

	// Verify that the Key header was set
	keyHeader := receivedHeaders.Get("Key")
	if keyHeader == "" {
		t.Fatalf("Key header was not set on the outer HTTP request")
	}

	// Verify the Key header format: remote_pk_id=local_key
	parts := strings.Split(keyHeader, "=")
	if len(parts) != 2 {
		t.Errorf("Key header should be in format 'remote_pk_id=local_key', got: %s", keyHeader)
	}

	remotePkId := parts[0]
	localKey := parts[1]

	// Basic validation
	if remotePkId == "" {
		t.Error("Remote PK ID should not be empty")
	}
	if localKey == "" {
		t.Error("Local key should not be empty")
	}
	if len(remotePkId) < 5 {
		t.Error("Remote PK ID seems too short")
	}
	if len(localKey) < 40 {
		t.Error("Local key seems too short for a base32-encoded 32-byte key")
	}

	t.Logf("✓ Key header successfully set on outer request: %s", keyHeader)
	t.Logf("  Remote PK ID: %s", remotePkId)
	t.Logf("  Local Key: %s", localKey)
}

// Helper function for string pointer
func stringPtr(s string) *string {
	return &s
}
