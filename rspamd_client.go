// Package rspamd_client provides an HTTP client for interacting with the Rspamd service.
// It supports asynchronous operations and includes support for HTTPCrypt encryption,
// ZSTD compression, proxy configuration, and TLS settings.
//
// Example usage:
//
//	cfg := config.NewConfig("http://localhost:11333")
//	envelopeData := config.NewEnvelopeData().WithFrom("sender@example.com")
//
//	response, err := client.ScanAsync(context.Background(), cfg, emailBytes, envelopeData)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	fmt.Printf("Spam score: %.2f\n", response.Score)
package rspamd_client

import (
	"context"

	"github.com/rspamd/rspamdclient-go/client"
	"github.com/rspamd/rspamdclient-go/config"
	"github.com/rspamd/rspamdclient-go/protocol"
)

// Re-export commonly used types and functions
type (
	Config          = config.Config
	EnvelopeData    = config.EnvelopeData
	TLSSettings     = config.TLSSettings
	ProxyConfig     = config.ProxyConfig
	RspamdScanReply = protocol.RspamdScanReply
	Symbol          = protocol.Symbol
	Milter          = protocol.Milter
	MailHeader      = protocol.MailHeader
	AsyncClient     = client.AsyncClient
	RspamdCommand   = protocol.RspamdCommand
)

// Re-export constructors
var (
	NewConfig       = config.NewConfig
	NewEnvelopeData = config.NewEnvelopeData
	NewAsyncClient  = client.NewAsyncClient
)

// Re-export commands
const (
	Scan      = protocol.Scan
	LearnSpam = protocol.LearnSpam
	LearnHam  = protocol.LearnHam
)

// ScanAsync scans an email asynchronously and returns the parsed reply.
//
// Example:
//
//	cfg := NewConfig("http://localhost:11333")
//	envelope := NewEnvelopeData()
//	email := []byte("From: user@example.com\nTo: recipient@example.com\nSubject: Test\n\nThis is a test email.")
//
//	response, err := ScanAsync(context.Background(), cfg, email, envelope)
//	if err != nil {
//		return err
//	}
//
//	fmt.Printf("Action: %s, Score: %.2f\n", response.Action, response.Score)
func ScanAsync(ctx context.Context, cfg *Config, body []byte, envelopeData *EnvelopeData) (*RspamdScanReply, error) {
	return client.ScanAsync(ctx, cfg, body, envelopeData)
}

// LearnSpamAsync learns a message as spam asynchronously.
//
// Example:
//
//	cfg := NewConfig("http://localhost:11333")
//	envelope := NewEnvelopeData()
//	email := []byte("...")
//
//	err := LearnSpamAsync(context.Background(), cfg, email, envelope)
//	if err != nil {
//		return err
//	}
func LearnSpamAsync(ctx context.Context, cfg *Config, body []byte, envelopeData *EnvelopeData) error {
	return client.LearnSpamAsync(ctx, cfg, body, envelopeData)
}

// LearnHamAsync learns a message as ham (not spam) asynchronously.
//
// Example:
//
//	cfg := NewConfig("http://localhost:11333")
//	envelope := NewEnvelopeData()
//	email := []byte("...")
//
//	err := LearnHamAsync(context.Background(), cfg, email, envelope)
//	if err != nil {
//		return err
//	}
func LearnHamAsync(ctx context.Context, cfg *Config, body []byte, envelopeData *EnvelopeData) error {
	return client.LearnHamAsync(ctx, cfg, body, envelopeData)
}
