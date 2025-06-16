// Package client provides asynchronous HTTP client for Rspamd
package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/rspamd/rspamdclient-go/config"
	"github.com/rspamd/rspamdclient-go/errors"
	"github.com/rspamd/rspamdclient-go/protocol"
)

// AsyncClient represents an asynchronous Rspamd client
type AsyncClient struct {
	config     *config.Config
	httpClient *http.Client
	encoder    *zstd.Encoder
	decoder    *zstd.Decoder
}

// NewAsyncClient creates a new asynchronous Rspamd client
func NewAsyncClient(cfg *config.Config) (*AsyncClient, error) {
	client := &http.Client{
		Timeout: time.Duration(cfg.Timeout * float64(time.Second)),
	}

	// Configure TLS if specified
	if cfg.TLSSettings != nil {
		tlsConfig := &tls.Config{}

		if cfg.TLSSettings.CAPath != nil {
			// Load CA certificate if specified
			caCert, err := os.ReadFile(*cfg.TLSSettings.CAPath)
			if err != nil {
				return nil, errors.NewConfigError(fmt.Sprintf("failed to read CA file: %v", err))
			}
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return nil, errors.NewConfigError("failed to append CA certificate")
			}
			tlsConfig.RootCAs = caCertPool
		}

		transport := &http.Transport{
			TLSClientConfig: tlsConfig,
		}
		client.Transport = transport
	}

	// Configure proxy if specified
	if cfg.ProxyConfig != nil {
		proxyURL, err := url.Parse(cfg.ProxyConfig.ProxyURL)
		if err != nil {
			return nil, errors.NewConfigError(fmt.Sprintf("invalid proxy URL: %v", err))
		}

		if cfg.ProxyConfig.Username != nil && cfg.ProxyConfig.Password != nil {
			proxyURL.User = url.UserPassword(*cfg.ProxyConfig.Username, *cfg.ProxyConfig.Password)
		}

		if client.Transport == nil {
			client.Transport = &http.Transport{}
		}
		transport := client.Transport.(*http.Transport)
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	asyncClient := &AsyncClient{
		config:     cfg,
		httpClient: client,
	}

	// Initialize ZSTD encoder/decoder if enabled
	if cfg.ZSTD {
		encoder, err := zstd.NewWriter(nil)
		if err != nil {
			return nil, errors.NewConfigError(fmt.Sprintf("failed to create ZSTD encoder: %v", err))
		}
		asyncClient.encoder = encoder

		decoder, err := zstd.NewReader(nil)
		if err != nil {
			return nil, errors.NewConfigError(fmt.Sprintf("failed to create ZSTD decoder: %v", err))
		}
		asyncClient.decoder = decoder
	}

	return asyncClient, nil
}

// Close closes the client and releases resources
func (c *AsyncClient) Close() error {
	if c.encoder != nil {
		c.encoder.Close()
	}
	if c.decoder != nil {
		c.decoder.Close()
	}
	return nil
}

// Request represents an HTTP request to Rspamd
type Request struct {
	endpoint     protocol.RspamdEndpoint
	client       *AsyncClient
	body         []byte
	envelopeData *config.EnvelopeData
}

// NewRequest creates a new request
func NewRequest(client *AsyncClient, body []byte, command protocol.RspamdCommand, envelopeData *config.EnvelopeData) *Request {
	return &Request{
		endpoint:     protocol.FromCommand(command),
		client:       client,
		body:         body,
		envelopeData: envelopeData,
	}
}

// Execute executes the request and returns the response
func (r *Request) Execute(ctx context.Context) (http.Header, []byte, error) {
	var retryCnt = r.client.config.Retries
	var sharedKey *protocol.RspamdNM

	for {
		// Build URL
		baseURL, err := url.Parse(r.client.config.BaseURL)
		if err != nil {
			return nil, nil, errors.NewParseError(err)
		}
		baseURL.Path = r.endpoint.URL

		// Determine HTTP method
		method := "GET"
		if r.endpoint.NeedBody {
			method = "POST"
		}

		// Declare request variable
		var req *http.Request

		// Handle encryption vs non-encryption flows differently
		if r.client.config.EncryptionKey != nil {
			// HTTPCrypt encryption flow - compression handled inside

			// Prepare inner request body (with compression if enabled)
			var innerBody []byte
			if r.endpoint.NeedBody {
				innerBody = r.body

				// Apply ZSTD compression to inner body if enabled
				if r.client.config.ZSTD && r.client.encoder != nil {
					compressed := r.client.encoder.EncodeAll(r.body, nil)
					innerBody = compressed
				}
			}

			// Build headers for inner request
			innerHeaders := make(map[string]string)

			// Set password header if configured
			if r.client.config.Password != nil {
				innerHeaders["Password"] = *r.client.config.Password
			}

			// Set compression headers for inner request if enabled
			if r.client.config.ZSTD {
				innerHeaders["Content-Encoding"] = "zstd"
				innerHeaders["Compression"] = "zstd"
			}

			// Add envelope data headers to inner request
			if r.envelopeData != nil {
				envelopeHeaders := r.envelopeData.ToHeaders()
				for k, v := range envelopeHeaders {
					innerHeaders[k] = v
				}
			}

			// Encrypt the request (HTTPCryptEncrypt will build the inner HTTP request)
			encrypted, err := protocol.HTTPCryptEncrypt(
				baseURL.Path,
				innerBody,
				innerHeaders,
				[]byte(*r.client.config.EncryptionKey),
			)
			if err != nil {
				return nil, nil, errors.NewEncryptionError(fmt.Sprintf("encryption failed: %v", err))
			}

			// Create outer HTTP request with only encrypted payload
			req, err = http.NewRequestWithContext(ctx, "POST", baseURL.String(), bytes.NewReader(encrypted.Body))
			if err != nil {
				return nil, nil, errors.NewHTTPErrorWithCause("failed to create encrypted request", err)
			}

			// Set Key header on outer request (required for HTTPCrypt)
			keyHeader, err := protocol.MakeKeyHeader(*r.client.config.EncryptionKey, encrypted.PeerKey)
			if err != nil {
				return nil, nil, errors.NewEncryptionError(fmt.Sprintf("failed to make key header: %v", err))
			}
			req.Header.Set("Key", keyHeader)
			sharedKey = &encrypted.SharedKey

		} else {
			// Non-encrypted flow - compression at outer level

			// Prepare request body
			var requestBody []byte
			if r.endpoint.NeedBody {
				requestBody = r.body

				// Apply ZSTD compression if enabled
				if r.client.config.ZSTD && r.client.encoder != nil {
					compressed := r.client.encoder.EncodeAll(r.body, nil)
					requestBody = compressed
				}
			}

			// Create HTTP request
			req, err = http.NewRequestWithContext(ctx, method, baseURL.String(), bytes.NewReader(requestBody))
			if err != nil {
				return nil, nil, errors.NewHTTPErrorWithCause("failed to create request", err)
			}

			// Set password header if configured
			if r.client.config.Password != nil {
				req.Header.Set("Password", *r.client.config.Password)
			}

			// Set compression headers if enabled
			if r.client.config.ZSTD {
				req.Header.Set("Content-Encoding", "zstd")
				req.Header.Set("Compression", "zstd")
			}

			// Add envelope data headers
			if r.envelopeData != nil {
				headers := r.envelopeData.ToHeaders()
				for k, v := range headers {
					req.Header.Set(k, v)
				}
			}
		}

		// Execute request
		resp, err := r.client.httpClient.Do(req)
		if err != nil {
			if retryCnt > 0 {
				retryCnt--
				// Sleep before retry
				select {
				case <-ctx.Done():
					return nil, nil, ctx.Err()
				case <-time.After(time.Duration(r.client.config.Timeout) * time.Second):
					continue
				}
			}
			return nil, nil, errors.NewHTTPErrorWithCause("request failed", err)
		}
		defer resp.Body.Close()

		// Check status code
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, nil, errors.NewHTTPError(fmt.Sprintf("HTTP %d: %s", resp.StatusCode, resp.Status))
		}

		// Read response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, nil, errors.NewIOError(err)
		}

		// Handle decryption if needed
		if sharedKey != nil {
			decryptedOffset, err := protocol.HTTPCryptDecrypt(body, *sharedKey)
			if err != nil {
				return nil, nil, errors.NewEncryptionError(fmt.Sprintf("decryption failed: %v", err))
			}

			// Parse decrypted HTTP response
			responseReader := bufio.NewReader(bytes.NewReader(body[decryptedOffset:]))

			// Read status line
			_, err = responseReader.ReadString('\n')
			if err != nil {
				return nil, nil, errors.NewHTTPError(fmt.Sprintf("failed to read status line: %v", err))
			}

			// Parse headers
			headers := make(http.Header)
			for {
				line, err := responseReader.ReadString('\n')
				if err != nil {
					if err == io.EOF {
						break
					}
					return nil, nil, errors.NewHTTPError(fmt.Sprintf("failed to read header: %v", err))
				}

				lineStr := strings.TrimSpace(line)
				if lineStr == "" {
					break // End of headers
				}

				parts := strings.SplitN(lineStr, ":", 2)
				if len(parts) == 2 {
					key := strings.TrimSpace(parts[0])
					value := strings.TrimSpace(parts[1])
					headers.Add(key, value)
				}
			}

			// Read remaining body
			remaining, err := io.ReadAll(responseReader)
			if err != nil {
				return nil, nil, errors.NewHTTPError(fmt.Sprintf("failed to read decrypted body: %v", err))
			}

			// Check if response is compressed
			if headers.Get("Compression") == "zstd" && r.client.decoder != nil {
				decompressed, err := r.client.decoder.DecodeAll(remaining, nil)
				if err != nil {
					return nil, nil, errors.NewHTTPError(fmt.Sprintf("ZSTD decompression failed: %v", err))
				}
				remaining = decompressed
			}

			return headers, remaining, nil
		}

		// Handle ZSTD decompression for non-encrypted responses
		if r.client.config.ZSTD && r.client.decoder != nil && resp.Header.Get("Content-Encoding") == "zstd" {
			decompressed, err := r.client.decoder.DecodeAll(body, nil)
			if err != nil {
				return nil, nil, errors.NewHTTPError(fmt.Sprintf("ZSTD decompression failed: %v", err))
			}
			body = decompressed
		}

		return resp.Header, body, nil
	}
}

// ScanAsync scans an email asynchronously and returns the parsed reply
func ScanAsync(ctx context.Context, cfg *config.Config, body []byte, envelopeData *config.EnvelopeData) (*protocol.RspamdScanReply, error) {
	client, err := NewAsyncClient(cfg)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	request := NewRequest(client, body, protocol.Scan, envelopeData)
	_, responseBody, err := request.Execute(ctx)
	if err != nil {
		return nil, err
	}

	var response protocol.RspamdScanReply
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return nil, errors.NewSerdeError(err)
	}

	return &response, nil
}

// LearnSpamAsync learns a message as spam
func LearnSpamAsync(ctx context.Context, cfg *config.Config, body []byte, envelopeData *config.EnvelopeData) error {
	client, err := NewAsyncClient(cfg)
	if err != nil {
		return err
	}
	defer client.Close()

	request := NewRequest(client, body, protocol.LearnSpam, envelopeData)
	_, _, err = request.Execute(ctx)
	return err
}

// LearnHamAsync learns a message as ham
func LearnHamAsync(ctx context.Context, cfg *config.Config, body []byte, envelopeData *config.EnvelopeData) error {
	client, err := NewAsyncClient(cfg)
	if err != nil {
		return err
	}
	defer client.Close()

	request := NewRequest(client, body, protocol.LearnHam, envelopeData)
	_, _, err = request.Execute(ctx)
	return err
}
