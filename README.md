# Rspamd Go Client

A fully-featured, asynchronous Go client for [Rspamd](https://rspamd.com/) spam filtering system with support for HTTPCrypt encryption.

[![Go Reference](https://pkg.go.dev/badge/github.com/rspamd/rspamdclient-go.svg)](https://pkg.go.dev/github.com/rspamd/rspamdclient-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/rspamd/rspamdclient-go)](https://goreportcard.com/report/github.com/rspamd/rspamdclient-go)

## Features

- ✅ **Full Rspamd API Support**: Scan, learn spam/ham, and all other operations
- 🔐 **HTTPCrypt Encryption**: End-to-end encryption with bug-to-bug compatibility with Rspamd's C implementation
- 🗜️ **ZSTD Compression**: Optional compression for better performance
- ⚡ **Async Operations**: Non-blocking operations using Go contexts and goroutines  
- 🔄 **Retry Logic**: Configurable retry attempts with exponential backoff
- 🌐 **Proxy Support**: HTTP/HTTPS proxy configuration
- 🔒 **TLS Support**: Secure connections with certificate validation
- 📊 **Comprehensive Response Parsing**: Full support for Rspamd's response format

## Cryptographic Implementation

This client implements Rspamd's custom HTTPCrypt protocol with:

- **X25519** Elliptic Curve Diffie-Hellman key exchange
- **HChaCha20** Key derivation (Rspamd-specific method)
- **XChaCha20-Poly1305** Authenticated encryption (24-byte nonces)
- **ZBase32** Encoding for keys (compatible with Rspamd's base32 format)
- **Blake2b-512** Hashing for key identification

The implementation maintains **bug-to-bug compatibility** with Rspamd's C implementation, including the specific cipher state management patterns used in the original code.

## Quick Start

### Installation

```bash
go get github.com/rspamd/rspamdclient-go
```

### Basic Usage

```go
package main

import (
    "context"
    "fmt"
    "log"

    rspamd "github.com/rspamd/rspamdclient-go"
)

func main() {
    // Create configuration
    cfg := rspamd.NewConfig("http://localhost:11333").
        WithTimeout(30.0).
        WithRetries(3)

    // Email to scan
    email := []byte(`From: test@example.com
To: recipient@example.com
Subject: Test Email

This is a test email for scanning.`)

    // Scan the email
    ctx := context.Background()
    response, err := rspamd.ScanAsync(ctx, cfg, email, nil)
    if err != nil {
        log.Fatalf("Scan failed: %v", err)
    }

    fmt.Printf("Action: %s, Score: %.2f\n", response.Action, response.Score)
}
```

### HTTPCrypt Encryption

```go
// Configure with HTTPCrypt encryption
cfg := rspamd.NewConfig("https://rspamd.example.com").
    WithEncryptionKey("your-base32-encoded-public-key").
    WithZSTD(true).  // Enable compression
    WithTimeout(30.0)

// All requests will be encrypted end-to-end
response, err := rspamd.ScanAsync(ctx, cfg, email, envelope)
```

### Advanced Configuration

```go
// Create envelope data for enhanced scanning
envelope := rspamd.NewEnvelopeData().
    WithFrom("sender@example.com").
    WithRcpt("recipient@example.com").
    WithIP("192.168.1.100").
    WithUser("username").
    WithHostname("mail.example.com")

// Full configuration with all options
cfg := rspamd.NewConfig("https://rspamd.example.com").
    WithEncryptionKey("k4nz984k36xmcynm1hr9kdbn6jhcxf4ggbrb1quay7f88rpm9kay").
    WithPassword("secret").
    WithZSTD(true).
    WithTimeout(30.0).
    WithRetries(5).
    WithTLS(&rspamd.TLSConfig{
        CAPath: "/path/to/ca.pem",
    }).
    WithProxy(&rspamd.ProxyConfig{
        ProxyURL: "http://proxy.example.com:8080",
        Username: "user",
        Password: "pass",
    })

// Scan with full configuration
response, err := rspamd.ScanAsync(ctx, cfg, email, envelope)
if err != nil {
    log.Fatalf("Scan failed: %v", err)
}

// Process response
fmt.Printf("Action: %s\n", response.Action)
fmt.Printf("Score: %.2f / %.2f\n", response.Score, response.RequiredScore)
fmt.Printf("Scan Time: %.4fs\n", response.ScanTime)

// Check detected symbols
for name, symbol := range response.Symbols {
    fmt.Printf("Symbol: %s (score: %.2f)\n", name, symbol.Score)
}
```

## API Reference

### Configuration

| Method | Description |
|--------|-------------|
| `NewConfig(baseURL)` | Create new configuration with server URL |
| `WithEncryptionKey(key)` | Enable HTTPCrypt with base32-encoded public key |
| `WithPassword(password)` | Set authentication password |
| `WithZSTD(enabled)` | Enable/disable ZSTD compression |
| `WithTimeout(seconds)` | Set request timeout |
| `WithRetries(count)` | Set retry attempts |
| `WithTLS(config)` | Configure TLS settings |
| `WithProxy(config)` | Configure HTTP proxy |

### Main Operations

| Function | Description |
|----------|-------------|
| `ScanAsync(ctx, cfg, email, envelope)` | Scan email for spam |
| `LearnSpamAsync(ctx, cfg, email, envelope)` | Learn email as spam |
| `LearnHamAsync(ctx, cfg, email, envelope)` | Learn email as ham |

### Envelope Data

```go
envelope := rspamd.NewEnvelopeData().
    WithFrom("sender@example.com").        // MAIL FROM
    WithRcpt("recipient@example.com").     // RCPT TO  
    WithIP("192.168.1.100").              // Client IP
    WithUser("username").                  // Authenticated user
    WithHostname("mail.example.com").     // Client hostname
    WithHelo("client.example.com")        // HELO/EHLO
```

## Examples

The repository includes comprehensive examples:

- **[Basic Example](examples/basic/)**: Simple spam scanning
- **[Encrypted Example](examples/encrypted/)**: HTTPCrypt encryption with all options
- **[Demo](examples/demo/)**: Encryption demonstration and key generation

Run examples:

```bash
# Basic scanning
cd examples/basic && go run main.go

# Encrypted scanning  
cd examples/encrypted && go run encrypted_example.go --key "your-key"

# Encryption demo with key generation
cd examples/demo && go run encryption_demo.go --generate
```

## HTTPCrypt Protocol Details

This implementation provides complete compatibility with Rspamd's HTTPCrypt protocol:

### Request Structure

```
Outer HTTP Request:
POST /check HTTP/1.1
Key: remote_pk_id=local_ephemeral_key

[encrypted payload]

Inner HTTP Request (encrypted):
POST /check HTTP/1.1
Content-Encoding: zstd
Compression: zstd
Password: secret
Content-Length: 1234

[compressed email body]
```

### Key Header Format

- `remote_pk_id`: `base32(blake2b-512(server_public_key)[:5])`
- `local_ephemeral_key`: `zbase32(client_ephemeral_public_key)`

### Encryption Process

1. Generate ephemeral X25519 keypair
2. Perform ECDH with server's public key
3. Derive shared secret using HChaCha20
4. Compress inner request body (if ZSTD enabled)
5. Build inner HTTP request with compression headers
6. Encrypt inner request with XChaCha20-Poly1305
7. Create outer request with Key header and encrypted payload

## Testing

The library includes comprehensive tests for:

- Cryptographic compatibility with Rspamd's C implementation
- HTTPCrypt protocol correctness
- ZSTD compression handling
- Key header generation
- End-to-end encryption/decryption

```bash
go test ./...
```

## Requirements

- Go 1.19 or later
- Dependencies (automatically managed):
  - `golang.org/x/crypto`
  - `github.com/klauspost/compress/zstd`
  - `github.com/vstakhov/go-base32`

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass: `go test ./...`
2. Code follows Go standards: `go fmt ./...`
3. Compatibility with Rspamd's C implementation is maintained

## Compatibility

This client is tested against Rspamd 3.0+ and maintains full compatibility with:

- Rspamd's HTTPCrypt encryption protocol
- Custom cryptographic implementations
- Base32 encoding format (zbase32)
- Response JSON format

The cryptographic implementation passes all compatibility tests against Rspamd's C reference implementation.
