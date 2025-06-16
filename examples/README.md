# Rspamd Client Go Examples

This directory contains example programs demonstrating various features of the Rspamd Go client.

## Examples

### 1. Basic Usage (`basic/`)

Demonstrates basic email scanning without encryption.

```bash
cd basic
go run main.go
```

This example shows:
- Basic client configuration
- Email scanning
- Processing scan results
- Envelope data usage

### 2. HTTPCrypt Encryption (`encrypted/`)

Demonstrates encrypted communication with an Rspamd server using HTTPCrypt.

```bash
cd encrypted
go run encrypted_example.go --key <base32-encoded-public-key> [options]
```

**Options:**
- `--key`: Base32-encoded public key for HTTPCrypt encryption (required)
- `--url`: Rspamd server URL (default: http://localhost:11333)
- `--password`: Authentication password (optional)
- `--verbose`: Enable detailed output showing encryption steps
- `--help`: Show usage information

**Example:**
```bash
go run encrypted_example.go \
  --key 'jowatt6enih6dyna3j3o14dzbcsxefox5umbagicp5obiyuirafy' \
  --url https://rspamd.example.com \
  --verbose
```

This example shows:
- HTTPCrypt encryption configuration
- Secure client-server communication
- Encryption key validation
- Detailed encryption process logging

### 3. Encryption Demo (`demo/`)

Standalone utility demonstrating HTTPCrypt encryption without requiring a running server.

```bash
cd demo

# Generate a new keypair for testing
go run encryption_demo.go --generate

# Test encryption with a key
go run encryption_demo.go --key <base32-key> --verbose
```

**Options:**
- `--generate`: Generate a new X25519 keypair
- `--key`: Test encryption with provided base32 key
- `--verbose`: Show detailed encryption steps
- `--help`: Show usage information

**Features:**
- Generate X25519 keypairs for testing
- Demonstrate complete encryption/decryption cycle
- Verify cryptographic compatibility with Rspamd
- Show detailed technical information

**Example workflow:**
```bash
# Step 1: Generate keypair
go run encryption_demo.go --generate
# Output will show public and private keys

# Step 2: Test encryption with the public key
go run encryption_demo.go \
  --key 'jowatt6enih6dyna3j3o14dzbcsxefox5umbagicp5obiyuirafy' \
  --verbose
```

## Building All Examples

You can build all examples at once:

```bash
# From the examples directory
cd basic && go build . && cd ..
cd encrypted && go build . && cd ..
cd demo && go build . && cd ..
```

## Prerequisites

Make sure you have Go 1.21+ installed and the parent module dependencies are available:

```bash
# From the root go/ directory
go mod tidy
```

## Notes

- The **basic** example works without any external dependencies
- The **encrypted** example requires a running Rspamd server with HTTPCrypt support
- The **demo** example is completely standalone and perfect for testing encryption

## Cryptographic Details

All encryption examples demonstrate:
- X25519 Elliptic Curve Diffie-Hellman key exchange
- HChaCha20 key derivation (Rspamd-specific implementation)  
- XChaCha20-Poly1305 authenticated encryption
- zbase32 encoding for Rspamd compatibility
- Bug-to-bug compatibility with Rspamd's HTTPCrypt implementation 