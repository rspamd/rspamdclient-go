// Package protocol contains encryption functions used by the HTTPCrypt protocol.
// This encryption uses x25519 and xchacha20-poly1305. While similar to RFC 8439,
// HTTPCrypt was designed before the RFC being published and uses a different way
// to do KEX and to derive shared keys.
// In general, it relies on hchacha20 for kdf, x25519 for key exchange, and
// XChaCha20 (with 24-byte nonces) for encryption.
package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/poly1305"
)

const (
	// It must be the same as Rspamd one, that is currently 5
	ShortKeyIDSize = 5
	NonceSize      = 24
	TagSize        = 16
	KeySize        = 32
)

// RspamdNM represents a shared secret key
type RspamdNM [32]byte

// RspamdSecretbox implements Rspamd's custom secretbox encryption
type RspamdSecretbox struct {
	encKey [32]byte
	macKey [32]byte
	nonce  [24]byte
}

// HTTPCryptEncrypted represents encrypted data with associated keys
type HTTPCryptEncrypted struct {
	Body      []byte
	PeerKey   string // Encoded as base32
	SharedKey RspamdNM
}

// NewRspamdSecretbox constructs new secretbox following Rspamd conventions
// This follows the exact pattern from Rspamd's C code in rspamd_cryptobox_auth_init
func NewRspamdSecretbox(key RspamdNM, nonce [24]byte) (*RspamdSecretbox, error) {
	// Create XChaCha20 cipher for encryption context
	encCipher, err := chacha20.NewUnauthenticatedCipher(key[:], nonce[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create XChaCha20 cipher: %w", err)
	}

	// Following Rspamd's C code pattern:
	// 1. Create 64-byte zero buffer (CHACHA_BLOCKBYTES)
	// 2. Run chacha_update on it to derive MAC key material
	// 3. Use first 32 bytes for Poly1305 initialization
	// 4. Continue using the same cipher context for encryption (important!)
	subkey := make([]byte, 64)             // CHACHA_BLOCKBYTES, zero-initialized
	encCipher.XORKeyStream(subkey, subkey) // chacha_update equivalent - advances cipher state

	rs := &RspamdSecretbox{
		encKey: key,
		nonce:  nonce,
	}

	// crypto_onetimeauth_init expects 32-byte key (first 32 bytes of subkey)
	copy(rs.macKey[:], subkey[:32])

	// Clear subkey for security (rspamd_explicit_memzero equivalent)
	for i := range subkey {
		subkey[i] = 0
	}

	return rs, nil
}

// EncryptInPlace encrypts data in place and returns a tag
// Creates fresh cipher and advances it by 64 bytes (matching Rspamd's pattern)
func (rs *RspamdSecretbox) EncryptInPlace(data []byte) ([16]byte, error) {
	// Create fresh cipher context (same as Rspamd does for each operation)
	encCipher, err := chacha20.NewUnauthenticatedCipher(rs.encKey[:], rs.nonce[:])
	if err != nil {
		return [16]byte{}, fmt.Errorf("failed to create XChaCha20 cipher: %w", err)
	}

	// Advance cipher by 64 bytes (same as MAC key derivation step)
	skipBytes := make([]byte, 64)
	encCipher.XORKeyStream(skipBytes, skipBytes)

	// Now encrypt the data (cipher is in the same state as during MAC key derivation)
	encCipher.XORKeyStream(data, data)

	// Compute MAC using Poly1305
	var tag [16]byte
	poly1305.Sum(&tag, data, &rs.macKey)

	return tag, nil
}

// DecryptInPlace decrypts in place if auth tag is correct
func (rs *RspamdSecretbox) DecryptInPlace(data []byte, tag [16]byte) error {
	// Verify MAC first
	var computedTag [16]byte
	poly1305.Sum(&computedTag, data, &rs.macKey)

	if computedTag != tag {
		return errors.New("authentication failed")
	}

	// For decryption, we need to recreate the same cipher state as used during encryption
	// This means: fresh cipher + MAC key derivation (64 bytes) + then decrypt the data
	decCipher, err := chacha20.NewUnauthenticatedCipher(rs.encKey[:], rs.nonce[:])
	if err != nil {
		return fmt.Errorf("failed to create XChaCha20 cipher for decryption: %w", err)
	}

	// Advance the cipher by the same 64 bytes used for MAC key derivation
	skipBytes := make([]byte, 64)
	decCipher.XORKeyStream(skipBytes, skipBytes)

	// Now decrypt the data (cipher is in the same state as during encryption)
	decCipher.XORKeyStream(data, data)

	return nil
}

// MakeKeyHeader creates the key header for HTTPCrypt
func MakeKeyHeader(remotePK, localPK string) (string, error) {
	remotePKBytes, err := Base32Decode(remotePK)
	if err != nil {
		return "", fmt.Errorf("base32 decode failed: %w", err)
	}

	hash := blake2b.Sum512(remotePKBytes)
	hashB32 := Base32Encode(hash[:ShortKeyIDSize])

	return fmt.Sprintf("%s=%s", hashB32, localPK), nil
}

// RspamdX25519Scalarmult performs scalar multiplication with a remote public key and a local secret key
func RspamdX25519Scalarmult(remotePK []byte, localSK [32]byte) (*[32]byte, error) {
	remotePKBytes, err := Base32Decode(string(remotePK))
	if err != nil {
		return nil, fmt.Errorf("base32 decode failed: %w", err)
	}

	if len(remotePKBytes) != 32 {
		return nil, errors.New("invalid remote public key length")
	}

	var remotePKArray [32]byte
	copy(remotePKArray[:], remotePKBytes)

	// Clamp the scalar as per X25519 spec (same as Rspamd does)
	clampedSK := localSK
	clampedSK[0] &= 248
	clampedSK[31] &= 127
	clampedSK[31] |= 64

	// Perform scalar multiplication
	sharedSecret, err := curve25519.X25519(clampedSK[:], remotePKArray[:])
	if err != nil {
		return nil, fmt.Errorf("X25519 failed: %w", err)
	}

	var result [32]byte
	copy(result[:], sharedSecret)
	return &result, nil
}

// RspamdX25519ECDH performs ECDH using Rspamd's custom method
// Unlike IETF version, Rspamd uses an old suggested way to derive a shared secret -
// it performs hchacha iteration on the point and a zeroed nonce.
func RspamdX25519ECDH(point *[32]byte) RspamdNM {
	// Zero nonce for hchacha20
	var nonce [16]byte // hchacha20 uses 16-byte nonce

	// Perform hchacha20 key derivation
	key := hchacha20(point[:], nonce[:])

	var nm RspamdNM
	copy(nm[:], key)
	return nm
}

// hchacha20 implements the HChaCha20 construction
func hchacha20(key, nonce []byte) []byte {
	if len(key) != 32 {
		panic("hchacha20: key must be 32 bytes")
	}
	if len(nonce) != 16 {
		panic("hchacha20: nonce must be 16 bytes")
	}

	// Constants for ChaCha20
	const (
		c0 = 0x61707865
		c1 = 0x3320646e
		c2 = 0x79622d32
		c3 = 0x6b206574
	)

	// Initialize state
	var state [16]uint32
	state[0] = c0
	state[1] = c1
	state[2] = c2
	state[3] = c3

	// Key
	for i := 0; i < 8; i++ {
		state[4+i] = binary.LittleEndian.Uint32(key[i*4:])
	}

	// Nonce
	for i := 0; i < 4; i++ {
		state[12+i] = binary.LittleEndian.Uint32(nonce[i*4:])
	}

	// 20 rounds of ChaCha20
	for i := 0; i < 10; i++ {
		// Column rounds
		quarterRound(&state[0], &state[4], &state[8], &state[12])
		quarterRound(&state[1], &state[5], &state[9], &state[13])
		quarterRound(&state[2], &state[6], &state[10], &state[14])
		quarterRound(&state[3], &state[7], &state[11], &state[15])

		// Diagonal rounds
		quarterRound(&state[0], &state[5], &state[10], &state[15])
		quarterRound(&state[1], &state[6], &state[11], &state[12])
		quarterRound(&state[2], &state[7], &state[8], &state[13])
		quarterRound(&state[3], &state[4], &state[9], &state[14])
	}

	// Return first and last 16 bytes (128 bits each)
	result := make([]byte, 32)
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint32(result[i*4:], state[i])
	}
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint32(result[16+i*4:], state[12+i])
	}

	return result
}

// quarterRound performs a ChaCha20 quarter round
func quarterRound(a, b, c, d *uint32) {
	*a += *b
	*d ^= *a
	*d = (*d << 16) | (*d >> 16)

	*c += *d
	*b ^= *c
	*b = (*b << 12) | (*b >> 20)

	*a += *b
	*d ^= *a
	*d = (*d << 8) | (*d >> 24)

	*c += *d
	*b ^= *c
	*b = (*b << 7) | (*b >> 25)
}

// encryptInPlace encrypts plaintext with a given peer public key generating an ephemeral keypair
func encryptInPlace(plaintext []byte, recipientPublicKey []byte, localSK [32]byte) ([]byte, RspamdNM, error) {
	// Perform X25519 scalar multiplication
	ecPoint, err := RspamdX25519Scalarmult(recipientPublicKey, localSK)
	if err != nil {
		return nil, RspamdNM{}, fmt.Errorf("X25519 scalarmult failed: %w", err)
	}

	// Derive shared secret using Rspamd's method
	nm := RspamdX25519ECDH(ecPoint)

	// Generate random nonce
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, RspamdNM{}, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Create secretbox
	sbox, err := NewRspamdSecretbox(nm, nonce)
	if err != nil {
		return nil, RspamdNM{}, fmt.Errorf("failed to create secretbox: %w", err)
	}

	// Prepare destination buffer: nonce + tag + ciphertext
	dest := make([]byte, NonceSize+TagSize+len(plaintext))
	copy(dest[:NonceSize], nonce[:])
	copy(dest[NonceSize+TagSize:], plaintext)

	// Encrypt in place
	tag, err := sbox.EncryptInPlace(dest[NonceSize+TagSize:])
	if err != nil {
		return nil, RspamdNM{}, fmt.Errorf("encryption failed: %w", err)
	}

	// Copy tag
	copy(dest[NonceSize:NonceSize+TagSize], tag[:])

	return dest, nm, nil
}

// HTTPCryptEncrypt encrypts data using HTTPCrypt protocol
func HTTPCryptEncrypt(url string, body []byte, headers map[string]string, peerKey []byte) (*HTTPCryptEncrypted, error) {
	// Generate ephemeral keypair
	var localSK [32]byte
	if _, err := rand.Read(localSK[:]); err != nil {
		return nil, fmt.Errorf("failed to generate local secret key: %w", err)
	}

	// Compute public key
	localPK, err := curve25519.X25519(localSK[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to compute public key: %w", err)
	}

	// Encode local public key for return
	localPKEncoded := Base32Encode(localPK)

	// Build inner HTTP request (without Key header - that goes in outer request)
	var dest []byte
	dest = append(dest, []byte("POST "+url+" HTTP/1.1\n")...)

	// Add headers to inner request
	for k, v := range headers {
		dest = append(dest, []byte(k+": "+v+"\n")...)
	}

	dest = append(dest, []byte(fmt.Sprintf("Content-Length: %d\n\n", len(body)))...)
	dest = append(dest, body...)

	// Encrypt the inner request
	encrypted, nm, err := encryptInPlace(dest, peerKey, localSK)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	return &HTTPCryptEncrypted{
		Body:      encrypted,
		PeerKey:   localPKEncoded,
		SharedKey: nm,
	}, nil
}

// HTTPCryptDecrypt decrypts body using HTTPCrypt algorithm
func HTTPCryptDecrypt(body []byte, nm RspamdNM) (int, error) {
	if len(body) < NonceSize+TagSize {
		return 0, errors.New("invalid body size")
	}

	// Extract nonce and tag
	var nonce [24]byte
	var tag [16]byte
	copy(nonce[:], body[:NonceSize])
	copy(tag[:], body[NonceSize:NonceSize+TagSize])

	// Create secretbox
	sbox, err := NewRspamdSecretbox(nm, nonce)
	if err != nil {
		return 0, fmt.Errorf("failed to create secretbox: %w", err)
	}

	// Decrypt in place
	decryptedData := body[NonceSize+TagSize:]
	if err := sbox.DecryptInPlace(decryptedData, tag); err != nil {
		return 0, fmt.Errorf("decryption failed: %w", err)
	}

	return NonceSize + TagSize, nil
}
