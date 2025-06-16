package protocol

import (
	"github.com/vstakhov/go-base32"
)

// Base32Encode encodes data using Rspamd's base32 format (zbase32 compatible)
func Base32Encode(data []byte) string {
	return base32.Encode(data)
}

// Base32Decode decodes data using Rspamd's base32 format (zbase32 compatible)
func Base32Decode(s string) ([]byte, error) {
	return base32.DecodeString(s)
}
