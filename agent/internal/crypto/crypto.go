// Package crypto implements HMAC-SHA256 command signing/verification
// for the agent.
//
// The canonical signing string is byte-stable across languages:
//
//	{command_id}|{kind}|{target}|{ttl_sec}|{issued_at}
//
// This MUST match server/src/zaqorincore_server/crypto.py.
// Any change here must be mirrored there, and vice versa.
package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Canonical returns the byte sequence that gets HMACed. Exported so
// tests can assert byte-stability.
func Canonical(commandID, kind, target string, ttlSec int, issuedAt string) []byte {
	// strconv.Itoa matches Python's str() for int.
	return []byte(strings.Join([]string{
		commandID,
		kind,
		target,
		strconv.Itoa(ttlSec),
		issuedAt,
	}, "|"))
}

// Sign returns the lowercase hex-encoded HMAC-SHA256 of the canonical
// form under secret.
func Sign(secret, commandID, kind, target string, ttlSec int, issuedAt string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(Canonical(commandID, kind, target, ttlSec, issuedAt))
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify returns true iff hexSig is a valid HMAC of the canonical form
// under secret. Comparison is constant-time.
func Verify(secret, commandID, kind, target string, ttlSec int, issuedAt, hexSig string) bool {
	expected := Sign(secret, commandID, kind, target, ttlSec, issuedAt)
	got, err := hex.DecodeString(strings.ToLower(hexSig))
	if err != nil {
		return false
	}
	exp, err := hex.DecodeString(expected)
	if err != nil {
		return false
	}
	return hmac.Equal(got, exp)
}

// ParseHexMAC returns the bytes for a hex-encoded signature, validating
// length and hex. Exported for tests.
func ParseHexMAC(hexSig string) ([]byte, error) {
	if len(hexSig) != 64 {
		return nil, errors.New("hmac: expected 64 hex chars")
	}
	b, err := hex.DecodeString(strings.ToLower(hexSig))
	if err != nil {
		return nil, fmt.Errorf("hmac: invalid hex: %w", err)
	}
	return b, nil
}
