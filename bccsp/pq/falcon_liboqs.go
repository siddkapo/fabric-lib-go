//go:build liboqs && cgo

/*
Copyright University of Utah. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pq

/*
#cgo pkg-config: liboqs
#include <stdlib.h>
#include <oqs/oqs.h>
*/
import "C"

import (
	"bytes"
	"crypto"
	"crypto/subtle"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"unsafe"

	"github.com/cloudflare/circl/sign"
)

// Only liboqs-tagged builds register Falcon; CIRCL-only builds stay pure Go.
func init() {
	C.OQS_init()
	for i, variant := range []struct {
		name      string
		oid, logN int
		padded    bool
	}{
		{"Falcon-512", 11, 9, false}, {"Falcon-1024", 14, 10, false},
		{"Falcon-padded-512", 16, 9, true}, {"Falcon-padded-1024", 19, 10, true},
	} {
		native, err := openFalcon(variant.name)
		if err != nil {
			panic(err)
		}
		scheme := &falconScheme{name: variant.name, code: byte(i + 1), logN: byte(variant.logN), padded: variant.padded,
			publicSize: int(native.length_public_key), secretSize: int(native.length_secret_key), signatureSize: int(native.length_signature)}
		C.OQS_SIG_free(native)
		// OQS experimental identifiers, not NIST FN-DSA identifiers.
		// https://github.com/open-quantum-safe/oqs-provider/blob/main/oqs-template/generate.yml
		algorithms = append(algorithms, Algorithm{variant.name, asn1.ObjectIdentifier{1, 3, 9999, 3, variant.oid}, variant.name, scheme})
	}
}

type falconScheme struct {
	name                                  string
	code, logN                            byte
	padded                                bool
	publicSize, secretSize, signatureSize int
}

var _ sign.Scheme = (*falconScheme)(nil)

func (s *falconScheme) Name() string       { return s.name }
func (s *falconScheme) PublicKeySize() int { return s.publicSize }

// The versioned private encoding includes the public key; liboqs cannot derive it.
func (s *falconScheme) PrivateKeySize() int { return 5 + s.secretSize + s.publicSize }

// For unpadded Falcon this is the maximum, not an exact signature length.
func (s *falconScheme) SignatureSize() int { return s.signatureSize }
func (s *falconScheme) ValidSignatureSize(n int) bool {
	if s.padded {
		return n == s.signatureSize
	}
	return n > 41 && n <= s.signatureSize // Header and nonce precede compressed signature data.
}
func (s *falconScheme) SupportsContext() bool { return false }

// liboqs exposes no deterministic seeded key generation; never replace its global RNG.
func (s *falconScheme) SeedSize() int { return 0 }
func (s *falconScheme) DeriveKey([]byte) (sign.PublicKey, sign.PrivateKey) {
	panic("liboqs Falcon does not support seeded key derivation; use GenerateKey")
}

func openFalcon(name string) (*C.OQS_SIG, error) {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	native := C.OQS_SIG_new(cName)
	if native == nil {
		return nil, fmt.Errorf("liboqs algorithm %s is unavailable; enable all four Falcon variants", name)
	}
	return native, nil
}
func (s *falconScheme) native() (*C.OQS_SIG, error) {
	native, err := openFalcon(s.name)
	if err != nil {
		return nil, err
	}
	// Check sizes before allowing C to write into Go-owned buffers.
	if int(native.length_public_key) != s.publicSize || int(native.length_secret_key) != s.secretSize || int(native.length_signature) != s.signatureSize {
		C.OQS_SIG_free(native)
		return nil, errors.New("liboqs Falcon size mismatch")
	}
	return native, nil
}

// Calls never retain Go pointers. The non-nil sentinel permits empty messages.
var falconEmpty C.uint8_t

func falconBytes(data []byte) *C.uint8_t {
	if len(data) == 0 {
		return &falconEmpty
	}
	return (*C.uint8_t)(unsafe.Pointer(&data[0]))
}
func (s *falconScheme) GenerateKey() (sign.PublicKey, sign.PrivateKey, error) {
	native, err := s.native()
	if err != nil {
		return nil, nil, err
	}
	defer C.OQS_SIG_free(native)
	pub := make([]byte, s.publicSize)
	secret := make([]byte, s.secretSize)
	if C.OQS_SIG_keypair(native, falconBytes(pub), falconBytes(secret)) != C.OQS_SUCCESS {
		clear(secret)
		return nil, nil, errors.New("liboqs Falcon key generation failed")
	}
	return &falconPublicKey{s, pub}, &falconPrivateKey{s, secret, bytes.Clone(pub)}, nil
}
func (s *falconScheme) Sign(key sign.PrivateKey, msg []byte, opts *sign.SignatureOpts) []byte {
	if opts != nil && opts.Context != "" {
		panic(sign.ErrContextNotSupported)
	}
	private, ok := key.(*falconPrivateKey)
	if !ok || private == nil || private.scheme != s {
		panic(sign.ErrTypeMismatch)
	}
	// Scheme.Sign has no error result; crypto.Signer is used by Fabric to retain errors.
	signature, err := private.Sign(nil, msg, crypto.Hash(0))
	if err != nil {
		return nil
	}
	return signature
}
func (s *falconScheme) Verify(key sign.PublicKey, msg, signature []byte, opts *sign.SignatureOpts) bool {
	if opts != nil && opts.Context != "" {
		return false
	}
	public, ok := key.(*falconPublicKey)
	if !ok || public == nil || public.scheme != s || !s.ValidSignatureSize(len(signature)) {
		return false
	}
	native, err := s.native()
	if err != nil {
		return false
	}
	defer C.OQS_SIG_free(native)
	return C.OQS_SIG_verify(native, falconBytes(msg), C.size_t(len(msg)), falconBytes(signature), C.size_t(len(signature)), falconBytes(public.raw)) == C.OQS_SUCCESS
}
func (s *falconScheme) UnmarshalBinaryPublicKey(raw []byte) (sign.PublicKey, error) {
	if len(raw) != s.publicSize || raw[0] != s.logN {
		return nil, errors.New("invalid Falcon public key encoding")
	}
	return &falconPublicKey{s, bytes.Clone(raw)}, nil
}
func (s *falconScheme) UnmarshalBinaryPrivateKey(raw []byte) (sign.PrivateKey, error) {
	// FPQ, version 1, and variant code prevent accidental relabeling of equal-sized keys.
	if len(raw) != s.PrivateKeySize() || !bytes.Equal(raw[:5], []byte{'F', 'P', 'Q', 1, s.code}) || raw[5] != 0x50+s.logN {
		return nil, errors.New("invalid Falcon private key encoding")
	}
	pub := raw[5+s.secretSize:]
	if _, err := s.UnmarshalBinaryPublicKey(pub); err != nil {
		return nil, err
	}
	private := &falconPrivateKey{s, bytes.Clone(raw[5 : 5+s.secretSize]), bytes.Clone(pub)}
	// Reject a stored public key that does not belong to the secret key.
	challenge := []byte("Fabric Falcon private-key import v1")
	signature, err := private.Sign(nil, challenge, crypto.Hash(0))
	if err != nil || !s.Verify(private.Public().(sign.PublicKey), challenge, signature, nil) {
		clear(private.secret)
		return nil, errors.New("Falcon private/public key pair does not match")
	}
	return private, nil
}

type falconPublicKey struct {
	scheme *falconScheme
	raw    []byte
}

func (k *falconPublicKey) Scheme() sign.Scheme            { return k.scheme }
func (k *falconPublicKey) MarshalBinary() ([]byte, error) { return bytes.Clone(k.raw), nil }
func (k *falconPublicKey) Equal(other crypto.PublicKey) bool {
	value, ok := other.(*falconPublicKey)
	return ok && k != nil && value != nil && k.scheme == value.scheme && bytes.Equal(k.raw, value.raw)
}

type falconPrivateKey struct {
	scheme         *falconScheme
	secret, public []byte
}

func (k *falconPrivateKey) Scheme() sign.Scheme { return k.scheme }
func (k *falconPrivateKey) Public() crypto.PublicKey {
	return &falconPublicKey{k.scheme, bytes.Clone(k.public)}
}
func (k *falconPrivateKey) MarshalBinary() ([]byte, error) {
	raw := make([]byte, 0, k.scheme.PrivateKeySize())
	raw = append(raw, 'F', 'P', 'Q', 1, k.scheme.code)
	raw = append(raw, k.secret...)
	raw = append(raw, k.public...)
	return raw, nil
}
func (k *falconPrivateKey) Equal(other crypto.PrivateKey) bool {
	value, ok := other.(*falconPrivateKey)
	return ok && k != nil && value != nil && k.scheme == value.scheme && subtle.ConstantTimeCompare(k.secret, value.secret) == 1 && bytes.Equal(k.public, value.public)
}

// liboqs uses its own system RNG; the caller's reader is not installed globally.
func (k *falconPrivateKey) Sign(_ io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	if k == nil || k.scheme == nil {
		return nil, errors.New("invalid Falcon private key")
	}
	if opts != nil && opts.HashFunc() != 0 {
		return nil, errors.New("Falcon requires a full message, not a prehash")
	}
	native, err := k.scheme.native()
	if err != nil {
		return nil, err
	}
	defer C.OQS_SIG_free(native)
	signature := make([]byte, k.scheme.signatureSize)
	var length C.size_t
	if C.OQS_SIG_sign(native, falconBytes(signature), &length, falconBytes(msg), C.size_t(len(msg)), falconBytes(k.secret)) != C.OQS_SUCCESS {
		return nil, errors.New("liboqs Falcon signing failed")
	}
	if !k.scheme.ValidSignatureSize(int(length)) {
		return nil, errors.New("invalid liboqs Falcon signature length")
	}
	return signature[:int(length)], nil
}
