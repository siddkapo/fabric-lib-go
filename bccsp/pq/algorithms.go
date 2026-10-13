/*
Copyright University of Utah. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package pq describes the pure PQ keys carried in enrollment certificates.
package pq

import (
	"crypto"
	"encoding"
	"encoding/asn1"
	"fmt"
	"reflect"
	"strings"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/cloudflare/circl/sign/slhdsa"
)

// Algorithm keeps issuance, key storage, and extension parsing in agreement.
type Algorithm struct {
	Name    string
	oid     asn1.ObjectIdentifier
	pemName string
	scheme  sign.Scheme
}

// CIRCL pure schemes are always available; tagged backends register additional schemes.
var algorithms = []Algorithm{
	{"MLDSA44", nistSignatureOID(17), "ML-DSA-44", mldsa44.Scheme()},
	{"MLDSA65", nistSignatureOID(18), "ML-DSA-65", mldsa65.Scheme()},
	{"MLDSA87", nistSignatureOID(19), "ML-DSA-87", mldsa87.Scheme()},
	{"SLH-DSA-SHA2-128s", nistSignatureOID(20), "SLH-DSA-SHA2-128s", slhdsa.SHA2_128s.Scheme()},
	{"SLH-DSA-SHA2-128f", nistSignatureOID(21), "SLH-DSA-SHA2-128f", slhdsa.SHA2_128f.Scheme()},
	{"SLH-DSA-SHA2-192s", nistSignatureOID(22), "SLH-DSA-SHA2-192s", slhdsa.SHA2_192s.Scheme()},
	{"SLH-DSA-SHA2-192f", nistSignatureOID(23), "SLH-DSA-SHA2-192f", slhdsa.SHA2_192f.Scheme()},
	{"SLH-DSA-SHA2-256s", nistSignatureOID(24), "SLH-DSA-SHA2-256s", slhdsa.SHA2_256s.Scheme()},
	{"SLH-DSA-SHA2-256f", nistSignatureOID(25), "SLH-DSA-SHA2-256f", slhdsa.SHA2_256f.Scheme()},
	{"SLH-DSA-SHAKE-128s", nistSignatureOID(26), "SLH-DSA-SHAKE-128s", slhdsa.SHAKE_128s.Scheme()},
	{"SLH-DSA-SHAKE-128f", nistSignatureOID(27), "SLH-DSA-SHAKE-128f", slhdsa.SHAKE_128f.Scheme()},
	{"SLH-DSA-SHAKE-192s", nistSignatureOID(28), "SLH-DSA-SHAKE-192s", slhdsa.SHAKE_192s.Scheme()},
	{"SLH-DSA-SHAKE-192f", nistSignatureOID(29), "SLH-DSA-SHAKE-192f", slhdsa.SHAKE_192f.Scheme()},
	{"SLH-DSA-SHAKE-256s", nistSignatureOID(30), "SLH-DSA-SHAKE-256s", slhdsa.SHAKE_256s.Scheme()},
	{"SLH-DSA-SHAKE-256f", nistSignatureOID(31), "SLH-DSA-SHAKE-256f", slhdsa.SHAKE_256f.Scheme()},
}

// Algorithms returns a copy so callers cannot change the supported algorithms.
func Algorithms() []Algorithm { return append([]Algorithm(nil), algorithms...) }

// Lookup accepts cryptogen names and preserves the existing MLDSA44 identifier.
func Lookup(name string) (Algorithm, bool) {
	for _, a := range algorithms {
		if strings.EqualFold(name, a.Name) || strings.EqualFold(name, a.pemName) {
			return a, true
		}
	}
	return Algorithm{}, false
}

// OID identifies the exact scheme; certificate parameters stay absent.
func (a Algorithm) OID() asn1.ObjectIdentifier {
	return append(asn1.ObjectIdentifier(nil), a.oid...)
}

// 2.16.840.1.101.3.4.3 is NIST's signature branch; the last integer selects the variant.
// Registry: https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
func nistSignatureOID(variant int) asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, variant}
}

// ValidSignatureSize accepts a bounded variable size only when the backend declares it.
func ValidSignatureSize(scheme sign.Scheme, size int) bool {
	if variable, ok := scheme.(interface{ ValidSignatureSize(int) bool }); ok {
		return variable.ValidSignatureSize(size)
	}
	return size == scheme.SignatureSize()
}

// PEMType records the exact variant; raw SLH-DSA key bytes do not identify it.
func (a Algorithm) PEMType() string { return a.pemName + " PRIVATE KEY" }

// GenerateKey uses the selected backend.
func (a Algorithm) GenerateKey() (crypto.Signer, error) {
	_, key, err := a.scheme.GenerateKey()
	return key, err
}

// ParsePrivateKey lets the scheme supply the variant when decoding raw bytes.
func (a Algorithm) ParsePrivateKey(raw []byte) (crypto.Signer, error) {
	return a.scheme.UnmarshalBinaryPrivateKey(raw)
}

// ValidatePublicKey checks encoding, not possession of the matching private key.
func (a Algorithm) ValidatePublicKey(raw []byte) error {
	// The backend supplies the key size for each parameter set.
	if size := a.scheme.PublicKeySize(); len(raw) != size {
		return fmt.Errorf("invalid %s public key size: got %d, want %d", a.Name, len(raw), size)
	}
	_, err := a.scheme.UnmarshalBinaryPublicKey(raw)
	return err
}

// MarshalPublicKey derives the algorithm from the native key, never its size.
func MarshalPublicKey(key crypto.PublicKey) (Algorithm, []byte, error) {
	var name string
	switch k := key.(type) {
	case *mldsa44.PublicKey:
		if k != nil {
			name = "MLDSA44"
		}
	case *mldsa65.PublicKey:
		if k != nil {
			name = "MLDSA65"
		}
	case *mldsa87.PublicKey:
		if k != nil {
			name = "MLDSA87"
		}
	case slhdsa.PublicKey:
		name = k.ID.String()
	case *slhdsa.PublicKey:
		if k != nil {
			name = k.ID.String()
		}
	case sign.PublicKey:
		// Native backends identify their scheme; never infer it from key length.
		if k != nil && !(reflect.ValueOf(k).Kind() == reflect.Ptr && reflect.ValueOf(k).IsNil()) {
			name = k.Scheme().Name()
		}
	}
	a, ok := Lookup(name)
	if !ok {
		return Algorithm{}, nil, fmt.Errorf("unsupported PQ public key %T", key)
	}
	raw, err := key.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		return Algorithm{}, nil, err
	}
	if err := a.ValidatePublicKey(raw); err != nil {
		return Algorithm{}, nil, err
	}
	return a, raw, nil
}

// Scheme exposes the same backend to BCCSP and certificate tooling.
func (a Algorithm) Scheme() sign.Scheme { return a.scheme }
