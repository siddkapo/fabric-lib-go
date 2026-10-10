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
	oid     int
	pemName string
	scheme  sign.Scheme
}

// These are NIST's pure-scheme OIDs; prehash modes are not enabled by this registry.
var algorithms = []Algorithm{
	{"MLDSA44", 17, "ML-DSA-44", mldsa44.Scheme()},
	{"MLDSA65", 18, "ML-DSA-65", mldsa65.Scheme()},
	{"MLDSA87", 19, "ML-DSA-87", mldsa87.Scheme()},
	{"SLH-DSA-SHA2-128s", 20, "SLH-DSA-SHA2-128s", slhdsa.SHA2_128s.Scheme()},
	{"SLH-DSA-SHA2-128f", 21, "SLH-DSA-SHA2-128f", slhdsa.SHA2_128f.Scheme()},
	{"SLH-DSA-SHA2-192s", 22, "SLH-DSA-SHA2-192s", slhdsa.SHA2_192s.Scheme()},
	{"SLH-DSA-SHA2-192f", 23, "SLH-DSA-SHA2-192f", slhdsa.SHA2_192f.Scheme()},
	{"SLH-DSA-SHA2-256s", 24, "SLH-DSA-SHA2-256s", slhdsa.SHA2_256s.Scheme()},
	{"SLH-DSA-SHA2-256f", 25, "SLH-DSA-SHA2-256f", slhdsa.SHA2_256f.Scheme()},
	{"SLH-DSA-SHAKE-128s", 26, "SLH-DSA-SHAKE-128s", slhdsa.SHAKE_128s.Scheme()},
	{"SLH-DSA-SHAKE-128f", 27, "SLH-DSA-SHAKE-128f", slhdsa.SHAKE_128f.Scheme()},
	{"SLH-DSA-SHAKE-192s", 28, "SLH-DSA-SHAKE-192s", slhdsa.SHAKE_192s.Scheme()},
	{"SLH-DSA-SHAKE-192f", 29, "SLH-DSA-SHAKE-192f", slhdsa.SHAKE_192f.Scheme()},
	{"SLH-DSA-SHAKE-256s", 30, "SLH-DSA-SHAKE-256s", slhdsa.SHAKE_256s.Scheme()},
	{"SLH-DSA-SHAKE-256f", 31, "SLH-DSA-SHAKE-256f", slhdsa.SHAKE_256f.Scheme()},
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

// OID identifies the exact pure scheme; certificate parameters stay absent.
// The prefix 2.16.840.1.101.3.4.3 identifies NIST signature algorithms;
// the final integer selects the variant (e.g., 17 is ML-DSA-44).
// Registry: https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
func (a Algorithm) OID() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, a.oid}
}

// PEMType records the exact variant; raw SLH-DSA key bytes do not identify it.
func (a Algorithm) PEMType() string { return a.pemName + " PRIVATE KEY" }

// GenerateKey uses the selected scheme for both ML-DSA and SLH-DSA.
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
	// CIRCL is the source of key sizes for every parameter set.
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

// Scheme exposes the same CIRCL implementation to BCCSP and certificate tooling.
func (a Algorithm) Scheme() sign.Scheme { return a.scheme }
