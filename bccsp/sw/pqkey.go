/*
Copyright University of Utah. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding"
	"encoding/pem"
	"errors"
	"reflect"
	"strings"

	"github.com/cloudflare/circl/sign"
	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/hyperledger/fabric-lib-go/bccsp/pq"
)

// These wrappers tell MSP to pass full messages to the pure PQ schemes.
type pqPrivateKey struct{ privKey sign.PrivateKey }
type pqPublicKey struct{ pubKey sign.PublicKey }

func (k *pqPrivateKey) Bytes() ([]byte, error) {
	return nil, errors.New("private key export is not supported")
}
func (k *pqPrivateKey) SKI() []byte {
	if k.privKey == nil {
		return nil
	}
	return pqSKI(k.privKey.Public())
}
func (k *pqPrivateKey) Symmetric() bool                   { return false }
func (k *pqPrivateKey) Private() bool                     { return true }
func (k *pqPrivateKey) RequiresFullMessage() bool         { return true }
func (k *pqPrivateKey) CryptoPublicKey() crypto.PublicKey { return k.privKey.Public() }
func (k *pqPrivateKey) PublicKey() (bccsp.Key, error) {
	if k.privKey == nil {
		return nil, errors.New("invalid PQ private key")
	}
	return &pqPublicKey{pubKey: k.privKey.Public().(sign.PublicKey)}, nil
}
func (k *pqPublicKey) Bytes() ([]byte, error) {
	if k.pubKey == nil {
		return nil, errors.New("invalid PQ public key")
	}
	return k.pubKey.MarshalBinary()
}
func (k *pqPublicKey) SKI() []byte                       { return pqSKI(k.pubKey) }
func (k *pqPublicKey) Symmetric() bool                   { return false }
func (k *pqPublicKey) Private() bool                     { return false }
func (k *pqPublicKey) RequiresFullMessage() bool         { return true }
func (k *pqPublicKey) PublicKey() (bccsp.Key, error)     { return k, nil }
func (k *pqPublicKey) CryptoPublicKey() crypto.PublicKey { return k.pubKey }

func pqSKI(key crypto.PublicKey) []byte {
	a, raw, err := pq.MarshalPublicKey(key)
	if err != nil {
		return nil
	}
	// Keep legacy MLDSA44 filenames; distinguish equal-size SLH-DSA variants.
	h := sha256.New()
	if a.Name != bccsp.MLDSA44 {
		h.Write([]byte(a.Name))
		h.Write([]byte{0})
	}
	h.Write(raw)
	return h.Sum(nil)
}

func pqPEMAlgorithm(label string, private bool) (pq.Algorithm, bool) {
	for _, a := range pq.Algorithms() {
		expected := a.PEMType()
		if !private {
			expected = strings.Replace(expected, "PRIVATE KEY", "PUBLIC KEY", 1)
		}
		if label == expected {
			return a, true
		}
	}
	return pq.Algorithm{}, false
}

type pqNativeKey interface {
	encoding.BinaryMarshaler
	Scheme() sign.Scheme
}

func pqKeyToPEM(key pqNativeKey, pwd []byte, private bool) ([]byte, error) {
	if key == nil || (reflect.ValueOf(key).Kind() == reflect.Ptr && reflect.ValueOf(key).IsNil()) {
		return nil, errors.New("invalid PQ key")
	}
	a, ok := pq.Lookup(key.Scheme().Name())
	if !ok {
		return nil, errors.New("unsupported PQ scheme")
	}
	raw, err := key.MarshalBinary()
	if err != nil {
		return nil, err
	}
	label := a.PEMType()
	if !private {
		label = strings.Replace(label, "PRIVATE KEY", "PUBLIC KEY", 1)
	}
	block := &pem.Block{Type: label, Bytes: raw}
	// Honor the existing keystore password behavior for PQ keys too.
	if len(pwd) != 0 {
		block, err = x509.EncryptPEMBlock(rand.Reader, label, raw, pwd, x509.PEMCipherAES256)
		if err != nil {
			return nil, err
		}
	}
	return pem.EncodeToMemory(block), nil
}
