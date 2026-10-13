/*
Copyright University of Utah. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign"
	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/hyperledger/fabric-lib-go/bccsp/pq"
)

// Shared adapters handle every backend in the PQ registry.
type pqKeyGenerator struct{}

func (*pqKeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	a, ok := pq.Lookup(opts.Algorithm())
	if !ok {
		return nil, fmt.Errorf("unsupported PQ scheme %q", opts.Algorithm())
	}
	_, key, err := a.Scheme().GenerateKey()
	if err != nil {
		return nil, err
	}
	return &pqPrivateKey{privKey: key}, nil
}

type pqPrivateKeyImporter struct{}
type pqPublicKeyImporter struct{}

func (*pqPrivateKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	a, data, err := pqImport(raw, opts)
	if err != nil {
		return nil, err
	}
	key, err := a.Scheme().UnmarshalBinaryPrivateKey(data)
	if err != nil {
		return nil, err
	}
	return &pqPrivateKey{privKey: key}, nil
}
func (*pqPublicKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	a, data, err := pqImport(raw, opts)
	if err != nil {
		return nil, err
	}
	key, err := a.Scheme().UnmarshalBinaryPublicKey(data)
	if err != nil {
		return nil, err
	}
	return &pqPublicKey{pubKey: key}, nil
}
func pqImport(raw interface{}, opts bccsp.KeyImportOpts) (pq.Algorithm, []byte, error) {
	a, ok := pq.Lookup(opts.Algorithm())
	if !ok {
		return a, nil, fmt.Errorf("unsupported PQ scheme %q", opts.Algorithm())
	}
	data, ok := raw.([]byte)
	if !ok || len(data) == 0 {
		return a, nil, errors.New("PQ key must be nonempty raw bytes")
	}
	return a, data, nil
}

func pqSignerOpts(opts bccsp.SignerOpts) error {
	// Pure schemes sign full messages with an empty context, never a caller-supplied hash.
	if opts != nil && opts.HashFunc() != 0 {
		return errors.New("pure PQ signatures require the full message, not a prehash")
	}
	return nil
}

type pqSigner struct{}

func (*pqSigner) Sign(k bccsp.Key, msg []byte, opts bccsp.SignerOpts) ([]byte, error) {
	key, ok := k.(*pqPrivateKey)
	if !ok || key == nil || key.privKey == nil {
		return nil, errors.New("invalid PQ private key")
	}
	if err := pqSignerOpts(opts); err != nil {
		return nil, err
	}
	scheme := key.privKey.Scheme()
	// crypto.Signer preserves backend errors, including liboqs failures.
	signature, err := key.privKey.Sign(rand.Reader, msg, crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	if !pq.ValidSignatureSize(scheme, len(signature)) {
		return nil, errors.New("PQ signing failed")
	}
	return signature, nil
}

type pqVerifier struct{}

func (*pqVerifier) Verify(k bccsp.Key, signature, msg []byte, opts bccsp.SignerOpts) (bool, error) {
	if err := pqSignerOpts(opts); err != nil {
		return false, err
	}
	var pub sign.PublicKey
	switch key := k.(type) {
	case *pqPrivateKey:
		if key != nil && key.privKey != nil {
			pub = key.privKey.Public().(sign.PublicKey)
		}
	case *pqPublicKey:
		if key != nil {
			pub = key.pubKey
		}
	}
	if pub == nil {
		return false, errors.New("invalid PQ verification key")
	}
	if !pq.ValidSignatureSize(pub.Scheme(), len(signature)) {
		return false, nil
	}
	return pub.Scheme().Verify(pub, msg, signature, nil), nil
}
