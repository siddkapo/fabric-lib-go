/*
Copyright University of Utah. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pq

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"

	"github.com/pkg/errors"
)

var oidSubjectAltPublicKeyInfo = asn1.ObjectIdentifier{2, 5, 29, 72}

type alternatePublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// AlternatePublicKey rejects malformed extensions instead of falling back to a classical key.
func AlternatePublicKey(cert *x509.Certificate) (string, []byte, bool, error) {
	var value []byte
	found := false
	for _, extension := range cert.Extensions {
		if !extension.Id.Equal(oidSubjectAltPublicKeyInfo) {
			continue
		}
		// Never select one of several conflicting keys or fall back to ECDSA.
		if found {
			return "", nil, true, errors.New("duplicate alternate public key extension")
		}
		value, found = extension.Value, true
	}
	if !found {
		return "", nil, false, nil
	}
	var info alternatePublicKeyInfo
	rest, err := asn1.Unmarshal(value, &info)
	if err != nil {
		return "", nil, true, errors.Wrap(err, "parse alternate public key extension")
	}
	if len(rest) != 0 {
		return "", nil, true, errors.New("trailing data in alternate public key extension")
	}
	if len(info.Algorithm.Parameters.FullBytes) != 0 {
		return "", nil, true, errors.New("alternate public key algorithm parameters must be absent")
	}
	if info.PublicKey.BitLength != len(info.PublicKey.Bytes)*8 {
		return "", nil, true, errors.New("alternate public key must be byte-aligned")
	}
	// Go's ASN.1 decoder can ignore extra sequence fields; require exact DER.
	canonical, err := asn1.Marshal(info)
	if err != nil || !bytes.Equal(canonical, value) {
		return "", nil, true, errors.New("non-canonical alternate public key extension")
	}
	for _, a := range Algorithms() {
		if info.Algorithm.Algorithm.Equal(a.OID()) {
			if err := a.ValidatePublicKey(info.PublicKey.Bytes); err != nil {
				return "", nil, true, err
			}
			return a.Name, info.PublicKey.Bytes, true, nil
		}
	}
	return "", nil, true, errors.Errorf("unsupported alternate public key algorithm OID %s", info.Algorithm.Algorithm)
}

// PrivateKeyFromPEM loads a PQ enrollment key and checks it against its certificate.
// A false result with no error leaves classical key loading to the caller.
func PrivateKeyFromPEM(cert *x509.Certificate, raw []byte) (crypto.Signer, bool, error) {
	name, public, found, err := AlternatePublicKey(cert)
	if err != nil || !found {
		return nil, found, err
	}
	a, _ := Lookup(name)
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != a.PEMType() || len(bytes.TrimSpace(rest)) != 0 {
		return nil, true, errors.New("private key PEM label does not match enrollment certificate or contains extra data")
	}
	// These clients have no password input; never interpret encrypted bytes as a key.
	if len(block.Headers) != 0 {
		return nil, true, errors.New("encrypted PQ private keys are not supported by this client")
	}
	key, err := a.ParsePrivateKey(block.Bytes)
	if err != nil {
		return nil, true, err
	}
	actual, encoded, err := MarshalPublicKey(key.Public())
	if err != nil {
		return nil, true, err
	}
	if actual.Name != name || !bytes.Equal(encoded, public) {
		return nil, true, errors.New("private key does not match enrollment certificate")
	}
	return key, true, nil
}
