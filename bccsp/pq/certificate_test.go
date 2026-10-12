/*
Copyright University of Utah. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pq

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding"
	"encoding/asn1"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEnrollmentPrivateKey(t *testing.T) {
	for _, a := range Algorithms() {
		t.Run(a.Name, func(t *testing.T) {
			key, err := a.GenerateKey()
			require.NoError(t, err)
			_, public, err := MarshalPublicKey(key.Public())
			require.NoError(t, err)
			info := alternatePublicKeyInfo{Algorithm: pkix.AlgorithmIdentifier{Algorithm: a.OID()}, PublicKey: asn1.BitString{Bytes: public, BitLength: len(public) * 8}}
			value, err := asn1.Marshal(info)
			require.NoError(t, err)
			cert := &x509.Certificate{Extensions: []pkix.Extension{{Id: oidSubjectAltPublicKeyInfo, Value: value}}}
			raw, err := key.(encoding.BinaryMarshaler).MarshalBinary()
			require.NoError(t, err)
			encoded := pem.EncodeToMemory(&pem.Block{Type: a.PEMType(), Bytes: raw})
			loaded, found, err := PrivateKeyFromPEM(cert, encoded)
			require.NoError(t, err)
			require.True(t, found)
			require.NotNil(t, loaded)
			_, roundtrip, err := MarshalPublicKey(loaded.Public())
			require.NoError(t, err)
			require.Equal(t, public, roundtrip)
			_, found, err = PrivateKeyFromPEM(cert, append(encoded, encoded...))
			require.Error(t, err)
			require.True(t, found)
			// Equal-sized key material must still match the certificate's public key.
			public[0] ^= 1
			cert.Extensions[0].Value, err = asn1.Marshal(info)
			require.NoError(t, err)
			_, found, err = PrivateKeyFromPEM(cert, encoded)
			require.ErrorContains(t, err, "does not match")
			require.True(t, found)
			cert.Extensions = append(cert.Extensions, cert.Extensions[0])
			_, found, err = PrivateKeyFromPEM(cert, encoded)
			require.ErrorContains(t, err, "duplicate")
			require.True(t, found)
		})
	}
	_, found, err := PrivateKeyFromPEM(&x509.Certificate{}, nil)
	require.NoError(t, err)
	require.False(t, found)
}
