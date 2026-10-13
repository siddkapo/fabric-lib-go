//go:build liboqs && cgo

/*
Copyright University of Utah. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pq

import (
	"crypto"
	"crypto/rand"
	"encoding/asn1"
	"sync"
	"testing"

	"github.com/cloudflare/circl/sign"
	"github.com/stretchr/testify/require"
)

func TestFalconBackend(t *testing.T) {
	require.Len(t, Algorithms(), 19)
	for _, tc := range []struct {
		name                        string
		oid, public, secret, maxSig int
	}{
		{"Falcon-512", 11, 897, 1281, 752}, {"Falcon-1024", 14, 1793, 2305, 1462},
		{"Falcon-padded-512", 16, 897, 1281, 666}, {"Falcon-padded-1024", 19, 1793, 2305, 1280},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, ok := Lookup(tc.name)
			require.True(t, ok)
			require.Equal(t, asn1.ObjectIdentifier{1, 3, 9999, 3, tc.oid}, a.OID())
			oid := a.OID()
			oid[0] = 0
			require.Equal(t, 1, a.OID()[0])
			s := a.Scheme()
			require.Equal(t, tc.public, s.PublicKeySize())
			require.Equal(t, 5+tc.secret+tc.public, s.PrivateKeySize())
			require.Equal(t, tc.maxSig, s.SignatureSize())
			require.False(t, s.SupportsContext())
			require.Panics(t, func() { s.DeriveKey(nil) })
			pub, priv, err := s.GenerateKey()
			require.NoError(t, err)
			raw, err := priv.MarshalBinary()
			require.NoError(t, err)
			loaded, err := s.UnmarshalBinaryPrivateKey(raw)
			require.NoError(t, err)
			require.True(t, priv.Equal(loaded))
			require.True(t, pub.Equal(loaded.Public()))
			for _, msg := range [][]byte{nil, []byte("Falcon transaction")} {
				signature, err := priv.Sign(rand.Reader, msg, crypto.Hash(0))
				require.NoError(t, err)
				require.True(t, ValidSignatureSize(s, len(signature)))
				require.True(t, s.Verify(pub, msg, signature, nil))
				require.False(t, s.Verify(pub, []byte("wrong"), signature, nil))
				require.False(t, s.Verify(pub, msg, signature[:len(signature)-1], nil))
				require.False(t, s.Verify(pub, msg, append(signature, 0), nil))
				signature[0] ^= 1
				require.False(t, s.Verify(pub, msg, signature, nil))
			}
			_, err = priv.Sign(rand.Reader, []byte("digest"), crypto.SHA256)
			require.Error(t, err)
			require.Panics(t, func() { s.Sign(priv, nil, &sign.SignatureOpts{Context: "unsupported"}) })
			require.False(t, s.Verify(pub, nil, nil, &sign.SignatureOpts{Context: "unsupported"}))
			require.False(t, ValidSignatureSize(s, 0))
			require.False(t, ValidSignatureSize(s, tc.maxSig+1))
			for _, index := range []int{0, 3, 4, 5} {
				bad := append([]byte(nil), raw...)
				bad[index] ^= 1
				_, err = s.UnmarshalBinaryPrivateKey(bad)
				require.Error(t, err)
			}
			otherPub, _, err := s.GenerateKey()
			require.NoError(t, err)
			otherRaw, err := otherPub.MarshalBinary()
			require.NoError(t, err)
			bad := append([]byte(nil), raw...)
			copy(bad[5+tc.secret:], otherRaw)
			_, err = s.UnmarshalBinaryPrivateKey(bad)
			require.ErrorContains(t, err, "pair does not match")
			// Serialization returns copies, and operations do not share mutable C handles.
			raw[5] ^= 1
			require.True(t, priv.Equal(loaded))
			var wg sync.WaitGroup
			for i := 0; i < 4; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					msg := []byte("concurrent")
					sig, err := priv.Sign(rand.Reader, msg, nil)
					if err != nil || !s.Verify(pub, msg, sig, nil) {
						t.Error("concurrent Falcon signing failed", err)
					}
				}()
			}
			wg.Wait()
		})
	}
}
