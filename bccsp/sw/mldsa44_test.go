/*
Copyright University of Utah. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package sw

import (
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/stretchr/testify/require"
)

func TestMLDSA44SignVerifyAndImport(t *testing.T) {
	csp, err := NewWithParams(256, "SHA2", NewDummyKeyStore())
	require.NoError(t, err)

	privateKey, err := csp.KeyGen(&bccsp.MLDSA44KeyGenOpts{Temporary: true})
	require.NoError(t, err)
	publicKey, err := privateKey.PublicKey()
	require.NoError(t, err)

	message := []byte("fabric transaction bytes")
	signature, err := csp.Sign(privateKey, message, nil)
	require.NoError(t, err)
	require.Len(t, signature, mldsa44.SignatureSize)

	valid, err := csp.Verify(publicKey, signature, message, nil)
	require.NoError(t, err)
	require.True(t, valid)
	valid, err = csp.Verify(publicKey, signature, []byte("different"), nil)
	require.NoError(t, err)
	require.False(t, valid)

	publicBytes, err := publicKey.Bytes()
	require.NoError(t, err)
	require.Len(t, publicBytes, mldsa44.PublicKeySize)
	importedPublic, err := csp.KeyImport(publicBytes, &bccsp.MLDSA44PublicKeyImportOpts{Temporary: true})
	require.NoError(t, err)
	valid, err = csp.Verify(importedPublic, signature, message, nil)
	require.NoError(t, err)
	require.True(t, valid)

	nativePrivate := privateKey.(*mldsa44PrivateKey).privKey
	importedPrivate, err := csp.KeyImport(nativePrivate.Bytes(), &bccsp.MLDSA44PrivateKeyImportOpts{Temporary: true})
	require.NoError(t, err)
	require.Equal(t, privateKey.SKI(), importedPrivate.SKI())
}

func TestMLDSA44FileKeyStoreRoundTrip(t *testing.T) {
	keyStore, err := NewFileBasedKeyStore(nil, t.TempDir(), false)
	require.NoError(t, err)
	csp, err := NewWithParams(256, "SHA2", keyStore)
	require.NoError(t, err)

	privateKey, err := csp.KeyGen(&bccsp.MLDSA44KeyGenOpts{})
	require.NoError(t, err)
	loaded, err := csp.GetKey(privateKey.SKI())
	require.NoError(t, err)

	message := []byte("persisted signer")
	signature, err := csp.Sign(loaded, message, nil)
	require.NoError(t, err)
	publicKey, err := loaded.PublicKey()
	require.NoError(t, err)
	valid, err := csp.Verify(publicKey, signature, message, nil)
	require.NoError(t, err)
	require.True(t, valid)
}

func BenchmarkMLDSA44Sign(b *testing.B) {
	csp, err := NewWithParams(256, "SHA2", NewDummyKeyStore())
	require.NoError(b, err)
	privateKey, err := csp.KeyGen(&bccsp.MLDSA44KeyGenOpts{Temporary: true})
	require.NoError(b, err)
	message := make([]byte, 1<<10)
	b.ReportAllocs()
	b.SetBytes(int64(len(message)))
	b.ResetTimer()
	for b.Loop() {
		_, err := csp.Sign(privateKey, message, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMLDSA44Verify(b *testing.B) {
	csp, err := NewWithParams(256, "SHA2", NewDummyKeyStore())
	require.NoError(b, err)
	privateKey, err := csp.KeyGen(&bccsp.MLDSA44KeyGenOpts{Temporary: true})
	require.NoError(b, err)
	publicKey, err := privateKey.PublicKey()
	require.NoError(b, err)
	message := make([]byte, 1<<10)
	signature, err := csp.Sign(privateKey, message, nil)
	require.NoError(b, err)
	b.ReportAllocs()
	b.SetBytes(int64(len(message)))
	b.ResetTimer()
	for b.Loop() {
		valid, err := csp.Verify(publicKey, signature, message, nil)
		if err != nil || !valid {
			b.Fatalf("valid=%v err=%v", valid, err)
		}
	}
}
