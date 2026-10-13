/*
Copyright University of Utah. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/hyperledger/fabric-lib-go/bccsp/pq"
	"github.com/hyperledger/fabric-lib-go/bccsp/signer"
	"github.com/stretchr/testify/require"
)

func TestPQVariants(t *testing.T) {
	for _, a := range pq.Algorithms() {
		t.Run(a.Name, func(t *testing.T) {
			csp, err := NewWithParams(256, "SHA2", NewDummyKeyStore())
			require.NoError(t, err)
			key, err := csp.KeyGen(&bccsp.PQKeyGenOpts{Scheme: a.Name, Temporary: true})
			require.NoError(t, err)
			pub, err := key.PublicKey()
			require.NoError(t, err)
			raw, err := pub.Bytes()
			require.NoError(t, err)
			require.Len(t, raw, a.Scheme().PublicKeySize())
			imported, err := csp.KeyImport(raw, &bccsp.PQPublicKeyImportOpts{Scheme: a.Name, Temporary: true})
			require.NoError(t, err)
			_, err = csp.KeyImport(raw[:len(raw)-1], &bccsp.PQPublicKeyImportOpts{Scheme: a.Name, Temporary: true})
			require.Error(t, err)
			private, err := key.(*pqPrivateKey).privKey.MarshalBinary()
			require.NoError(t, err)
			require.Len(t, private, a.Scheme().PrivateKeySize())
			_, err = csp.KeyImport(private[:len(private)-1], &bccsp.PQPrivateKeyImportOpts{Scheme: a.Name, Temporary: true})
			require.Error(t, err)
			bridge, err := signer.New(csp, key)
			require.NoError(t, err)
			msg := []byte("full Fabric message")
			sig, err := bridge.Sign(rand.Reader, msg, crypto.Hash(0))
			require.NoError(t, err)
			require.True(t, pq.ValidSignatureSize(a.Scheme(), len(sig)))
			for _, k := range []bccsp.Key{key, imported} {
				valid, err := csp.Verify(k, sig, msg, nil)
				require.NoError(t, err)
				require.True(t, valid)
			}
			valid, err := csp.Verify(imported, sig, []byte("tampered"), nil)
			require.NoError(t, err)
			require.False(t, valid)
			valid, err = csp.Verify(imported, sig[:len(sig)-1], msg, nil)
			require.NoError(t, err)
			require.False(t, valid)
			_, err = csp.Sign(key, msg, crypto.SHA256)
			require.Error(t, err)
			_, err = csp.Verify(pub, sig, msg, crypto.SHA256)
			require.Error(t, err)
			_, err = key.Bytes()
			require.Error(t, err)
			// Both password modes must survive a fresh provider and cryptogen's filename.
			for _, pwd := range [][]byte{nil, []byte("test password")} {
				dir := t.TempDir()
				ks, err := NewFileBasedKeyStore(pwd, dir, false)
				require.NoError(t, err)
				stored, err := NewWithParams(256, "SHA2", ks)
				require.NoError(t, err)
				persisted, err := stored.KeyImport(private, &bccsp.PQPrivateKeyImportOpts{Scheme: a.Name})
				require.NoError(t, err)
				require.Equal(t, key.SKI(), persisted.SKI())
				path := filepath.Join(dir, hex.EncodeToString(key.SKI())+"_sk")
				info, err := os.Stat(path)
				require.NoError(t, err)
				require.Equal(t, os.FileMode(0600), info.Mode().Perm())
				fresh, err := NewFileBasedKeyStore(pwd, dir, false)
				require.NoError(t, err)
				reloaded, err := NewWithParams(256, "SHA2", fresh)
				require.NoError(t, err)
				loaded, err := reloaded.GetKey(key.SKI())
				require.NoError(t, err)
				sig, err := reloaded.Sign(loaded, msg, nil)
				require.NoError(t, err)
				valid, err := csp.Verify(pub, sig, msg, nil)
				require.NoError(t, err)
				require.True(t, valid)
				require.NoError(t, os.Rename(path, filepath.Join(dir, "priv_sk")))
				loaded, err = reloaded.GetKey(key.SKI())
				require.NoError(t, err)
				require.True(t, loaded.Private())
				require.NoError(t, fresh.StoreKey(pub))
				loaded, err = reloaded.GetKey(pub.SKI())
				require.NoError(t, err)
				require.False(t, loaded.Private())
				valid, err = reloaded.Verify(loaded, sig, msg, nil)
				require.NoError(t, err)
				require.True(t, valid)
				if len(pwd) > 0 {
					wrong, err := NewFileBasedKeyStore([]byte("wrong"), dir, false)
					require.NoError(t, err)
					_, err = wrong.GetKey(pub.SKI())
					require.Error(t, err)
				}
			}
		})
	}
}

func TestPQVariantIdentityAndLegacy(t *testing.T) {
	csp, err := NewWithParams(256, "SHA2", NewDummyKeyStore())
	require.NoError(t, err)
	a, _ := pq.Lookup("SLH-DSA-SHA2-128s")
	pub, _, err := a.Scheme().GenerateKey()
	require.NoError(t, err)
	raw, err := pub.MarshalBinary()
	require.NoError(t, err)
	first, err := csp.KeyImport(raw, &bccsp.PQPublicKeyImportOpts{Scheme: a.Name, Temporary: true})
	require.NoError(t, err)
	second, err := csp.KeyImport(raw, &bccsp.PQPublicKeyImportOpts{Scheme: "SLH-DSA-SHA2-128f", Temporary: true})
	require.NoError(t, err)
	require.NotEqual(t, first.SKI(), second.SKI())
	legacy, err := csp.KeyGen(&bccsp.MLDSA44KeyGenOpts{Temporary: true})
	require.NoError(t, err)
	generic, err := csp.KeyImport(legacy.(*mldsa44PrivateKey).privKey.Bytes(), &bccsp.PQPrivateKeyImportOpts{Scheme: bccsp.MLDSA44, Temporary: true})
	require.NoError(t, err)
	require.Equal(t, legacy.SKI(), generic.SKI())
	msg := []byte("legacy compatibility")
	old, err := csp.Sign(legacy, msg, nil)
	require.NoError(t, err)
	current, err := csp.Sign(generic, msg, nil)
	require.NoError(t, err)
	require.Equal(t, old, current)
	_, err = csp.KeyGen(&bccsp.PQKeyGenOpts{Scheme: "unknown", Temporary: true})
	require.Error(t, err)
	_, err = csp.KeyImport(raw, &bccsp.PQPublicKeyImportOpts{Scheme: "unknown", Temporary: true})
	require.Error(t, err)
	_, err = csp.KeyImport(raw, &bccsp.PQPrivateKeyImportOpts{Scheme: "unknown", Temporary: true})
	require.Error(t, err)
}
