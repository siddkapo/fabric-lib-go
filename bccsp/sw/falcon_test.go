//go:build liboqs && cgo

/*
Copyright University of Utah. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"testing"

	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/stretchr/testify/require"
)

func TestFalconVariantSKI(t *testing.T) {
	csp, err := NewWithParams(256, "SHA2", NewDummyKeyStore())
	require.NoError(t, err)
	private, err := csp.KeyGen(&bccsp.PQKeyGenOpts{Scheme: bccsp.Falcon512, Temporary: true})
	require.NoError(t, err)
	public, err := private.PublicKey()
	require.NoError(t, err)
	raw, err := public.Bytes()
	require.NoError(t, err)
	padded, err := csp.KeyImport(raw, &bccsp.PQPublicKeyImportOpts{Scheme: bccsp.FalconPadded512, Temporary: true})
	require.NoError(t, err)
	require.NotEqual(t, public.SKI(), padded.SKI(), "padded and ordinary schemes must not share keystore entries")
	signature, err := csp.Sign(private, []byte("message"), nil)
	require.NoError(t, err)
	valid, err := csp.Verify(padded, signature, []byte("message"), nil)
	require.NoError(t, err)
	require.False(t, valid)
}
