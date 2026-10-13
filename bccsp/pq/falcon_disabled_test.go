//go:build !liboqs

/*
Copyright University of Utah. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pq

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFalconRequiresBuildTag(t *testing.T) {
	for _, name := range []string{"Falcon-512", "Falcon-1024", "Falcon-padded-512", "Falcon-padded-1024"} {
		_, ok := Lookup(name)
		require.False(t, ok, "Falcon must not silently select another backend")
	}
}
