//go:build liboqs && !cgo

/*
Copyright University of Utah. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pq

// A requested Falcon build must not silently omit its algorithms.
var _ = liboqs_requires_CGO_ENABLED_1
