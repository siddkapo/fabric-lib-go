#!/bin/bash -eu

#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

# Keep race and coverage checks while allowing slower PQ variants to finish.
test_timeout=${GO_TEST_TIMEOUT:-30m}
time {
    go test -timeout "$test_timeout" -race -cover ./...
    go test -timeout "$test_timeout" -race -cover -tags "pkcs11" github.com/hyperledger/fabric-lib-go/bccsp/factory
    go test -timeout "$test_timeout" -race -cover -tags "pkcs11" github.com/hyperledger/fabric-lib-go/bccsp/pkcs11
}
