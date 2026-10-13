# Copyright IBM Corp All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# -------------------------------------------------------------
# This makefile defines the followng targets

#   - all (default) - runs checks and unit-tests
#   - unit-test     - runs the go-test based unit tests
#   - checks        - runs vet and go format checks

GOTOOLS_BINDIR ?= $(shell go env GOPATH)/bin
# Let check scripts find the tools installed by this Makefile.
export PATH := $(abspath $(GOTOOLS_BINDIR)):$(PATH)
LIBOQS_PREFIX ?= $(abspath build/liboqs)
# SLH-DSA tests need more time when race detection and coverage are enabled.
export GO_TEST_TIMEOUT ?= 30m

.PHONY: all checks

all: checks unit-tests

checks: license vet gotools fmtcheck

.PHONY: fmtcheck
fmtcheck: gotools
	@echo "Checking source code formatting..."
	@scripts/check-go-formatting.sh

.PHONY: license
license:
	@echo "Checking for license headers..."
	@scripts/check-license.sh

.PHONY: vet
vet:
	@echo "Running go vet..."
	@scripts/run-go-vet.sh

.PHONY: gotools
gotools:
	@echo "Installing goimports..."
	@cd tools && GOBIN=$(abspath $(GOTOOLS_BINDIR)) go install golang.org/x/tools/cmd/goimports

.PHONY: unit-tests
unit-tests:
	@echo "Running unit tests..."
	@scripts/run-unit-tests.sh

# Keep native dependencies in the ignored build tree; ordinary builds stay unchanged.
.PHONY: liboqs build-pq test-pq
liboqs: $(LIBOQS_PREFIX)/lib/pkgconfig/liboqs.pc

$(LIBOQS_PREFIX)/lib/pkgconfig/liboqs.pc: scripts/build-liboqs.sh
	scripts/build-liboqs.sh "$(LIBOQS_PREFIX)"

build-pq: liboqs
	CGO_ENABLED=1 PKG_CONFIG_PATH="$(LIBOQS_PREFIX)/lib/pkgconfig:$(PKG_CONFIG_PATH)" go build -mod=vendor -tags liboqs ./...

test-pq: liboqs
	CGO_ENABLED=1 PKG_CONFIG_PATH="$(LIBOQS_PREFIX)/lib/pkgconfig:$(PKG_CONFIG_PATH)" go test -timeout "$(GO_TEST_TIMEOUT)" -mod=vendor -tags liboqs ./bccsp/...
