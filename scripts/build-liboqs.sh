#!/usr/bin/env bash
# Copyright University of Utah. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

# Build only Falcon, statically, so binaries do not need liboqs.so at runtime.
install_prefix=${1:?Usage: build-liboqs.sh INSTALL_PREFIX}
mkdir -p "$install_prefix"
install_prefix=$(cd "$install_prefix" && pwd)
source_root=$(mktemp -d)
trap 'rm -rf -- "$source_root"' EXIT
archive="$source_root/liboqs.tar.gz"
if [[ -n ${LIBOQS_ARCHIVE:-} ]]; then
    cp "$LIBOQS_ARCHIVE" "$archive"
else
    curl --fail --location --retry 3 \
        https://codeload.github.com/open-quantum-safe/liboqs/tar.gz/refs/tags/0.15.0 \
        --output "$archive"
fi
# Pin the reviewed source, not a moving branch or an unchecked download.
printf '%s  %s\n' 3983f7cd1247f37fb76a040e6fd684894d44a84cecdcfbdb90559b3216684b5c "$archive" | sha256sum --check -
tar -xzf "$archive" -C "$source_root"
cmake -S "$source_root/liboqs-0.15.0" -B "$source_root/build" \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$install_prefix" \
    -DCMAKE_INSTALL_LIBDIR=lib -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DBUILD_SHARED_LIBS=OFF -DOQS_USE_OPENSSL=OFF -DOQS_DIST_BUILD=ON \
    -DOQS_BUILD_ONLY_LIB=ON \
    '-DOQS_MINIMAL_BUILD=SIG_falcon_512;SIG_falcon_1024;SIG_falcon_padded_512;SIG_falcon_padded_1024'
cmake --build "$source_root/build" --parallel "${CMAKE_BUILD_PARALLEL_LEVEL:-2}"
cmake --install "$source_root/build"
printf 'Set PKG_CONFIG_PATH=%s/lib/pkgconfig and build with CGO_ENABLED=1 and -tags liboqs.\n' "$install_prefix"
