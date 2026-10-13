# Building the optional Falcon backend

ML-DSA and SLH-DSA use the vendored CIRCL Go module. Falcon uses our Go adapter
and a separately built liboqs C library. Ordinary Go builds do not enable Falcon.

On Linux, install Go (at least the version in `go.mod`), a C compiler, Make,
CMake, pkg-config, curl, tar, and sha256sum. From this repository:

```sh
make build-pq test-pq
```

The first run downloads and checksum-verifies liboqs 0.15.0, then builds only
the four Falcon variants. The native installation stays in ignored
`build/liboqs`; do not commit generated headers, archives, or binaries.
The helper is also shipped in Fabric's `scripts/build-liboqs.sh` so either
repository can bootstrap independently; keep the two copies identical.

To reuse an installation built with the helper, pass an absolute prefix:

```sh
make build-pq test-pq LIBOQS_PREFIX=/absolute/path/to/liboqs-install
```

For direct Go commands, configure the native dependency explicitly:

```sh
export CGO_ENABLED=1
export PKG_CONFIG_PATH="$PWD/build/liboqs/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
go test -mod=vendor -tags liboqs ./bccsp/...
```

For an offline setup, supply the previously downloaded release archive:

```sh
LIBOQS_ARCHIVE=/absolute/path/to/liboqs-0.15.0.tar.gz make build-pq test-pq
```

The checksum is still verified. Go dependencies and build tools must already
be available. `go mod vendor` does not install liboqs; it only copies Go module
dependencies. The native library is linked statically into consumers.

Publish the library commit before pinning it in Fabric or a Gateway application.
Consumers need both the Go changes and the `liboqs` build tag to use Falcon.

## Test timeouts

`make` runs unit tests with race detection and coverage, which slow down the
SLH-DSA variants. Unit tests and `make test-pq` allow 30 minutes per package.
Override this limit on slower machines with `make GO_TEST_TIMEOUT=45m`.
Direct Go test commands still need an explicit `-timeout 30m` if the default
10-minute limit is insufficient. Wrong-password tests deliberately log PEM
decryption errors; these messages alone do not indicate a failed test.
