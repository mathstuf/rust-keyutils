#!/bin/sh

set -e

readonly version="0.12.4"
readonly sha256sum="a9537853c7bbc2fa6ffb4b71899b44f3b49dd0a1f2d80819d89c581b961dcdde"
readonly filename="cargo-tarpaulin-$version-travis"
readonly tarball="$filename.tar.gz"

cd .ci

echo "$sha256sum  $tarball" > tarpaulin.sha256sum
curl -OL "https://github.com/xd009642/tarpaulin/releases/download/$version/$tarball"
sha256sum --check tarpaulin.sha256sum
tar xf "$tarball"
