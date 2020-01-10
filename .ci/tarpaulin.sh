#!/bin/sh

set -e

readonly version="0.10.0"
readonly sha256sum="6843be8384bf14385b36a3118efc1ed2d25d531acb8df954cd3f93d44018b09e"
readonly filename="cargo-tarpaulin-$version-travis"
readonly tarball="$filename.tar.gz"

cd .ci

echo "$sha256sum  $tarball" > tarpaulin.sha256sum
curl -OL "https://github.com/xd009642/tarpaulin/releases/download/$version/$tarball"
sha256sum --check tarpaulin.sha256sum
tar xf "$tarball"
