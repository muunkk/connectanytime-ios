#!/bin/bash
# Tests openconnect-strap-cookie.patch on this Mac: OpenConnect hands the server a new key
# for the session (STRAP) on every reconnect, and the saved cookie has to carry it.
# Builds OpenConnect with Vendor/patches and runs Vendor/tests/strap-cookie-test.c against
# it. Then the negative control: the same test against OpenConnect without that patch,
# where it has to fail, since a test that passes either way proves nothing.
# Needs Homebrew's openssl@3 (3.5, as the iOS build uses), the Command Line Tools, and
# the OpenConnect tarball that Vendor/build-deps.sh downloads. Builds in
# Vendor/src/build-host, which Git ignores.
set -euo pipefail
export LC_ALL=C # the patches apply in the order build-deps.sh uses
cd "$(dirname "$0")/../Vendor"
TARBALL=src/openconnect-9.21.tar.gz
[ -f "$TARBALL" ] || { echo "Run Vendor/build-deps.sh first: it downloads OpenConnect."; exit 1; }
OSSL="$(brew --prefix openssl@3.5 2>/dev/null || brew --prefix openssl@3)"
SDK="$(xcrun --show-sdk-path)"
STRAP=patches/openconnect-strap-cookie.patch
[ -f "$STRAP" ] || { echo "$STRAP is missing"; exit 1; }
HOST="$PWD/src/build-host"

# build <name> <patch>...: OpenConnect with those patches in src/build-host/<name>,
# built again only when they change.
build() {
  local work="$HOST/$1" sum
  shift
  local oc="$work/openconnect-9.21"
  sum=$(cat "$@" | shasum -a 256 | awk '{print $1}')
  if [ "$(cat "$work/build.sha256" 2>/dev/null || true)" != "$sum" ]; then
    rm -rf "$work" && mkdir -p "$work"
    tar -xzf "$TARBALL" -C "$work"
    for p in "$@"; do patch -d "$oc" -p1 --forward -s < "$p"; done
    (cd "$oc"
      OPENSSL_CFLAGS="-I$OSSL/include" OPENSSL_LIBS="-L$OSSL/lib -lssl -lcrypto" \
      LIBXML2_CFLAGS="-I$SDK/usr/include/libxml2" LIBXML2_LIBS="-lxml2" ZLIB_CFLAGS=" " ZLIB_LIBS="-lz" \
      CC=/usr/bin/clang ./configure --enable-static --disable-shared --disable-nls --disable-docs \
        --without-gnutls --with-openssl --without-libpskc --without-stoken --without-libpcsclite \
        --without-libproxy --without-gssapi --without-lz4 --without-java \
        --with-vpnc-script=/var/empty/vpnc-script >/dev/null 2>&1
      make -j"$(sysctl -n hw.ncpu)" libopenconnect.la >/dev/null)
    echo "$sum" > "$work/build.sha256"
  fi
  grep -q 'define HAVE_HPKE_SUPPORT 1' "$oc/config.h" || { echo "OpenConnect built without STRAP support"; exit 1; }
}

# cookie_test <name> [compiler flag]...: strap-cookie-test.c against that build.
cookie_test() {
  local oc="$HOST/$1/openconnect-9.21" out="$HOST/$1/strap-cookie-test"
  shift
  /usr/bin/clang -Wall -Wno-unused-function "$@" -I"$oc" -I"$oc/json" -I"$OSSL/include" -I"$SDK/usr/include/libxml2" \
    tests/strap-cookie-test.c "$oc/.libs/libopenconnect.a" -L"$OSSL/lib" -lssl -lcrypto -lxml2 -lz -liconv -o "$out"
  "$out"
}

# must_fail <test> <name> [flag]...: 1 is a test's own "checks failed"; anything else is a
# crash or a broken build.
must_fail() {
  local code=0
  "$@" || code=$?
  [ "$code" -eq 1 ] || { echo "The negative control didn't fail the way it should (exit $code)"; exit 1; }
}

ALL=(patches/openconnect-*.patch)
OTHERS=()
for p in "${ALL[@]}"; do [ "$p" = "$STRAP" ] || OTHERS+=("$p"); done

echo "== The patch (strap-cookie-test.c), with every patch applied"
build patched "${ALL[@]}"
cookie_test patched

echo
echo "== Negative control: without openconnect-strap-cookie.patch, checks have to fail"
build unpatched "${OTHERS[@]}"
must_fail cookie_test unpatched -DWITHOUT_STRAP_PATCH

echo
echo "OK: passes with the patch, fails without it"
