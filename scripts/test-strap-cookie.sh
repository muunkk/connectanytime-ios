#!/bin/bash
# Tests, on this Mac, that a saved session can be rejoined: OpenConnect hands the server a
# new key for the session (STRAP) on every reconnect, and the saved cookie has to carry it.
# Builds OpenConnect with Vendor/patches and runs against it:
#   Vendor/tests/strap-cookie-test.c     openconnect-strap-cookie.patch itself
#   Vendor/tests/bridge-session-test.c   Tunnel/ocbridge.c's saved session, end to end
#                                        against a server that enforces the key; then
#                                        again under ThreadSanitizer
# Then the negative control: both against OpenConnect without that patch, where they have
# to fail, since a test that passes either way proves nothing.
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
        --with-vpnc-script=/var/empty/vpnc-script >"$work/build.log" 2>&1 &&
      make -j"$(sysctl -n hw.ncpu)" libopenconnect.la >>"$work/build.log" 2>&1) ||
      { echo "Building OpenConnect in $work failed:"; tail -20 "$work/build.log"; exit 1; }
    echo "$sum" > "$work/build.sha256"
  fi
  grep -q 'define HAVE_HPKE_SUPPORT 1' "$oc/config.h" || { echo "OpenConnect built without STRAP support"; exit 1; }
}

# cookie_test <name> [compiler flag]...: strap-cookie-test.c against that build.
cookie_test() {
  local oc="$HOST/$1/openconnect-9.21" out="$HOST/$1/strap-cookie-test"
  shift
  rm -f "$out" # never one from an earlier build
  /usr/bin/clang -Wall -Wno-unused-function "$@" -I"$oc" -I"$oc/json" -I"$OSSL/include" -I"$SDK/usr/include/libxml2" \
    tests/strap-cookie-test.c "$oc/.libs/libopenconnect.a" -L"$OSSL/lib" -lssl -lcrypto -lxml2 -lz -liconv -o "$out" || return 2
  "$out"
}

# bridge_test <name> [compiler flag]...: bridge-session-test.c, which compiles the real
# Tunnel/ocbridge.c, against that build.
bridge_test() {
  local oc="$HOST/$1/openconnect-9.21" out="$HOST/$1/bridge-session-test"
  shift
  rm -f "$out"
  /usr/bin/clang -g -Wall -Wno-unused-function -Wno-deprecated-declarations "$@" -I../Tunnel -I"$oc" -I"$OSSL/include" \
    tests/bridge-session-test.c "$oc/.libs/libopenconnect.a" -L"$OSSL/lib" -lssl -lcrypto -lxml2 -lz -liconv \
    -framework Security -framework CoreFoundation -o "$out" || return 2
  "$out"
}

# must_fail <test> <name> [flag]...: 1 is a test's own "checks failed"; anything else is a
# crash or a build that failed (2, so it can't pass for a failed check).
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
echo "== The bridge's saved session (bridge-session-test.c), on the same build"
bridge_test patched

echo
echo "== The same under ThreadSanitizer (the snapshot is read while OpenConnect reconnects)"
bridge_test patched -fsanitize=thread | tail -n 1

echo
echo "== Negative control: without openconnect-strap-cookie.patch, checks have to fail"
build unpatched "${OTHERS[@]}"
must_fail cookie_test unpatched -DWITHOUT_STRAP_PATCH
echo
must_fail bridge_test unpatched -DWITHOUT_STRAP_PATCH

echo
echo "OK: both pass with the patch and fail without it"
