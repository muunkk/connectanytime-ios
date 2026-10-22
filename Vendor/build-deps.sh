#!/bin/zsh
# Build OpenSSL + libopenconnect as static libraries for iOS devices (arm64).
# Output: Vendor/out/{include,lib}. Sources are downloaded into Vendor/src.
set -euo pipefail
cd "${0:A:h}"
OPENSSL=openssl-3.5.9
OPENCONNECT=openconnect-9.21
# Pinned checksums. OpenSSL's matches its published .sha256; OpenConnect's tarball
# was checked against David Woodhouse's GPG signature (key 63762CDA67E2F359).
OPENSSL_SHA256=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
OPENCONNECT_SHA256=5b32369467db6e5f317aa1ed12cfcbb81ed00bdbc765450b6bfcbdc300944a58
MIN_IOS=18.4
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
OUT=$PWD/out
JOBS=$(sysctl -n hw.ncpu)
mkdir -p src "$OUT"

fetch() { # url file sha256
  [[ -f "src/$2" ]] || curl -fL --retry 3 -o "src/$2" "$1"
  [[ "$(shasum -a 256 "src/$2" | awk '{print $1}')" == "$3" ]] || { echo "Checksum mismatch: $2"; exit 1; }
}

# --- OpenSSL ---------------------------------------------------------------
if [[ ! -f "$OUT/lib/libssl.a" ]]; then
  fetch "https://github.com/openssl/openssl/releases/download/$OPENSSL/$OPENSSL.tar.gz" "$OPENSSL.tar.gz" "$OPENSSL_SHA256"
  rm -rf "src/$OPENSSL" && tar -xzf "src/$OPENSSL.tar.gz" -C src
  (cd "src/$OPENSSL" &&
    ./Configure ios64-xcrun no-shared no-tests no-apps no-docs no-engine no-async no-module \
      --prefix="$OUT" --openssldir=/var/empty -mios-version-min=$MIN_IOS &&
    make -j"$JOBS" build_libs >/dev/null && make install_dev >/dev/null)
fi

# --- OpenConnect -----------------------------------------------------------
if [[ ! -f "$OUT/lib/libopenconnect.a" ]]; then
  fetch "https://www.infradead.org/openconnect/download/$OPENCONNECT.tar.gz" "$OPENCONNECT.tar.gz" "$OPENCONNECT_SHA256"
  rm -rf "src/$OPENCONNECT" && tar -xzf "src/$OPENCONNECT.tar.gz" -C src
  CC="$(xcrun --sdk iphoneos -f clang)"
  CFLAGS="-arch arm64 -isysroot $SDK -miphoneos-version-min=$MIN_IOS -O2"
  (cd "src/$OPENCONNECT" &&
    PKG_CONFIG_PATH="$OUT/lib/pkgconfig" PKG_CONFIG_LIBDIR="$OUT/lib/pkgconfig" \
    CC="$CC" CFLAGS="$CFLAGS" LDFLAGS="-arch arm64 -isysroot $SDK" \
    LIBXML2_CFLAGS="-I$SDK/usr/include/libxml2" LIBXML2_LIBS="-lxml2" \
    ZLIB_CFLAGS="" ZLIB_LIBS="-lz" \
    ./configure --host=aarch64-apple-darwin --prefix="$OUT" \
      --enable-static --disable-shared --disable-nls --disable-docs \
      --without-gnutls --with-openssl \
      --without-libpskc --without-stoken --without-libpcsclite --without-libproxy \
      --without-gssapi --without-lz4 --without-java \
      --with-vpnc-script=/var/empty/vpnc-script &&
    make -j"$JOBS" libopenconnect.la && make install-libLTLIBRARIES install-includeHEADERS)
fi
echo "Built into $OUT"
ls "$OUT/lib"/*.a
