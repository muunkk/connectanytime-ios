#!/bin/zsh
# Build OpenSSL + libopenconnect as static libraries for iOS devices (arm64).
# Output: Vendor/out/{include,lib}. Sources are downloaded into Vendor/src.
#
# `Vendor/build-deps.sh simulator` builds them for the iOS Simulator on an Apple
# silicon Mac instead, into Vendor/out-sim, which the Xcode project uses for
# Simulator builds. A VPN can't run there, but everything compiles and links.
set -euo pipefail
cd "${0:A:h}"
OPENSSL=openssl-3.5.9
OPENCONNECT=openconnect-9.21
# Pinned checksums. OpenSSL's matches its published .sha256; OpenConnect's tarball
# was checked against David Woodhouse's GPG signature (key 63762CDA67E2F359).
OPENSSL_SHA256=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
OPENCONNECT_SHA256=5b32369467db6e5f317aa1ed12cfcbb81ed00bdbc765450b6bfcbdc300944a58
MIN_IOS=18.4
case "${1:-device}" in
  device)
    SDK_NAME=iphoneos OUT=$PWD/out OPENSSL_TARGET=ios64-xcrun
    OPENSSL_MIN=-mios-version-min=$MIN_IOS CC_MIN=-miphoneos-version-min=$MIN_IOS ;;
  simulator)
    SDK_NAME=iphonesimulator OUT=$PWD/out-sim OPENSSL_TARGET=iossimulator-arm64-xcrun
    OPENSSL_MIN=-mios-simulator-version-min=$MIN_IOS CC_MIN=-mios-simulator-version-min=$MIN_IOS ;;
  *) echo "usage: $0 [device|simulator]"; exit 2 ;;
esac
SDK=$(xcrun --sdk $SDK_NAME --show-sdk-path)
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
    ./Configure $OPENSSL_TARGET no-shared no-tests no-apps no-docs no-engine no-async no-module \
      --prefix="$OUT" --openssldir=/var/empty $OPENSSL_MIN &&
    make -j"$JOBS" build_libs >/dev/null && make install_dev >/dev/null)
fi

# --- OpenConnect -----------------------------------------------------------
# Our fixes live in patches/; rebuild whenever they change.
PATCHES=(patches/openconnect-*.patch(N))
STAMP="$OUT/lib/openconnect-patches.sha256"
PATCH_SUM=$(cat "${PATCHES[@]}" </dev/null | shasum -a 256 | awk '{print $1}')
if [[ ! -f "$OUT/lib/libopenconnect.a" || "$(cat "$STAMP" 2>/dev/null)" != "$PATCH_SUM" ]]; then
  fetch "https://www.infradead.org/openconnect/download/$OPENCONNECT.tar.gz" "$OPENCONNECT.tar.gz" "$OPENCONNECT_SHA256"
  rm -rf "src/$OPENCONNECT" && tar -xzf "src/$OPENCONNECT.tar.gz" -C src
  for p in "${PATCHES[@]}"; do patch -d "src/$OPENCONNECT" -p1 --forward < "$p"; done
  CC="$(xcrun --sdk $SDK_NAME -f clang)"
  CFLAGS="-arch arm64 -isysroot $SDK $CC_MIN -O2"
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
  echo "$PATCH_SUM" > "$STAMP"
fi
echo "Built into $OUT"
ls "$OUT/lib"/*.a
