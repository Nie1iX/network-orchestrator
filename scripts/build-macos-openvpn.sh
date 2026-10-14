#!/bin/bash
# Builds the OpenVPN the privileged helper runs: a pinned release, compiled from
# a hash-checked source tarball and linked statically against OpenSSL, LZO and
# LZ4, so the binary needs nothing but system libraries. (Root must never
# execute a file with user-writable dylibs next to it, see trusted_exec.rs.)
#
# Needs: Xcode command line tools and `brew install openssl@3 lzo lz4` (only the
# static libraries are used, nothing from Homebrew ends up in the result).
# Prints the path of the finished binary; everything else goes to stderr.
set -euo pipefail
VERSION="2.6.17"
URL="https://swupdate.openvpn.org/community/releases/openvpn-$VERSION.tar.gz"
# Same digest Homebrew's formula pins for this release.
SHA256="4cc8e63f710d3001493b13d8a32cf22a214d5e4f71dd37d93831e2fd3208b370"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$REPO_ROOT/target/macos-backends"
BIN="$OUT/openvpn-$VERSION"
if [[ -x "$BIN" ]]; then
    echo "$BIN"
    exit 0
fi

BREW="$(command -v brew || true)"
if [[ -z "$BREW" ]]; then
    echo "Homebrew is needed once, to provide static OpenSSL, LZO and LZ4: https://brew.sh" >&2
    exit 1
fi
SSL="$("$BREW" --prefix openssl@3)"
LZO="$("$BREW" --prefix lzo)"
LZ4="$("$BREW" --prefix lz4)"
for lib in "$SSL/lib/libssl.a" "$SSL/lib/libcrypto.a" "$LZO/lib/liblzo2.a" "$LZ4/lib/liblz4.a"; do
    if [[ ! -f "$lib" ]]; then
        echo "Missing $lib - run: brew install openssl@3 lzo lz4" >&2
        exit 1
    fi
done

WORK="$OUT/build-openvpn-$VERSION"
rm -rf "$WORK"
mkdir -p "$WORK/src" "$WORK/static"
echo "Downloading OpenVPN $VERSION ..." >&2
curl -fsSL --max-time 300 -o "$WORK/openvpn.tar.gz" "$URL"
if [[ "$(shasum -a 256 "$WORK/openvpn.tar.gz" | cut -d' ' -f1)" != "$SHA256" ]]; then
    echo "The OpenVPN source archive does not match its pinned SHA-256; refusing to build it." >&2
    exit 1
fi
tar xzf "$WORK/openvpn.tar.gz" -C "$WORK/src" --strip-components=1
# `-llz4`/`-llzo2` must resolve to the static archives, not Homebrew's dylibs.
ln -s "$LZ4/lib/liblz4.a" "$WORK/static/liblz4.a"
ln -s "$LZO/lib/liblzo2.a" "$WORK/static/liblzo2.a"

cd "$WORK/src"
export MACOSX_DEPLOYMENT_TARGET=27.0
OPENSSL_CFLAGS="-I$SSL/include" \
OPENSSL_LIBS="$SSL/lib/libssl.a $SSL/lib/libcrypto.a" \
CPPFLAGS="-I$LZ4/include -I$LZO/include" \
LDFLAGS="-L$WORK/static" \
./configure --disable-dependency-tracking --disable-debug --disable-dco \
    --disable-plugin-auth-pam --disable-pkcs11 --disable-systemd --disable-silent-rules \
    --with-crypto-library=openssl --enable-lzo --enable-lz4 >"$WORK/configure.log" 2>&1 \
    || { tail -20 "$WORK/configure.log" >&2; exit 1; }
make -j"$(sysctl -n hw.ncpu)" >"$WORK/make.log" 2>&1 || { tail -20 "$WORK/make.log" >&2; exit 1; }

BUILT="$WORK/src/src/openvpn/openvpn"
strip -x "$BUILT"
# Nothing outside the system may be loaded (the helper runs this as root).
if otool -L "$BUILT" | tail -n +2 | awk '{print $1}' | grep -vE '^/(usr/lib|System)/'; then
    echo "The OpenVPN build links a library outside the system." >&2
    exit 1
fi
codesign --force --sign - "$BUILT" >&2
"$BUILT" --version | head -1 >&2
install -m 0755 "$BUILT" "$BIN"
rm -rf "$WORK"
echo "$BIN"
