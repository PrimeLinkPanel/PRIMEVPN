#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &&
    pwd
)"

REPO_ROOT="$(
    cd "$SCRIPT_DIR/../.." &&
    pwd
)"

VERSION="$(
    tr -d '[:space:]' \
        < "$REPO_ROOT/internal/config/version"
)"

CUSTOM_XRAY="${PRIMEVPN_CUSTOM_XRAY:-}"
EXPECTED_CUSTOM_XRAY_SHA256="${PRIMEVPN_CUSTOM_XRAY_SHA256:-}"
EXPECTED_PANEL_SHA256="${PRIMEVPN_EXPECTED_PANEL_SHA256:-}"
RUNTIME_BIN_DIR="${PRIMEVPN_RUNTIME_BIN_DIR:-/usr/local/primevpn/bin}"
OUTPUT_DIR="${PRIMEVPN_RELEASE_OUTPUT_DIR:-$REPO_ROOT/release-out}"

fail() {
    printf '\nERROR: %s\n' "$*" >&2
    exit 1
}

need() {
    command -v "$1" >/dev/null 2>&1 ||
        fail "missing required tool: $1"
}

for tool in \
    git npm node go tar gzip sha256sum file \
    install find grep sed awk sort date
do
    need "$tool"
done

test "$VERSION" = "1.5.0" ||
    fail "release version must be 1.5.0, got: $VERSION"

test -n "$CUSTOM_XRAY" ||
    fail "PRIMEVPN_CUSTOM_XRAY is required"

test -f "$CUSTOM_XRAY" ||
    fail "custom Xray file not found: $CUSTOM_XRAY"

test -n "$EXPECTED_CUSTOM_XRAY_SHA256" ||
    fail "PRIMEVPN_CUSTOM_XRAY_SHA256 is required"

ACTUAL_CUSTOM_XRAY_SHA256="$(
    sha256sum "$CUSTOM_XRAY" |
    awk '{print $1}'
)"

test "$ACTUAL_CUSTOM_XRAY_SHA256" = "$EXPECTED_CUSTOM_XRAY_SHA256" ||
    fail "custom Xray SHA256 mismatch"

test -n "$EXPECTED_PANEL_SHA256" ||
    fail "PRIMEVPN_EXPECTED_PANEL_SHA256 is required"

SOURCE_HEAD="$(git -C "$REPO_ROOT" rev-parse HEAD)"
SOURCE_TREE="$(git -C "$REPO_ROOT" rev-parse HEAD^{tree})"
SOURCE_STATUS="$(git -C "$REPO_ROOT" status --porcelain)"

test -z "$SOURCE_STATUS" || {
    printf '%s\n' "$SOURCE_STATUS"
    fail "release source must be clean"
}

SOURCE_DATE_EPOCH="$(
    git -C "$REPO_ROOT" show \
        -s \
        --format=%ct \
        HEAD
)"

BUILD_DATE="$(
    date -u \
        -d "@$SOURCE_DATE_EPOCH" \
        +%Y-%m-%dT%H:%M:%SZ
)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

BUILD_SRC="$WORK/source"
STAGE="$WORK/stage"
VERIFY="$WORK/verify"
mkdir -p \
    "$BUILD_SRC" \
    "$STAGE/primevpn/bin" \
    "$STAGE/primevpn/sub_templates/ourenus" \
    "$VERIFY" \
    "$OUTPUT_DIR"

printf '===== RELEASE INPUTS =====\n'
printf 'VERSION=%s\n' "$VERSION"
printf 'SOURCE_HEAD=%s\n' "$SOURCE_HEAD"
printf 'SOURCE_TREE=%s\n' "$SOURCE_TREE"
printf 'SOURCE_DATE_EPOCH=%s\n' "$SOURCE_DATE_EPOCH"
printf 'BUILD_DATE=%s\n' "$BUILD_DATE"
printf 'CUSTOM_XRAY=%s\n' "$CUSTOM_XRAY"
printf 'CUSTOM_XRAY_SHA256=%s\n' "$ACTUAL_CUSTOM_XRAY_SHA256"
printf 'EXPECTED_PANEL_SHA256=%s\n' "$EXPECTED_PANEL_SHA256"
printf 'RUNTIME_BIN_DIR=%s\n' "$RUNTIME_BIN_DIR"
printf 'OUTPUT_DIR=%s\n' "$OUTPUT_DIR"

printf '\n===== EXPORT CLEAN SOURCE =====\n'

git -C "$REPO_ROOT" archive HEAD |
tar -x -C "$BUILD_SRC"

test "$(
    tr -d '[:space:]' \
        < "$BUILD_SRC/internal/config/version"
)" = "$VERSION" ||
    fail "exported source version mismatch"

printf 'SOURCE_EXPORT=pass\n'

printf '\n===== BUILD FRONTEND =====\n'

(
    cd "$BUILD_SRC/frontend"

    npm ci
    npm run build
)

test -f "$BUILD_SRC/internal/web/dist/index.html" ||
    fail "frontend build did not create embedded dist"

printf 'FRONTEND_BUILD=pass\n'

printf '\n===== BUILD VALIDATED LIVE-PARITY PANEL =====\n'

PANEL_BINARY="$WORK/primevpn"

(
    cd "$BUILD_SRC"

    export CGO_ENABLED=1
    export GOOS=linux
    export GOARCH=amd64
    unset CC

    go build \
        -trimpath \
        -buildvcs=false \
        -ldflags='-s -w' \
        -o "$PANEL_BINARY" \
        github.com/mhsanaei/PRIMEVPN/v3
)

test -s "$PANEL_BINARY" ||
    fail "panel binary was not built"

file "$PANEL_BINARY"

PANEL_SHA256="$(
    sha256sum "$PANEL_BINARY" |
    awk '{print $1}'
)"

test "$PANEL_SHA256" = "$EXPECTED_PANEL_SHA256" ||
    fail "release panel SHA256 does not match validated live panel"

printf 'PANEL_SHA256=%s\n' "$PANEL_SHA256"
printf 'PANEL_LIVE_PARITY=yes\n'

printf '\n===== ASSEMBLE RELEASE PAYLOAD =====\n'

install -m 0755 \
    "$PANEL_BINARY" \
    "$STAGE/primevpn/primevpn"

for name in \
    primevpn.sh \
    primevpn.rc
do
    test -f "$BUILD_SRC/$name" ||
        fail "required script missing: $name"

    install -m 0755 \
        "$BUILD_SRC/$name" \
        "$STAGE/primevpn/$name"
done

for name in \
    primevpn.service.debian \
    primevpn.service.arch \
    primevpn.service.rhel \
    LICENSE
do
    test -f "$BUILD_SRC/$name" ||
        fail "required release file missing: $name"

    install -m 0644 \
        "$BUILD_SRC/$name" \
        "$STAGE/primevpn/$name"
done

install -m 0755 \
    "$BUILD_SRC/packaging/scripts/y-ui.sh" \
    "$STAGE/primevpn/y-ui.sh"

install -m 0755 \
    "$BUILD_SRC/packaging/migrations/y-ui-migration-center.py" \
    "$STAGE/primevpn/y-ui-migration-center.py"

for name in \
    index.html \
    index.php
do
    test -f "$BUILD_SRC/sub_templates/ourenus/$name" ||
        fail "required Ourenus file missing: $name"

    install -m 0644 \
        "$BUILD_SRC/sub_templates/ourenus/$name" \
        "$STAGE/primevpn/sub_templates/ourenus/$name"
done

install -m 0755 \
    "$CUSTOM_XRAY" \
    "$STAGE/primevpn/bin/xray-linux-amd64"

for name in \
    mtg-linux-amd64 \
    geoip.dat \
    geosite.dat \
    geoip_IR.dat \
    geosite_IR.dat \
    geoip_RU.dat \
    geosite_RU.dat
do
    test -f "$RUNTIME_BIN_DIR/$name" ||
        fail "required runtime asset missing: $RUNTIME_BIN_DIR/$name"

    case "$name" in
        mtg-linux-amd64)
            mode="0755"
            ;;
        *)
            mode="0644"
            ;;
    esac

    install -m "$mode" \
        "$RUNTIME_BIN_DIR/$name" \
        "$STAGE/primevpn/bin/$name"
done

printf '%s\n' "$VERSION" \
    > "$STAGE/primevpn/RELEASE_VERSION"

cat > "$STAGE/primevpn/RELEASE_MANIFEST" <<MANIFEST
VERSION=$VERSION
SOURCE_HEAD=$SOURCE_HEAD
SOURCE_TREE=$SOURCE_TREE
SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH
BUILD_DATE=$BUILD_DATE
ARCH=linux-amd64
PANEL_BUILD_RECIPE=validated-live-parity
PANEL_SHA256=$PANEL_SHA256
CUSTOM_XRAY_SHA256=$ACTUAL_CUSTOM_XRAY_SHA256
MANIFEST

(
    cd "$STAGE/primevpn"

    find . \
        -type f \
        ! -name SHA256SUMS \
        -print0 |
    sort -z |
    xargs -0 sha256sum \
        > SHA256SUMS
)

printf '\n===== PACKAGE DETERMINISTIC ARCHIVE =====\n'

ARCHIVE="$OUTPUT_DIR/primevpn-linux-amd64.tar.gz"
ARCHIVE_SHA_FILE="$ARCHIVE.sha256"

rm -f \
    "$ARCHIVE" \
    "$ARCHIVE_SHA_FILE"

tar \
    --sort=name \
    --mtime="@${SOURCE_DATE_EPOCH}" \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    -C "$STAGE" \
    -cf - \
    primevpn |
gzip -n \
    > "$ARCHIVE"

test -s "$ARCHIVE" ||
    fail "release archive is empty"

ARCHIVE_SHA256="$(
    sha256sum "$ARCHIVE" |
    awk '{print $1}'
)"

printf '%s  %s\n' \
    "$ARCHIVE_SHA256" \
    "$(basename "$ARCHIVE")" \
    > "$ARCHIVE_SHA_FILE"

printf 'ARCHIVE=%s\n' "$ARCHIVE"
printf 'ARCHIVE_SHA256=%s\n' "$ARCHIVE_SHA256"
printf 'ARCHIVE_SIZE=%s\n' "$(
    stat -c '%s' "$ARCHIVE"
)"

printf '\n===== EXTRACT AND VERIFY ARCHIVE =====\n'

tar -xzf \
    "$ARCHIVE" \
    -C "$VERIFY"

REQUIRED_PATHS=(
    primevpn/primevpn
    primevpn/primevpn.sh
    primevpn/primevpn.rc
    primevpn/y-ui.sh
    primevpn/y-ui-migration-center.py
    primevpn/primevpn.service.debian
    primevpn/primevpn.service.arch
    primevpn/primevpn.service.rhel
    primevpn/LICENSE
    primevpn/RELEASE_VERSION
    primevpn/RELEASE_MANIFEST
    primevpn/SHA256SUMS
    primevpn/bin/xray-linux-amd64
    primevpn/bin/mtg-linux-amd64
    primevpn/bin/geoip.dat
    primevpn/bin/geosite.dat
    primevpn/bin/geoip_IR.dat
    primevpn/bin/geosite_IR.dat
    primevpn/bin/geoip_RU.dat
    primevpn/bin/geosite_RU.dat
    primevpn/sub_templates/ourenus/index.html
    primevpn/sub_templates/ourenus/index.php
)

for path in "${REQUIRED_PATHS[@]}"; do
    test -f "$VERIFY/$path" ||
        fail "archive required file missing: $path"
done

if find "$VERIFY/primevpn" \
    -type l \
    -print \
    -quit |
grep -q .
then
    fail "release archive contains symlinks"
fi

test "$(
    tr -d '[:space:]' \
        < "$VERIFY/primevpn/RELEASE_VERSION"
)" = "$VERSION" ||
    fail "archive version mismatch"

VERIFIED_PANEL_SHA256="$(
    sha256sum "$VERIFY/primevpn/primevpn" |
    awk '{print $1}'
)"

test "$VERIFIED_PANEL_SHA256" = "$PANEL_SHA256" ||
    fail "archive panel SHA mismatch"

VERIFIED_CUSTOM_XRAY_SHA256="$(
    sha256sum "$VERIFY/primevpn/bin/xray-linux-amd64" |
    awk '{print $1}'
)"

test "$VERIFIED_CUSTOM_XRAY_SHA256" = "$EXPECTED_CUSTOM_XRAY_SHA256" ||
    fail "archive custom Xray SHA mismatch"

SOURCE_OURENUS_HTML_SHA256="$(
    sha256sum "$BUILD_SRC/sub_templates/ourenus/index.html" |
    awk '{print $1}'
)"

ARCHIVE_OURENUS_HTML_SHA256="$(
    sha256sum "$VERIFY/primevpn/sub_templates/ourenus/index.html" |
    awk '{print $1}'
)"

test "$SOURCE_OURENUS_HTML_SHA256" = "$ARCHIVE_OURENUS_HTML_SHA256" ||
    fail "Ourenus HTML SHA mismatch"

SOURCE_OURENUS_PHP_SHA256="$(
    sha256sum "$BUILD_SRC/sub_templates/ourenus/index.php" |
    awk '{print $1}'
)"

ARCHIVE_OURENUS_PHP_SHA256="$(
    sha256sum "$VERIFY/primevpn/sub_templates/ourenus/index.php" |
    awk '{print $1}'
)"

test "$SOURCE_OURENUS_PHP_SHA256" = "$ARCHIVE_OURENUS_PHP_SHA256" ||
    fail "Ourenus PHP SHA mismatch"

file "$VERIFY/primevpn/primevpn"
file "$VERIFY/primevpn/bin/xray-linux-amd64"

file "$VERIFY/primevpn/bin/xray-linux-amd64" |
grep -q 'statically linked' ||
    fail "verified custom Xray binary is not static"

(
    cd "$VERIFY/primevpn"

    sha256sum -c SHA256SUMS
)

printf '\n===== RELEASE RESULT =====\n'
printf 'RELEASE_VERSION=%s\n' "$VERSION"
printf 'RELEASE_ARCH=linux-amd64\n'
printf 'SOURCE_HEAD=%s\n' "$SOURCE_HEAD"
printf 'SOURCE_TREE=%s\n' "$SOURCE_TREE"
printf 'PANEL_BUILD_RECIPE=validated-live-parity\n'
printf 'PANEL_LIVE_PARITY=yes\n'
printf 'PANEL_SHA256=%s\n' "$PANEL_SHA256"
printf 'CUSTOM_XRAY_SHA256=%s\n' "$VERIFIED_CUSTOM_XRAY_SHA256"
printf 'CUSTOM_XRAY_MATCH=yes\n'
printf 'OURENUS_HTML_SHA256=%s\n' "$ARCHIVE_OURENUS_HTML_SHA256"
printf 'OURENUS_PHP_SHA256=%s\n' "$ARCHIVE_OURENUS_PHP_SHA256"
printf 'OURENUS_MATCH=yes\n'
printf 'OFFICIAL_XRAY_DOWNLOADED=no\n'
printf 'ARCHIVE_VERIFIED=yes\n'
printf 'ARCHIVE=%s\n' "$ARCHIVE"
printf 'ARCHIVE_SHA_FILE=%s\n' "$ARCHIVE_SHA_FILE"
printf 'ARCHIVE_SHA256=%s\n' "$ARCHIVE_SHA256"
