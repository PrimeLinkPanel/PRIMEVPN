#!/bin/sh
set -eu

cat >&2 <<'MESSAGE'
PRIMEVPN Docker dependency bundling is disabled.

PRIMEVPN requires the audited private custom Xray core. Downloading or
substituting an official prebuilt Xray binary is forbidden.

The supported v1.5.0 distribution is the audited linux-amd64 release archive.
MESSAGE

exit 1
