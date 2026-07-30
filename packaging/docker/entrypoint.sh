#!/bin/sh
set -eu

# PRIMEVPN IP and speed limits are enforced inside the custom Xray Core.
# Do not start legacy ban services or mutate firewall rules in the container.
if [ -f /root/.acme.sh/acme.sh ]; then
    /root/.acme.sh/acme.sh --install-cronjob >/dev/null 2>&1 || true

    if command -v crond >/dev/null 2>&1; then
        crond >/dev/null 2>&1 || true
    elif command -v cron >/dev/null 2>&1; then
        cron >/dev/null 2>&1 || true
    fi
fi

exec /app/x-ui
