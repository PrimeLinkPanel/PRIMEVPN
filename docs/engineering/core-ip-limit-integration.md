# Core-level concurrent IP limit integration

This source tree synchronizes each enabled client's `limitIp` value to:

```text
/usr/local/primevpn/bin/client-ip-limits.json
```

The file is consumed by the custom Xray 26.6.1 binary that implements
first-IP-wins enforcement inside the dispatcher.

## Runtime behavior

- `limitIp = 0`: unlimited.
- `limitIp = N`: the first N distinct active source IPs are accepted.
- Further source IPs are rejected before outbound dispatch.
- No access-log parsing or external firewall jail is required.
- A slot is released after all dispatch contexts for the IP close and the
  configured inactivity delay elapses.

The panel writes the file before Xray starts and refreshes it every two seconds.
Writes are atomic and skipped when content has not changed.

## Optional environment variables

```text
XRAY_CLIENT_IP_LIMITS_FILE=/usr/local/primevpn/bin/client-ip-limits.json
XUI_IP_LIMIT_RELEASE_SECONDS=60
```

Both variables are optional. The release delay accepts values from 1 to 86400
seconds and defaults to 60.

## Required release contents

A production release must contain both:

1. the panel binary built from this source tree;
2. the custom Xray binary at `primevpn/bin/xray-linux-amd64`.

Shipping only the panel binary creates the JSON file but does not enforce it.
Shipping only the custom Xray binary requires manual JSON management.

## Build checks

The project `go.mod` requires Go 1.26.4. The frontend requires Node.js 22 and
npm 10 or newer.

```bash
cd frontend
npm ci
npm run typecheck
npm test
npm run build

cd ..
go test ./web/job ./web/service ./web/controller
go build -trimpath -o primevpn-panel ./main.go
```

## Legacy IP-limit components

`CheckClientIpJob` remains only for compatibility and online-client observation. IP-limit enforcement is performed exclusively by the pinned PRIMEVPN custom core.