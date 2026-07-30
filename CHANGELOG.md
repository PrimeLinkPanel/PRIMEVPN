# Changelog

Notable PRIMEVPN changes are documented here.

## Unreleased

### Changed

- Removed the vendored Windows OpenSSL installer from source and release archives; Windows users obtain third-party OpenSSL separately when needed.
- Reorganized packaging and localized documentation.
- Established PRIMEVPN-owned documentation, CI, release, and container links.

## 1.5.0

### Added

- Runtime-backed multi-profile inbounds with automatic per-profile listeners and subscription generation for TCP/RAW, mKCP, WebSocket, HTTPUpgrade, gRPC, and XHTTP transports.
- Independent per-profile transport, TLS/REALITY, header, Sockopt, and runtime-binding controls.
- Runtime listener collision validation before inbound persistence, including safe use of the same numeric port across TCP and UDP.
- Start-after-first-use client expiration synchronization.

### Changed

- Reworked the subscription-profile editor, transport layouts, field ownership, and security controls across supported transports.
- Canonicalized the linux-amd64 release process to reproduce the validated live panel and package the audited PRIMEVPN custom Xray runtime.
- Refined CLI menu borders, spacing, usage rows, and terminal alignment.

### Fixed

- Corrected profile header-map editing, TCP HTTP obfuscation, TLS and REALITY SNI synchronization, mKCP/finalmask ownership, and runtime shared-port routing.
- Prevented duplicate or conflicting runtime listeners from being persisted.
- Improved validation and synchronization between inbound profiles, generated runtime listeners, and subscription output.

