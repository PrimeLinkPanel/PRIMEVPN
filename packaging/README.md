# Packaging

Release and runtime support assets are grouped here so the repository root
remains focused on stable public entrypoints and application source.

## Layout

- `docker/` — container initialization and entrypoint scripts.
- `scripts/` — helper commands included in release archives.
- `migrations/` — standalone migration utilities.
- `windows/` — Windows packaging policy and third-party dependency notes.

The following files intentionally remain in the repository root to preserve
existing installation commands, raw GitHub URLs, update behavior, and older
installed versions:

- `install.sh`
- `update.sh`
- `primevpn.sh`
- `primevpn.rc`
- `primevpn.service.arch`
- `primevpn.service.debian`
- `primevpn.service.rhel`
