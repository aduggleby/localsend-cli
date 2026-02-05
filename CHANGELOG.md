# Changelog
All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.

## [Unreleased]

## [0.9.0] - 2026-02-05
### Added
- Full CLI surface: `list`, `search`, `send`, `receive`, `webshare` with standard help output.
- LocalSend discovery across LAN plus Tailscale host discovery via `tailscale status --json`.
- Direct IP send with protocol probing (HTTP/HTTPS) and better error messages.
- QR-code fallback webshare flow with terminal QR + share URLs (optional PIN).
- Auto-accept receive behavior and `receive --max-files` to exit after N files.
- Progress/awaiting output so LLM operators can report state while blocking.
- Integration tests covering send, receive, webshare, QR, and error cases.
- GitHub Actions release workflow producing multi-OS artifacts.

### Changed
- README now includes GitHub release install commands and blocking behavior notes.

### Fixed
- Release workflow permissions for publishing GitHub releases.
