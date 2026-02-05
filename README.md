# localsend-cli

Headless, non-interactive LocalSend CLI for Linux/macOS/Windows. Designed for LLM automation and scripting: no prompts, deterministic exit codes, optional JSON output.

## Features

- Fully non-interactive (all behavior controlled by flags)
- Discover devices (multicast + optional subnet scan)
- Send text, files, directories (directories are zipped), and globbed file lists
- Receive mode with auto-accept and optional PIN
- Optional JSON output for machine control
- Native binaries for Linux/macOS/Windows

## Install

### Prebuilt binaries

Use the GitHub Releases artifacts for your OS.

### Build from source

```bash
cargo build --release
./target/release/localsend-cli --help
```

## Quickstart

List devices:

```bash
localsend-cli list
localsend-cli list --json
```

Send a file:

```bash
localsend-cli send --to "Alice" --file ./photo.jpg
```

Send a file with QR fallback (recommended on multi-network setups):

```bash
localsend-cli send --to "Alice" --file ./photo.jpg --qr
```

Send text:

```bash
localsend-cli send --to 192.168.1.42 --text "Hello from CLI"
```

Send a directory (zipped):

```bash
localsend-cli send --to "office-pc" --dir ./project
```

Receive files (auto-accept):

```bash
localsend-cli receive --output ./downloads
```

## Device selection

`--to` can match any of:

- device id (fingerprint)
- device alias (case-insensitive)
- hostname (if the alias equals hostname)
- IP address

If you already know the target address, you can bypass discovery:

```bash
localsend-cli send --direct 192.168.1.42:53317 --file ./report.pdf
```

## Authentication (PIN)

If the receiver requires a PIN, pass it with `--pin`:

```bash
localsend-cli send --to "Alice" --file ./secret.txt --pin 123456
```

Receiver can require a PIN:

```bash
localsend-cli receive --pin 123456
```

## QR fallback

If discovery fails, `--qr` starts a local web share server and prints a terminal QR code so the receiver can open the link and download the files in a browser. By default the link uses HTTPS (self-signed).

## JSON output

Use `--json` to enable machine-readable output. For example:

```bash
localsend-cli list --json
localsend-cli send --to "Alice" --file ./photo.jpg --json
localsend-cli receive --output ./downloads --json
```

## Protocol

This CLI implements the LocalSend v2.1 protocol endpoints:

- `POST /api/localsend/v2/register`
- `GET /api/localsend/v2/info`
- `POST /api/localsend/v2/prepare-upload`
- `POST /api/localsend/v2/upload`

## Notes

- Directories are zipped before transfer to preserve structure.
- HTTPS uses a self-signed certificate and accepts invalid certs for interoperability.
- Subnet scanning is optional (`localsend-cli list --scan`) and may be slow on large networks.

## Development

Run locally:

```bash
cargo run -- list
cargo run -- send --to 192.168.1.42 --file ./photo.jpg
cargo run -- receive --output ./downloads
```

## License

MIT
