# Roadmap

## v0.4.0

- SHA-256 checksum support alongside MD5 and CRC32
- Signature verification via GPG or minisign for `.apg` files
- `--strict` flag: treat warnings as errors
- Validate `architecture` field against a known set of values
- Warn on deprecated or unknown metadata fields

## v0.5.0

- APG v3 format support (to be defined)
- Machine-readable output improvements: include checksum details and warnings in JSON
- `--extract` flag: optionally keep the extracted directory instead of cleaning up
- Configurable tmp directory via `--tmpdir`

## v1.0.0

- Stable public API for use as a Go library
- Full APG specification compliance
- Comprehensive test suite with real `.apg` fixtures
- Man page

## Ideas / Backlog

- Parallel checksum verification for large packages
- Plugin system for custom validation rules
