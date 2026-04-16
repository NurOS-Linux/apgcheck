# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-04-15

### Added
- APG v2 format validation with `crc32sums` checksum verification
- `--apg-version` / `-A` flag to select between APG v1 and v2
- `--skip-checksums` flag to bypass MD5 and CRC32 verification
- `--max-size` flag to set maximum allowed decompression size (default 500 MB)
- `--json` / `-j` flag for machine-readable JSON output
- `--quiet` / `-q` flag to suppress all output
- `--verbose` / `-V` flag for detailed diagnostic output
- `--no-color` flag and `NO_COLOR` environment variable support
- Color output with terminal detection
- Tar-bomb protection: aborts extraction when cumulative size exceeds limit
- Disk space check before extraction
- `--version` / `-v` flag

### Security
- Fixed path traversal vulnerability in `extractTarXz` by cleaning entry paths with `filepath.Clean`
- Replaced deprecated `rand.Seed` with `rand.New(rand.NewSource(...))`

## [0.2.0] - 2025-10-01

### Added
- Initial support for APG v2 metadata format (`MetadataV2`)
- `type`, `tags`, and `conf` fields in APG v2 metadata validation

### Changed
- Renamed internal checksum verification section

## [0.1.0] - 2025-07-26

### Added
- Initial Go implementation of apgcheck
- APG v1 format validation: checks for `data/`, `md5sums`, and `metadata.json`
- MD5 checksum verification against `md5sums`
- Required metadata fields validation for APG v1: `name`, `version`, `description`, `maintainer`, `homepage`, `dependencies`, `conflicts`, `provides`, `replaces`
- `.tar.xz` archive extraction using `ulikunitz/xz`
- CLI interface using `spf13/pflag`

## [beta] - 2025-06-08

### Added
- First working prototype written in Go
- Basic APG file extraction and structure check
