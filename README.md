# apgcheck

APG file validator for [NurOS](https://nuros.org). Validates `.apg` packages against the APG v1 and v2 specifications: checks archive structure, verifies checksums, and validates metadata fields.

## Installation

```bash
git clone https://github.com/NurOS-Linux/apgcheck
cd apgcheck
go build -o apgcheck .
```

## Usage

```
apgcheck -a <file.apg> [options]
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--apgfile` | `-a` | | Path to the `.apg` file to validate |
| `--apg-version` | `-A` | `1` | APG format version (`1` or `2`) |
| `--skip-checksums` | | `false` | Skip MD5/CRC32 checksum verification |
| `--max-size` | | `500` | Max allowed decompression size in MB |
| `--json` | `-j` | `false` | Output result as JSON |
| `--quiet` | `-q` | `false` | Suppress all output |
| `--verbose` | `-V` | `false` | Print detailed diagnostic info to stderr |
| `--no-color` | | `false` | Disable colored output |
| `--version` | `-v` | | Show version and exit |
| `--help` | `-h` | | Show help and exit |

Color output is also suppressed when the `NO_COLOR` environment variable is set or when output is redirected.

## Examples

Validate an APG v1 package:

```bash
apgcheck -a ./astrum-1.3.2-x86_64.apg
```

Validate an APG v2 package:

```bash
apgcheck -A 2 -a ./my-package-1.0.0.apg
```

Get machine-readable output:

```bash
apgcheck -j -a ./package.apg
```

## APG format

An APG file is a `.tar.xz` archive with the following layout:

**v1:**
```
data/          package files
md5sums        MD5 checksums for files in data/
metadata.json  package metadata
```

**v2** adds:
```
crc32sums      CRC32 checksums for files in data/
```

Required `metadata.json` fields for v1: `name`, `version`, `description`, `maintainer`, `homepage`, `dependencies`, `conflicts`, `provides`, `replaces`.

v2 additionally requires: `type`, `tags`, `conf`.

## License

Licrnsed under [GNU GPLv3.0](LICENSE)
