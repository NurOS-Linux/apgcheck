# TODO
### MD5 Checksum Verification
- [ ] Implement reading of `md5sums` file
- [ ] Check hashes of all files in `data/` directory
- [ ] Detailed report on mismatched hashes
- [ ] `--skip-checksums` option to skip verification

### Output Modes
- [ ] Verbose mode (`-v`, `--verbose`)
  - Output information about each verification stage
  - List of all files being checked
  - Archive extraction details
- [ ] Quiet mode (`-q`, `--quiet`)
  - Output only on errors
  - Exit code: 0 = success, 1 = error
  - Suitable for use in scripts

### JSON Output
- [ ] `--json` flag for structured output
- [ ] Response format:
```json
{
  "valid": true,
  "version": 2,
  "file": "package.apg",
  "metadata": {...},
  "errors": [],
  "warnings": []
}
```
- [ ] Compatibility with quiet mode

### Size Check Before Extraction
- [ ] Read archive size before extraction
- [ ] `--max-size` flag to limit size (default 500MB)
- [ ] Check available space in `/tmp`
- [ ] Warning about large archives
- [ ] Protection against zip bombs

### Batch Verification
- [ ] Support for multiple files: `./apgcheck -a *.apg`
- [ ] Check all APG in directory: `./apgcheck -d ./packages/`
- [ ] Summary report:
  - Number of files checked
  - Number of valid/invalid
  - List of problematic packages
- [ ] `--fail-fast` option to stop at first error
- [ ] Progress bar for batch verification

### Metadata Field Validation
- [ ] Check version format (semver)
- [ ] Validate email in `maintainer` field
- [ ] Check URL in `homepage` field
- [ ] Check allowed values of `type` for APG v2

### Output Improvements
- [ ] Color indication for levels (info/warning/error)
- [ ] Table with results for batch verification
- [ ] Localization support (EN/RU)

## Future Ideas
- [ ] Lint mode with style warnings
- [ ] Extract metadata without full validation
- [ ] Check dependency conflicts
- [ ] Compare two package versions
- [ ] Support for configuration file `.apgcheck.yaml`
- [ ] Generate reports in HTML/Markdown
- [ ] Integration tests
- [ ] CI/CD pipeline

## Bug Fixes
- [ ] Improve error handling for insufficient permissions
- [ ] Test functionality on Windows (if applicable)
- [ ] Add tests for edge cases

---
## Legend
- [ ] Planned
- [x] Completed
- [~] In Progress