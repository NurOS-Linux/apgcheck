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

---
## Legend
- [ ] Planned
- [x] Completed
- [~] In Progress