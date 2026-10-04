# Changelog

## 1.7.0

### Added

- IEEE CRC32 calculation and SFV parsing/export.
- Optional BLAKE3 support using the official `b3sum.exe`, with confirmed,
  verified installation from the algorithm or Help menu.
- Batch verification with per-file status, path, size, algorithm, timing,
  mismatch details, and separate error counts.
- GNU, SFV, and tagged manifest exports from the result menu.
- User-initiated, verified GitHub updates with backup and concurrent-edit
  protection.
- Runtime-dependent SHA3 support and automated regression/menu/large-file test
  scripts.

### Fixed

- Filename matching, conflicting checksum entries, algorithm labels, and
  digest-length validation.
- Duplicate algorithms, binary BLAKE3 streaming, buffer-boundary handling, and
  relative paths.
- Existing checksum files are protected from overwrites, including mismatch
  saves.
- Settings validation and atomic persistence, structured logs, and literal log
  paths containing brackets.
- Dialog cleanup, overflowing source selections, direct checksum input, and
  Recent files ALL behavior.

### Improved

- SHA256-first algorithm selection, clearer menus, and optional privacy
  controls.
- Documentation covering setup, formats, batch workflows, troubleshooting,
  networking, and deletion limits.

### Compatibility

- The utility remains one distributable PowerShell script; only BLAKE3 needs an
  optional executable.
- Windows PowerShell 5.1 and PowerShell 7 are supported. SHA3 availability
  depends on the runtime.
- Download checks require published SHA256 digests. No automatic startup network
  checks are performed.
- Checksums establish agreement with an expected value, not authenticity without
  a trusted source.

### Validation

- Automated regression and menu tests pass on Windows PowerShell 5.1 and
  PowerShell 7.6.6.
- Final release checks: 138 tests on PowerShell 5.1 and 140 on PowerShell 7,
  including the official BLAKE3 backend, with zero failures.
- All repository Markdown passes markdownlint. Launch examples use process-scoped
  RemoteSigned, with guidance for reviewed downloaded scripts.
- Large-file streaming checks matched independent standard hashes, official
  b3sum file-mode output, and 7-Zip CRC32 output.
- Native dialogs, clipboard operations, and networking use replacements in
  automated tests; manual GUI coverage is not exhaustive.
