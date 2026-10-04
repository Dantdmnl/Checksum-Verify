# Checksum-Verify

A single-script Windows PowerShell utility for calculating and verifying
checksums, including large files and batch manifests.

**Version:** 1.7.0 | **Author:** Ruben Draaisma

## Quick Start

Download `Checksum-Verify.ps1` from the repository's releases, then run it in a
regular PowerShell window:

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\Checksum-Verify.ps1
# Or, with PowerShell 7:
pwsh.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\Checksum-Verify.ps1
```

The first command selects RemoteSigned for that process without changing your
saved execution policy. Administrator privileges are normally unnecessary. Use
Windows 10 or newer with PowerShell 5.1 or 7. GUI pickers and clipboard support
require an interactive desktop.

Downloaded unsigned scripts can be blocked under RemoteSigned. After reviewing
the script and trusting its source, unblock only that file before running it:

```powershell
Unblock-File -LiteralPath .\Checksum-Verify.ps1
```

Only the `.ps1` is needed for normal use. BLAKE3 has an optional companion
executable. Files under `Debug` are developer tests, not runtime dependencies.

## Main Menu

| Key | Action                                           |
| --- | ------------------------------------------------ |
| `1` | Calculate one hash or ALL available hashes       |
| `2` | Verify using an automatically detected algorithm |
| `3` | Verify using an explicitly chosen algorithm      |
| `B` | Batch verify selected files against one manifest |
| `4` | Recent files, when tracking is enabled           |
| `5` | Preferences                                      |
| `6` | Privacy & data                                   |
| `U` | Check for updates                                |
| `H` | Help & algorithms                                |
| `7` | Exit                                             |

Console menus use single keys. Text entry, paths, and confirmations require
Enter. Other hosts, including ISE, may fall back to line-based input. Enter
accepts the displayed default; Escape returns from key-based submenus. Leave a
CLI file path blank to cancel.

### Calculate

Choose a file, confirm the large-file warning if shown, and select an algorithm.
SHA256 is the default. `A` calculates all available algorithms in one streaming
read; `B` selects BLAKE3 or offers installation. Algorithm numbers depend on
runtime availability, so follow the displayed menu.

Progress shows bytes processed, speed, and ETA. ALL takes longer than a single
fast algorithm despite reading the file once. Optional auto-copy uses
algorithm-labeled lines for multiple hashes.

### Verify

Choose the target. The source prompt offers matching nearby checksum files,
pasted text, confirmed clipboard text, or another checksum file. Enter selects
the first discovered candidate; `0` goes back. In CLI mode without discovered
candidates, paste a checksum or checksum-file path directly.

Named entries must match the selected filename. Conflicting hashes and
algorithm/length disagreements are rejected. SHA3 and BLAKE3 share digest
lengths with SHA2: preserve labels or algorithm-bearing sidecar filenames, or
use option `3` to choose explicitly.

### Batch Verify

1. Choose `B` and select the manifest.
2. In GUI mode, select one or more targets in the second picker. In CLI mode,
   enter paths one at a time, then submit a blank line.
3. Review the results. Processing continues after individual errors.

The terminal shows the manifest and file count, then a numbered entry for each
file with full path, size, and detected algorithm. The PowerShell progress bar
remains active during hashing. Each result appears immediately: `OK`,
`MISMATCH`, or `ERROR`, with hashing time when available. Mismatches show
expected and calculated hashes. The final summary separates mismatches from
errors and includes total elapsed time.

Batch mode checks selected files, not every entry in the manifest. A one-file
selection is a valid batch. It does not extract archives, recursively select
folders, copy results to the clipboard, or save sidecars.

### Result Actions

| Key | Action             | Output                                                              |
| --- | ------------------ | ------------------------------------------------------------------- |
| `C` | Copy               | Hash text; labeled lines for multiple algorithms                    |
| `F` | Quick-save         | `filename.ALGORITHM.txt`, containing the digest                     |
| `M` | Save with metadata | Same naming scheme, with algorithm, timestamp, and file information |
| `E` | Export manifest    | `filename.sfv` for CRC32; `filename.ALGORITHM.sums.txt` otherwise   |
| `N` | Done               | No file written                                                     |

Outputs are saved beside the target. Username suffixes apply to quick/metadata
saves only when enabled in Privacy. Existing files are protected; move them or
supply a different path programmatically. `F` and `M` share the same default
filename, so one cannot replace the other.

## Algorithms and Formats

| Algorithm              | Availability           | Notes                                               |
| ---------------------- | ---------------------- | --------------------------------------------------- |
| SHA256, SHA384, SHA512 | Built in               | SHA256 is the default                               |
| MD5, SHA1              | Built in               | Legacy; unsuitable for adversarial integrity checks |
| CRC32                  | Windows native routine | IEEE CRC32; accidental corruption detection and SFV |
| BLAKE3                 | Optional `b3sum.exe`   | Binary streaming through the official backend       |
| SHA3-256, SHA3-512     | Runtime-dependent      | Unavailable on Windows PowerShell 5.1               |

Inputs include bare digests, GNU/coreutils, BSD/OpenBSD, OpenSSL, labeled
metadata, and SFV. Examples:

```text
<SHA256 hex digest>  archive.7z
<SHA256 hex digest> *archive.7z
BLAKE3 (archive.7z) = <BLAKE3 hex digest>
archive.7z 4948B024
```

SFV uses a filename followed by eight hexadecimal CRC32 characters. Discovery
recognizes names such as `SHA256SUMS`, `checksums.txt`, and file-specific
`.sha256`, `.sfv`, or `.BLAKE3.sums.txt` sidecars. Both path separators and
filenames with spaces are supported. Export uses GNU entries for MD5/SHA1/SHA2,
SFV for CRC32, and tagged entries for SHA3/BLAKE3.

Matching a checksum confirms agreement with the supplied value. Obtain expected
values from a trusted source for authenticity; two matching local calculations
do not establish it.

## BLAKE3 Setup

Select `B` in the algorithm menu and confirm installation, or use `H` then `I`.
Setup downloads an official Windows x64 release from GitHub, checks its
published SHA256 and size, and saves `b3sum.exe` beside the script. Installation
from the algorithm menu immediately selects BLAKE3. Declining or a failed
download returns to the menu. Existing executables are not overwritten.

Automatic installation requires 64-bit Windows and write permission beside the
script. For manual setup, download a compatible binary from
[official BLAKE3 releases](https://github.com/BLAKE3-team/BLAKE3/releases),
rename it to `b3sum.exe`, and place it beside the script or on `PATH`.

The backend's version is separate: installing b3sum 1.8.7 does not change
utility version 1.7.0.

## Preferences and Privacy

Preferences (`5`) control auto-copy, progress interval (minimum 50 ms), progress
delta (0-100%), GUI/CLI selection, large-file warning threshold, log directory,
and log viewing. Changes save immediately.

Defaults: auto-copy off, GUI selection on, 200 ms interval, 0.25% progress
delta, 1 GB warning threshold, recent history off, username metadata off, and
path anonymization on. Existing saved preferences take precedence.

Settings: `%LOCALAPPDATA%\checksum-tool\settings.json`. Default log:
`checksum_tool.log` in the same directory; its directory is configurable. Logs
rotate at 5 MB with up to five archives. Enabled history retains up to ten
entries by default.

Privacy (`6`) controls username/path handling and history, displays settings,
clears history/logs, exports settings information, and deletes local
settings/logs. Exports do not contain log contents. See [PRIVACY.md](PRIVACY.md)
for storage, networking, and deletion limits.

## Updates

Choose `U` to check
[Checksum-Verify releases](https://github.com/Dantdmnl/Checksum-Verify/releases).
No automatic startup check is performed. Installation requires confirmation;
validates SHA256, size, script syntax, and version; refuses downgrades or
concurrent local edits; and retains a uniquely named `.bak` beside the script.
Restart after updating.

Updates replace local script edits but preserve settings/logs. Releases without
a published SHA256 digest cannot be installed automatically. Updates and
optional BLAKE3 setup contact GitHub; target file contents are not uploaded.

## Programmatic Use

```powershell
# Skips menus, but initializes local settings and logging.
. .\Checksum-Verify.ps1 -NoMenu
Get-FileChecksumEx -Path 'C:\files\archive.7z' -Algorithm SHA256 -ShowProgress
Get-FileChecksumEx -Path 'C:\files\archive.7z' -Algorithm ALL -ShowProgress
Test-FileChecksum -Path 'C:\files\archive.7z' `
    -ExpectedChecksumOrFile 'C:\files\SHA256SUMS' -AutoDetectAlgorithm

# Status is opt-in; returned objects remain usable for automation.
$results = Test-FileChecksums -Path @('C:\files\one.iso', 'C:\files\two.iso') `
    -ChecksumFile 'C:\files\SHA256SUMS' -ShowProgress -ShowStatus
$results | Select-Object Path, Algorithm, Match, Error

# One algorithm per manifest, using basename filenames.
$hashes = Get-ChildItem -LiteralPath 'C:\files' -Filter '*.iso' -File |
    ForEach-Object { Get-FileChecksumEx -Path $_.FullName -Algorithm SHA256 }
Export-ChecksumManifest -Results @($hashes) -OutputPath 'C:\files\SHA256SUMS'
```

Dot-sourcing skips menus even without `-NoMenu`. Manifest export supports
`-Format Auto`, `GNU`, `SFV`, or `Tagged` and rejects incompatible formats,
duplicate basenames, and existing outputs. Verification with `-SaveOnMismatch`
writes a separate `.calculated.txt` unless an explicit path is supplied; the
target and manifest are protected.

## Troubleshooting

| Symptom                  | Check                                                                                |
| ------------------------ | ------------------------------------------------------------------------------------ |
| BLAKE3 unavailable       | Install through `B`, or check executable name/location and `PATH`                    |
| Wrong algorithm detected | Choose option `3`, or retain SHA3/BLAKE3 labels                                      |
| No matching entry        | Match the filename; archive and extracted file are different targets                 |
| Mismatch                 | Check the target, algorithm, and trusted expected value                              |
| Save refused             | Move the existing protected sidecar before saving again                              |
| Clipboard failure        | Use an interactive desktop or save/export instead                                    |
| GUI unavailable          | Switch Preferences to CLI selection                                                  |
| Permission/policy error  | Use a writable folder and the launch command above; managed policies may still apply |
| Other error              | Preferences > View recent log entries                                                |

## Developer Validation

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\Debug\test_regression.ps1
pwsh.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\Debug\test_regression.ps1
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\Debug\test_menus.ps1
pwsh.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\Debug\test_menus.ps1
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\Debug\test_syntax.ps1
# Optional real backend and read-only large-file checks:
pwsh.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\Debug\test_regression.ps1 -Blake3Executable 'C:\tools\b3sum.exe'
pwsh.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\Debug\test_large_file.ps1 -Path 'C:\files\archive.7z' `
    -Blake3Executable 'C:\tools\b3sum.exe'
```

Regression/menu suites need no additional framework and isolate settings/logs in
temporary storage. Coverage includes vectors, buffer boundaries, manifests,
conflicts, safe saves, settings, logging, batch failures, menus, and offline
updater/setup failures. Dialogs, clipboard operations, and networking use test
replacements. Large-file checks compare standard hashes with `Get-FileHash` and
optional BLAKE3 with b3sum file mode, without writing sidecars. PSScriptAnalyzer
is optional. Automated tests do not replace manual GUI checks or establish file
authenticity.
