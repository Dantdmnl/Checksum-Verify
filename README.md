# Checksum-Verify
Menu-driven PowerShell checksum tool (MD5/SHA1/SHA256/...) with clipboard & ISE support

## NOTES

- **Author:** Ruben Draaisma
- **Version:** 1.3.1
- **Tested on:** Windows 11 24H2
- **Tested with:** PowerShell ISE, PowerShell 5.1 and PowerShell 7

---

## Description

A compact, interactive PowerShell-based checksum utility that supports streaming checksum calculation (MD5, SHA-1, SHA-256, SHA-384, SHA-512) with throttled progress reporting, persistent preferences, single-key menu navigation, GDPR compliance, and convenient clipboard/save actions.

The tool is designed to be used interactively (menu-driven) but also exposes functions you can call programmatically from other scripts.

## Key Features

- **Checksum Algorithms**: Streaming calculation for large files (MD5, SHA1, SHA256, SHA384, SHA512)
- **Performance**: Throttled `Write-Progress` updates with configurable interval and minimum delta percent
- **Large File Support**: Int64-safe arithmetic for files over 2GB
- **Single-Key Navigation**: No Enter required for menu selections (works in console and PowerShell ISE)
- **Dual File Selection**: Choose between GUI (File Explorer) or CLI (Type/Paste/Drag-Drop) modes
- **Recent Files**: Quick access to your last 10 processed files
- **Enhanced Progress**: Real-time speed (MB/s), ETA, and progress in window title
- **File Info Preview**: See file size, modified date, and large file warnings before processing
- **Human-Readable Sizes**: Automatic formatting (TB, GB, MB, KB)
- **Persistent Settings**: Stored in `%LOCALAPPDATA%\checksum-tool\settings.json`
- **Clipboard Support**: Auto-copy calculated checksums with `Set-Clipboard` or Windows Forms fallback
- **File Operations**: Quick-save and save-with-metadata options
- **Algorithm Detection**: Automatic algorithm detection when verifying checksums
- **Checksum File Support**: Parse various common checksum file formats
- **GDPR Compliant**: Privacy-first defaults with full data management controls
- **Logging**: Rotating logs with optional path anonymization
- **PowerShell Best Practices**: All approved verbs, parameter validation, comprehensive error handling

## Prerequisites

- Windows 10 or newer operating system.
- PowerShell 5.1 or PowerShell 7+ recommended.
- Permission to run PowerShell scripts (you may need to set execution policy for the current user):

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force
```

- An interactive desktop session is required for clipboard fallback (`System.Windows.Forms.Clipboard`).

## Installation

### Download and run locally

1. Download the latest `Checksum-Verify.ps1` from the repository's releases.
2. Right-click the file and choose **Run with PowerShell**, or run it from an elevated PowerShell window if needed.

## Usage

### Interactive (menu)

1. Run the script.
2. Use the single-key menu to select an action:
   - `1` Calculate checksum
   - `2` Verify checksum (auto-detect algorithm, supports pasted value or checksum-file)
   - `3` Verify checksum (specify algorithm, supports pasted value or checksum-file)
   - `4` Recent files (quick access to last 10 processed files)
   - `5` Preferences
   - `6` Privacy & Data Management
   - `7` Exit
3. Follow prompts and dialogs for file selection and actions.

### Example: programmatic usage

You can call the core functions from PowerShell directly:

```powershell
# Calculate checksum with progress
Get-FileChecksumEx -Path 'C:\path\to\file.iso' -Algorithm 'SHA256' -ShowProgress

# Verify checksum (auto-detect)
Test-FileChecksum -Path 'C:\path\to\file.iso' -ExpectedChecksum 'abcdef123...' -AutoDetectAlgorithm -ShowProgress
```

## Settings

Settings are stored (JSON) in:

```
%LOCALAPPDATA%\checksum-tool\settings.json
```

Default keys: `AutoCopyToClipboard`, `ProgressUpdateIntervalMs`, `ProgressMinDeltaPercent`, `UseFileDialog`, `LogDirectory`, `RecentFiles`, `MaxRecentFiles`, `IncludeUsernameInMetadata`, `AnonymizeLogPaths`.

Example JSON:

```json
{
    "AutoCopyToClipboard": false,
    "ProgressUpdateIntervalMs": 200,
    "ProgressMinDeltaPercent": 0.25,
    "UseFileDialog": true,
    "LogDirectory": "C:\\Users\\YourUser\\AppData\\Local\\checksum-tool",
    "RecentFiles": [],
    "MaxRecentFiles": 10,
    "IncludeUsernameInMetadata": false,
    "AnonymizeLogPaths": true
}
```

## Privacy

This tool is **GDPR compliant** with privacy-first defaults:

- All data stored locally (no external transmission)
- Path anonymization in logs (enabled by default)
- Username in file metadata (disabled by default)
- Full data management via Privacy menu (view, export, delete all data)
- Transparent data storage locations

See [PRIVACY.md](PRIVACY.md) for complete privacy policy.

## Troubleshooting

- **Check Logs**
- **PowerShell ISE**: The script includes a cross-host single-key reader (`Read-SingleKey`) so single-key input works in ISE as well as in regular consoles. If your environment still requires pressing Enter in some hosts, the script will fall back to `Read-Host` as a last-resort.
- **Clipboard failures**: If `Set-Clipboard` is unavailable or fails, the script attempts a Windows Forms clipboard fallback. That fallback requires an interactive desktop session.
- **Permissions / Execution Policy**: If the script fails to run, ensure your execution policy allows running unsigned scripts for the current user (see prerequisites).
- **Verbose output**: Rerun the script enabling verbose messages to get more detail (`$VerbosePreference = 'Continue'` or use `Write-Verbose` output when debugging).