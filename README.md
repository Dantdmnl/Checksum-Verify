# Checksum-Verify
Menu-driven PowerShell checksum tool (MD5/SHA1/SHA256/...) with clipboard & ISE support

## NOTES

- **Author:** Ruben Draaisma
- **Version:** 1.0
- **Tested on:** Windows 11 24H2
- **Tested with:** PowerShell ISE, PowerShell 5.1 and PowerShell 7

---

## Description

A compact, interactive PowerShell-based checksum utility that supports streaming checksum calculation (MD5, SHA-1, SHA-256, SHA-384, SHA-512) with throttled progress reporting, persistent preferences, single-key menu navigation, and convenient clipboard/save actions.

The tool is designed to be used interactively (menu-driven) but also exposes functions you can call programmatically from other scripts.

## Key Features

- Streaming checksum calculation for large files (MD5, SHA1, SHA256, SHA384, SHA512).
- Throttled `Write-Progress` updates with configurable interval and minimum delta percent to avoid flooding the UI.
- Int64-safe arithmetic for large file sizes.
- Single-key main menu navigation (no Enter required) — works in regular console windows and PowerShell ISE.
- Persistent settings stored in `%LOCALAPPDATA%\checksum-tool\settings.json`.
- Clipboard copy support (prefers `Set-Clipboard`, falls back to Windows Forms clipboard).
- File quick-save and save-with-metadata options.
- Algorithm selection menu and automatic algorithm detection when verifying checksums.
- GUI file selection dialogs (Windows Forms) for interactive file selection.

## Prerequisites

- Windows 10 or newer operating system.
- PowerShell 5.1 or PowerShell 7+ recommended.
- Permission to run PowerShell scripts (you may need to set execution policy for the current user):

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force
```

- An interactive desktop session is required for clipboard fallback (`System.Windows.Forms.Clipboard`).

## Installation

### Method 1 — Download and run locally

1. Download the latest `checksum-tool.ps1` (or `checksum-test.ps1`) from the repository's releases.
2. Right-click the file and choose **Run with PowerShell**, or run it from an elevated PowerShell window if needed.

### Method 2 — Run directly from GitHub (one-liner)

Open PowerShell and run:

```powershell
iex "& { $(iwr -useb 'https://raw.githubusercontent.com/Dantdmnl/Checksum-Verify/blob/main/checksum-tool.ps1') }"
```

## Usage

### Interactive (menu)

1. Run the script.
2. Use the single-key menu to select an action:
   - `1` Calculate checksum
   - `2` Verify checksum (auto-detect algorithm)
   - `3` Verify checksum (specify algorithm)
   - `4` Preferences
   - `5` Exit
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

Default keys: `AutoCopyToClipboard`, `ProgressUpdateIntervalMs`, `ProgressMinDeltaPercent`.

Example JSON:

```json
{
  "AutoCopyToClipboard": false,
  "ProgressUpdateIntervalMs": 200,
  "ProgressMinDeltaPercent": 0.25
}
```

## Troubleshooting

- **PowerShell ISE**: The script includes a cross-host single-key reader (`Read-SingleKey`) so single-key input works in ISE as well as in regular consoles. If your environment still requires pressing Enter in some hosts, the script will fall back to `Read-Host` as a last-resort.
- **Clipboard failures**: If `Set-Clipboard` is unavailable or fails, the script attempts a Windows Forms clipboard fallback. That fallback requires an interactive desktop session.
- **Permissions / Execution Policy**: If the script fails to run, ensure your execution policy allows running unsigned scripts for the current user (see prerequisites).
- **Verbose output**: Rerun the script enabling verbose messages to get more detail (`$VerbosePreference = 'Continue'` or use `Write-Verbose` output when debugging).