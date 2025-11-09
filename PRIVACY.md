# Privacy Policy & GDPR Compliance

**Checksum-Verify Tool v1.3.0**  
Last Updated: November 9, 2025

## Overview

This tool is designed with privacy in mind and is fully GDPR compliant. All data is stored locally on your device. **No data is transmitted to external servers or third parties.**

## Data Collection & Storage

### What Data We Store

1. **Settings File** (`%LOCALAPPDATA%\checksum-tool\settings.json`)
   - User preferences (clipboard auto-copy, file dialog preference, etc.)
   - Recent file paths (optional, can be disabled)
   - Privacy settings

2. **Log Files** (`%LOCALAPPDATA%\checksum-tool\checksum_tool.log`)
   - Application events and errors
   - File paths (anonymized by default for privacy)
   - Timestamps of operations

3. **Optional Metadata in Generated Files**
   - Username (only if explicitly enabled in Privacy settings)
   - Timestamp of checksum creation
   - File path and algorithm used

### What We DON'T Store

- File contents
- Checksum values in persistent storage
- Any network or remote data
- Personal information beyond optional username

## Your Privacy Rights (GDPR)

The tool provides a dedicated **Privacy & Data Management** menu with the following capabilities:

### 1. Right to Access
- View all stored data in JSON format
- Export all your data to a file

### 2. Right to Rectification
- Modify settings at any time
- Toggle privacy features on/off

### 3. Right to Erasure ("Right to be Forgotten")
- Clear recent files history
- Clear all log files
- Delete ALL stored data completely

### 4. Right to Data Portability
- Export all settings and data to JSON format
- Save export to your desktop for backup or transfer

### 5. Right to Object
- Disable username inclusion in file metadata
- Enable path anonymization in logs
- Disable recent files tracking

## Privacy Features

### Default Privacy Settings (Privacy-First Design)

By default, the tool is configured for maximum privacy:

- ✅ **Username NOT included** in file metadata
- ✅ **File paths anonymized** in logs
- ✅ Recent files stored (can be cleared anytime)

### Privacy Controls

Access via: **Main Menu → 6) Privacy & Data Management**

1. **Toggle username in file metadata**
   - Default: OFF (privacy protected)
   - When OFF: Files show `[Not recorded - Privacy setting]` instead of username

2. **Toggle path anonymization in logs**
   - Default: ON (privacy protected)
   - When ON: File paths replaced with `[PATH_REDACTED]` in logs

3. **View all stored data**
   - Transparent access to everything we store

4. **Clear recent files history**
   - Remove all tracked file paths

5. **Clear all logs**
   - Permanently delete all log files

6. **Export all data (JSON)**
   - Download your data in machine-readable format

7. **Delete ALL stored data**
   - Complete erasure of settings, logs, and history
   - Requires typing 'DELETE' to confirm

## Data Retention

- **Settings**: Retained until manually deleted or tool uninstalled
- **Logs**: Auto-rotated at 5 MB, max 5 archives (self-cleaning)
- **Recent Files**: Limited to 10 most recent (configurable)

## Data Security

- All data stored locally in user's `%LOCALAPPDATA%` directory
- No encryption needed as no sensitive data is stored
- Standard Windows file permissions apply
- No network transmission of any kind

## Legal Basis for Processing

Under GDPR Article 6(1)(f) - Legitimate interests:
- Processing is necessary for the application to function
- No personal data is processed without user control
- Users can disable/delete data at any time

## Contact & Questions

For questions about privacy:
- Author: Ruben Draaisma
- Repository: https://github.com/Dantdmnl/Checksum-Verify

## Changes to Privacy Policy

Any changes to this policy will be reflected in:
- This PRIVACY.md file
- Updated version number in script header
- Changelog documentation

## Consent

By using this tool, you acknowledge:
1. You understand what data is stored locally
2. You can access, modify, or delete your data at any time
3. No data leaves your device
4. You have full control over privacy settings

---

**Version History:**
- v1.3.0 (2025-11-09): Added GDPR compliance features, privacy controls, ESC key support, recent files history, human-readable file sizes, and all approved PowerShell verbs
