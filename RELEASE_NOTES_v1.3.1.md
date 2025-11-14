# Release v1.3.1 - Bug Fixes & UX Improvements

## 🐛 Bug Fixes
- **Fixed: Script crash on locked files** - The script now gracefully handles files that are open in other programs instead of crashing with an unhandled exception
- **Fixed: ESC key not working in Preferences menu** - ESC now properly exits the Preferences menu
- **Fixed: Recent files action menu requires Enter** - Now uses single-key selection like other menus

## ✨ Improvements
- **Configurable file size warning** - Large file warning threshold is now adjustable in Preferences (default: 1.0 GB)
- **Improved error messages** - Clear, user-friendly error messages for common file access issues:
  - File locked by another process
  - Access denied / permission issues
  - File not found errors
- **Consistent error handling** - Applied improved error handling to both calculation and verification operations
- **Enhanced recent files UX** - Better match/mismatch display formatting with consistent [OK]/[FAIL] indicators

## 📋 Changes
- Error messages now use clean `Write-Host` output instead of PowerShell error streams
- Added actionable suggestions for common errors (e.g., "Close the file and try again")
- Recent files action menu now responds immediately to key press (no Enter required)
- Preferences menu: Added option 5 for configuring large file warning threshold
- All menu options renumbered for consistency (0 = Back/Cancel)

## 🔧 Technical
- 1,697 lines of code (+128 from v1.3.0)
- 56 error handlers (improved coverage)
- All syntax tests passing

---

**Previous Release**: [v1.3.0](https://github.com/Dantdmnl/Checksum-Verify/releases/tag/v1.3.0)
