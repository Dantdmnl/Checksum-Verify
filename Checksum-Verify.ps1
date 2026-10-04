<#
.SYNOPSIS
    Checksum Tool with persistent settings and single-key main-menu navigation.

.DESCRIPTION
    - Streaming checksums with progress (MD5/SHA1/SHA2/SHA3/CRC32 and optional BLAKE3)
    - Stable throttled Write-Progress and Int64-safe math for large files
    - Quick-save and metadata-save functions (fast file writes)
    - Clipboard copy (Set-Clipboard preferred, fallback to Windows.Forms clipboard)
    - Algorithm selection menu with ESC key support
    - Settings persisted to %LOCALAPPDATA%\checksum-tool\settings.json
    - Main menu accepts single-key input (no Enter required)
    - Dual file selection modes: GUI (File Explorer) or CLI (Type/Paste/Drag-Drop)
    - Recent files history for quick access
    - Human-readable file size display with large file warnings
    - Enhanced progress display with speed and ETA
    - Window title shows progress during processing
    - View recent log entries from preferences
    - Log file for troubleshooting
    - Support for checksum files in GNU/coreutils, BSD/OpenBSD, OpenSSL, and labeled formats
    - Auto-discovery of checksum files in target file directory, including target.iso.SHA256.txt
    - Cross-platform path handling for checksum files
    - All functions use approved PowerShell verbs
    - Local privacy controls and user-initiated verified updates

.PRIVACY
    This tool stores local data for functionality:
    - Settings file: %LOCALAPPDATA%\checksum-tool\settings.json
    - Log file: %LOCALAPPDATA%\checksum-tool\checksum_tool.log
    - Recent files: File paths only (no file contents)
    - Username: Optional, only in file metadata if enabled
    
    Settings, logs, and history stay local. Optional updates and BLAKE3 setup
    contact GitHub; selected file contents and checksum input are not uploaded.
    You can view, export, or delete all stored data via the Privacy menu.

.NOTES
    - Author: Ruben Draaisma
    - Version: 1.7.0
    - Tested on: Windows 11 24H2
    - Tested with: PowerShell ISE, PowerShell 5.1 and PowerShell 7
#>

param([switch] $NoMenu)

#region Version & helper: settings path
$ScriptVersion = '1.7.0'
$script:ApplicationPath = $PSCommandPath

function Get-SettingsFilePath {
    try {
        $localApp = [Environment]::GetFolderPath('LocalApplicationData')
        if (-not $localApp -or [string]::IsNullOrWhiteSpace($localApp)) { $localApp = $env:TEMP }
    } catch { $localApp = $env:TEMP }
    $dir = Join-Path -Path $localApp -ChildPath 'checksum-tool'
    if (-not (Test-Path -LiteralPath $dir)) {
        try { New-Item -ItemType Directory -Path $dir -Force | Out-Null } catch {}
    }
    return Join-Path -Path $dir -ChildPath 'settings.json'
}

function Get-DefaultSettings {
    $defaultLogDir = Split-Path -Parent (Get-SettingsFilePath)
    return [PSCustomObject]@{
        AutoCopyToClipboard       = $false
        ProgressUpdateIntervalMs  = 200
        ProgressMinDeltaPercent   = 0.25
        UseFileDialog             = $true
        LogDirectory              = $defaultLogDir
        EnableRecentFiles         = $false
        RecentFiles               = @()
        MaxRecentFiles            = 10
        IncludeUsernameInMetadata = $false
        AnonymizeLogPaths         = $true
        LargeFileSizeWarningGB    = 1.0
    }
}
#endregion

#region Logging (rotating)
$Global:MaxLogSizeMB   = 5
$Global:MaxLogArchives = 5
$Global:MinLogLevel    = "INFO"
$Global:LogLevels      = @{ "DEBUG"=1; "INFO"=2; "WARN"=3; "ERROR"=4; "CRITICAL"=5 }

function Invoke-LogRotation {
    try {
        if (-not (Test-Path -LiteralPath $Global:LogFile)) { return }
        $fileSizeMB = (Get-Item -LiteralPath $Global:LogFile).Length / 1MB
        if ($fileSizeMB -lt $Global:MaxLogSizeMB) { return }

        $oldest = "$Global:LogFile.$Global:MaxLogArchives.log"
        if (Test-Path -LiteralPath $oldest) { Remove-Item -LiteralPath $oldest -Force -ErrorAction Stop }

        for ($i = $Global:MaxLogArchives - 1; $i -ge 1; $i--) {
            $oldLog = "$Global:LogFile.$i.log"
            $newLog = "$Global:LogFile.$($i + 1).log"
            if (Test-Path -LiteralPath $oldLog) { Move-Item -LiteralPath $oldLog -Destination $newLog -Force -ErrorAction Stop }
        }

        Move-Item -LiteralPath $Global:LogFile -Destination "$Global:LogFile.1.log" -Force -ErrorAction Stop
    } catch { }
}

function Write-LogMessage {
    param([string] $Message, [ValidateSet("DEBUG","INFO","WARN","ERROR","CRITICAL")] [string] $Level = "INFO")
    try {
        if ($Global:LogLevels[$Level] -lt $Global:LogLevels[$Global:MinLogLevel]) { return }
    } catch {}

    try {
        if (-not $Global:LogFile) { return }
        Invoke-LogRotation
        
        # Anonymize file paths if enabled (GDPR privacy)
        if ($Global:Settings.AnonymizeLogPaths) {
            $Message = $Message -replace '([A-Z]:[\\/][^"'']+)', '[PATH_REDACTED]'
            $Message = $Message -replace '(\\\\[^"'']+)', '[UNC_PATH_REDACTED]'
        }
        
        $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $entry = [PSCustomObject]@{ timestamp = $ts; level = $Level; message = $Message } | ConvertTo-Json -Compress
        [IO.File]::AppendAllText($Global:LogFile, $entry + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
    } catch {}
}
#endregion

#region Settings persistence (load/save/normalize)
function Save-Settings {
    param([Parameter(Mandatory=$true)] $Settings)
    $path = Get-SettingsFilePath
    $temporaryPath = $null
    $backupPath = $null
    try {
        $dir = Split-Path -Parent $path
        if (-not (Test-Path -LiteralPath $dir)) { try { New-Item -ItemType Directory -Path $dir -Force | Out-Null } catch {} }
        $json = $Settings | ConvertTo-Json -Depth 4 -ErrorAction Stop
        $temporaryPath = Join-Path $dir ([IO.Path]::GetRandomFileName())
        [IO.File]::WriteAllText($temporaryPath, $json, [Text.UTF8Encoding]::new($false))
        if ([IO.File]::Exists($path)) {
            $backupPath = Join-Path $dir ([IO.Path]::GetRandomFileName())
            [IO.File]::Replace($temporaryPath, $path, $backupPath)
        }
        else { [IO.File]::Move($temporaryPath, $path) }
        Write-LogMessage -Message ("Settings saved to {0}" -f $path) -Level INFO
        return $true
    } catch {
        Write-LogMessage -Message ("Failed saving settings: {0}" -f $_.Exception.Message) -Level ERROR
        return $false
    } finally {
        if ($temporaryPath -and [IO.File]::Exists($temporaryPath)) { [IO.File]::Delete($temporaryPath) }
        if ($backupPath -and [IO.File]::Exists($backupPath)) { [IO.File]::Delete($backupPath) }
    }
}

function ConvertTo-NormalizedSettings {
    param([Parameter(Mandatory=$true)] $Obj)
    if (-not ($Obj -is [PSCustomObject])) {
        try { $Obj = [PSCustomObject]$Obj } catch { $Obj = [PSCustomObject]@{} }
    }
    $defaults = Get-DefaultSettings
    foreach ($prop in $defaults.PSObject.Properties.Name) {
        if (-not ($Obj.PSObject.Properties.Name -contains $prop)) {
            $Obj | Add-Member -MemberType NoteProperty -Name $prop -Value ($defaults.$prop)
        }
    }

    try {
        $tmp = 0
        if (-not [int]::TryParse("$($Obj.ProgressUpdateIntervalMs)", [ref]$tmp) -or $tmp -lt 50) {
            $Obj.ProgressUpdateIntervalMs = $defaults.ProgressUpdateIntervalMs
        } else {
            $Obj.ProgressUpdateIntervalMs = [int]$tmp
        }
    } catch { $Obj.ProgressUpdateIntervalMs = $defaults.ProgressUpdateIntervalMs }

    try {
        $d = [double]::Parse("$($Obj.ProgressMinDeltaPercent)") 2>$null
        if ($d -lt 0) { $Obj.ProgressMinDeltaPercent = $defaults.ProgressMinDeltaPercent } else { $Obj.ProgressMinDeltaPercent = [double]$d }
    } catch { $Obj.ProgressMinDeltaPercent = $defaults.ProgressMinDeltaPercent }

    try {
        $b = $Obj.AutoCopyToClipboard
        if ($b -is [string]) { $Obj.AutoCopyToClipboard = $b -match '^(1|true|yes)$' } else { $Obj.AutoCopyToClipboard = [bool]$b }
    } catch { $Obj.AutoCopyToClipboard = $defaults.AutoCopyToClipboard }

    try {
        $b = $Obj.UseFileDialog
        if ($b -is [string]) { $Obj.UseFileDialog = $b -match '^(1|true|yes)$' } else { $Obj.UseFileDialog = [bool]$b }
    } catch { $Obj.UseFileDialog = $defaults.UseFileDialog }

    try {
        $b = $Obj.EnableRecentFiles
        if ($b -is [string]) { $Obj.EnableRecentFiles = $b -match '^(1|true|yes)$' } else { $Obj.EnableRecentFiles = [bool]$b }
    } catch { $Obj.EnableRecentFiles = $defaults.EnableRecentFiles }

    try {
        if (-not $Obj.LogDirectory) { $Obj.LogDirectory = $defaults.LogDirectory }
        $ld = $Obj.LogDirectory.Trim()
        $Obj.LogDirectory = $ld
    } catch { $Obj.LogDirectory = $defaults.LogDirectory }

    try {
        $gb = [double]::Parse("$($Obj.LargeFileSizeWarningGB)") 2>$null
        if ($gb -lt 0) { $Obj.LargeFileSizeWarningGB = $defaults.LargeFileSizeWarningGB } else { $Obj.LargeFileSizeWarningGB = [double]$gb }
    } catch { $Obj.LargeFileSizeWarningGB = $defaults.LargeFileSizeWarningGB }

    foreach ($name in @('IncludeUsernameInMetadata', 'AnonymizeLogPaths')) {
        $value = $Obj.$name
        if ($value -is [bool]) { continue }
        if ("$value" -match '^(true|yes|1)$') { $Obj.$name = $true }
        elseif ("$value" -match '^(false|no|0)$') { $Obj.$name = $false }
        else { $Obj.$name = $defaults.$name }
    }
    foreach ($name in @('ProgressMinDeltaPercent', 'LargeFileSizeWarningGB')) {
        $value = [double]$Obj.$name
        if ([double]::IsNaN($value) -or [double]::IsInfinity($value) -or $value -lt 0 -or ($name -eq 'ProgressMinDeltaPercent' -and $value -gt 100)) { $Obj.$name = $defaults.$name }
    }
    $limit = 0
    if (-not [int]::TryParse("$($Obj.MaxRecentFiles)", [ref]$limit) -or $limit -lt 1 -or $limit -gt 100) { $limit = $defaults.MaxRecentFiles }
    $Obj.MaxRecentFiles = $limit
    $Obj.RecentFiles = @($Obj.RecentFiles | Where-Object { $_ -is [string] -and -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique -First $limit)
    return $Obj
}

function Import-Settings {
    $path = Get-SettingsFilePath
    if (-not (Test-Path -LiteralPath $path)) {
        $defaults = Get-DefaultSettings
        Save-Settings -Settings $defaults | Out-Null
        return [PSCustomObject]$defaults
    }
    try {
        $json = Get-Content -LiteralPath $path -Raw -ErrorAction Stop
        if (-not $json -or $json.Trim().Length -eq 0) {
            $defaults = Get-DefaultSettings
            Save-Settings -Settings $defaults | Out-Null
            return [PSCustomObject]$defaults
        }
        $o = $json | ConvertFrom-Json -ErrorAction Stop
        $o = ConvertTo-NormalizedSettings -Obj $o
        return $o
    } catch {
        Write-LogMessage -Message ("Settings load failed, recreating defaults: {0}" -f $_.Exception.Message) -Level WARN
        $defaults = Get-DefaultSettings
        Save-Settings -Settings $defaults | Out-Null
        return [PSCustomObject]$defaults
    }
}

try {
    $loaded = Import-Settings
    if (-not $loaded) { $loaded = Get-DefaultSettings }
    $Global:Settings = ConvertTo-NormalizedSettings -Obj $loaded
} catch {
    Write-LogMessage -Message ("Unexpected error loading settings: {0}" -f $_.Exception.Message) -Level ERROR
    $Global:Settings = Get-DefaultSettings
}

# Initialize log path globals using settings
$Global:LogDirectory = $Global:Settings.LogDirectory
if (-not (Test-Path -Path $Global:LogDirectory)) {
    try { New-Item -ItemType Directory -Path $Global:LogDirectory -Force | Out-Null } catch {}
}
$Global:LogFile = Join-Path -Path $Global:LogDirectory -ChildPath "checksum_tool.log"

Write-LogMessage -Message ("Checksum tool starting (v{0})" -f $ScriptVersion) -Level INFO
Write-LogMessage -Message ("LogDirectory set to {0}" -f $Global:LogDirectory) -Level INFO
#endregion

#region Utility: File size formatting
function Format-FileSize {
    param(
        [Parameter(Mandatory=$true)]
        [int64] $Bytes
    )
    
    if ($Bytes -ge 1TB) {
        return "{0:N2} TB" -f ($Bytes / 1TB)
    } elseif ($Bytes -ge 1GB) {
        return "{0:N2} GB" -f ($Bytes / 1GB)
    } elseif ($Bytes -ge 1MB) {
        return "{0:N2} MB" -f ($Bytes / 1MB)
    } elseif ($Bytes -ge 1KB) {
        return "{0:N2} KB" -f ($Bytes / 1KB)
    } else {
        return "{0} bytes" -f $Bytes
    }
}
#endregion

#region Utility: Clipboard (deferred Add-Type)
function Copy-ToClipboard {
    param([Parameter(Mandatory=$true)][string] $Text)
    if (Get-Command -Name Set-Clipboard -ErrorAction SilentlyContinue) {
        try { Set-Clipboard -Value $Text -ErrorAction Stop; return $true } catch { Write-LogMessage -Message ("Set-Clipboard failed: {0}" -f $_.Exception.Message) -Level WARN }
    }
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
        [void][System.Windows.Forms.Clipboard]::SetText($Text)
        return $true
    } catch {
        Write-LogMessage -Message ("Fallback clipboard failed: {0}" -f $_.Exception.Message) -Level WARN
        return $false
    }
}

function Get-ClipboardText {
    if (Get-Command -Name Get-Clipboard -ErrorAction SilentlyContinue) {
        try { return (Get-Clipboard -Raw -ErrorAction Stop) } catch { Write-LogMessage -Message ("Get-Clipboard failed: {0}" -f $_.Exception.Message) -Level WARN }
    }
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
        return [System.Windows.Forms.Clipboard]::GetText()
    } catch {
        Write-LogMessage -Message ("Fallback clipboard read failed: {0}" -f $_.Exception.Message) -Level WARN
        return $null
    }
}

function Get-ConfirmedClipboardChecksumText {
    param([string] $TargetFile)

    $clipboardText = Get-ClipboardText
    if (-not $clipboardText) {
        Write-Host "Clipboard does not contain text." -ForegroundColor Yellow
        return $null
    }

    $targetName = if ($TargetFile) { Split-Path -Leaf $TargetFile } else { $null }
    $parsed = $null
    try {
        $parsed = ConvertFrom-ChecksumText -Text $clipboardText -TargetFilename $targetName
    } catch {
        $parsed = $null
    }

    Write-Host ""
    Write-MenuHeader -Title "Clipboard Checksum Preview" -Subtitle "Confirm before using clipboard text"
    if ($parsed -and $parsed.Checksum) {
        $algHint = if ($parsed.Algorithm) { $parsed.Algorithm } else { Get-ChecksumAlgorithmFromLength -Checksum $parsed.Checksum }
        $matchHint = if ($parsed.FilenameMatch) { "target match" } else { "candidate" }
        Write-Host ("  Algorithm: {0}" -f $algHint) -ForegroundColor White
        Write-Host ("  Checksum:  {0}" -f $parsed.Checksum) -ForegroundColor Green
        Write-Host ("  Source:    {0}, line {1}" -f $matchHint, $parsed.LineNumber) -ForegroundColor DarkGray
    } else {
        $preview = ($clipboardText -replace '\s+', ' ').Trim()
        if ($preview.Length -gt 96) { $preview = $preview.Substring(0, 96) + "..." }
        Write-Host "  No supported checksum was detected in the clipboard text." -ForegroundColor Yellow
        if ($preview) { Write-Host ("  Preview: {0}" -f $preview) -ForegroundColor DarkGray }
    }

    $confirm = Read-Host "Use clipboard text? (Y/N) [Y]"
    if ($confirm -match '^[nN]') {
        Write-Host "Clipboard input cancelled." -ForegroundColor DarkGray
        return $null
    }

    return $clipboardText
}
#endregion

#region Utility: Interactive display helpers
function Show-FileSummary {
    param(
        [Parameter(Mandatory=$true)][string] $Path,
        [string] $Title = "Selected File"
    )

    try {
        $fileInfo = Get-Item -LiteralPath $Path -ErrorAction Stop
        Write-Host ""
        Write-MenuHeader -Title $Title -Subtitle $fileInfo.Name
        Write-Host ("  Size:     {0} ({1:N0} bytes)" -f (Format-FileSize -Bytes $fileInfo.Length), $fileInfo.Length) -ForegroundColor White
        Write-Host ("  Modified: {0}" -f $fileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")) -ForegroundColor White
        Write-Host ("  Path:     {0}" -f $fileInfo.FullName) -ForegroundColor DarkGray
        return $fileInfo
    } catch {
        Write-LogMessage -Message ("Failed to get file summary: {0}" -f $_.Exception.Message) -Level WARN
        return $null
    }
}

function Write-StatusMessage {
    param([Parameter(Mandatory=$true)][string] $Message)
    Write-Host ""
    Write-Host ("... {0}" -f $Message) -ForegroundColor Cyan
}

function Show-ChecksumResults {
    param(
        [Parameter(Mandatory=$true)][array] $Results,
        [Parameter(Mandatory=$true)][string] $FilePath
    )

    $fileName = Split-Path -Leaf $FilePath
    $fileSize = Format-FileSize -Bytes $Results[0].Length
    Write-Host ""
    Write-MenuHeader -Title "Checksum Result" -Subtitle ("{0} | {1}" -f $fileName, $fileSize)

    foreach ($res in $Results) {
        Write-Host ("  {0,-10} {1}" -f $res.Algorithm, $res.Checksum) -ForegroundColor Green
    }

    Write-Host ""
    Write-Host ("  Time: {0:N2} seconds" -f $Results[0].Elapsed.TotalSeconds) -ForegroundColor DarkGray
}

function Show-FriendlyError {
    param(
        [string] $Action = "Operation",
        [Parameter(Mandatory=$true)] $ErrorRecord
    )

    $message = $ErrorRecord.Exception.Message
    Write-Host ""
    Write-MenuHeader -Title ("{0} Failed" -f $Action) -Subtitle "The tool could not complete the requested operation"

    if ($message -match "being used by another process") {
        Write-Host "  The file is currently open in another program." -ForegroundColor Red
        Write-Host "  Close the file and try again." -ForegroundColor Yellow
    } elseif ($message -match "Access.*denied") {
        Write-Host "  Access denied while reading the file." -ForegroundColor Red
        Write-Host "  Try a different folder or run PowerShell with sufficient permissions." -ForegroundColor Yellow
    } elseif ($message -match "Unable to detect algorithm|Algorithm must be specified") {
        Write-Host ("  {0}" -f $message) -ForegroundColor Red
        Write-Host "  Try Verify with chosen algorithm, or paste a full MD5/SHA checksum." -ForegroundColor Yellow
    } else {
        Write-Host ("  {0}" -f $message) -ForegroundColor Red
    }

    Write-Host ""
}
#endregion

#region Recent files management
function Get-RecentFilesStatus {
    if (-not $Global:Settings.EnableRecentFiles) {
        return [PSCustomObject]@{
            Enabled = $false
            Count = 0
            Detail = "Off in Privacy"
        }
    }

    $count = if ($Global:Settings.RecentFiles) { @($Global:Settings.RecentFiles).Count } else { 0 }
    $detail = if ($count -gt 0) { "{0} available" -f $count } else { "Empty" }
    return [PSCustomObject]@{
        Enabled = $true
        Count = $count
        Detail = $detail
    }
}

function Add-RecentFile {
    param([Parameter(Mandatory=$true)][string] $FilePath)
    
    if (-not $Global:Settings.EnableRecentFiles) { return }

    if (-not $Global:Settings.RecentFiles) {
        $Global:Settings | Add-Member -MemberType NoteProperty -Name RecentFiles -Value @() -Force
    }
    
    # Remove if already exists (to move to top)
    $Global:Settings.RecentFiles = @($Global:Settings.RecentFiles | Where-Object { $_ -ne $FilePath })
    
    # Add to beginning
    $Global:Settings.RecentFiles = @($FilePath) + $Global:Settings.RecentFiles
    
    # Trim to max
    $maxFiles = if ($Global:Settings.MaxRecentFiles) { $Global:Settings.MaxRecentFiles } else { 10 }
    if ($Global:Settings.RecentFiles.Count -gt $maxFiles) {
        $Global:Settings.RecentFiles = $Global:Settings.RecentFiles[0..($maxFiles - 1)]
    }
    
    Save-Settings -Settings $Global:Settings | Out-Null
}

function Show-RecentFilesMenu {
    if (-not $Global:Settings.RecentFiles -or $Global:Settings.RecentFiles.Count -eq 0) {
        Write-Host "No recent files." -ForegroundColor Yellow
        Start-Sleep -Milliseconds 1000
        return $null
    }
    
    Clear-Host
    Write-MenuHeader -Title "Recent Files" -Subtitle "Pick a previously used file"
    
    $validFiles = @()
    $index = 1
    foreach ($file in $Global:Settings.RecentFiles) {
        if (Test-Path -LiteralPath $file -PathType Leaf) {
            $fileName = Split-Path -Leaf $file
            $fileSize = Format-FileSize -Bytes (Get-Item -LiteralPath $file).Length
            Write-MenuItem -Key $index -Label $fileName -Detail $fileSize
            Write-Host ("   {0}" -f $file) -ForegroundColor DarkGray
            $validFiles += $file
            $index++
        }
    }
    
    if ($validFiles.Count -eq 0) {
        Write-Host "No valid recent files found." -ForegroundColor Yellow
        Start-Sleep -Milliseconds 1000
        return $null
    }
    
    Write-Host ""
    Write-MenuItem -Key "0" -Label "Back"
    Write-Host ""
    
    if ($validFiles.Count -le 9) {
        Write-Host ("Choose a file (0-{0})  ESC=Back" -f $validFiles.Count) -ForegroundColor DarkGray
        
        $choice = Read-SingleKey
        try { $choice = [string]$choice; $choice = $choice.Trim() } catch {}
    } else {
        Write-Host "Type a number, or leave blank to go back." -ForegroundColor DarkGray
        $choice = Read-Host "Choose a file (0-$($validFiles.Count))"
    }
    
    if ([string]::IsNullOrWhiteSpace($choice) -or $choice -eq '0' -or $choice -eq [char]27 -or $choice -match '^\x1B') {
        return $null
    }
    
    try {
        $idx = [int]$choice - 1
        if ($idx -ge 0 -and $idx -lt $validFiles.Count) {
            return $validFiles[$idx]
        }
    } catch {}
    
    Write-Host "Invalid choice." -ForegroundColor Yellow
    Start-Sleep -Milliseconds 700
    return $null
}
#endregion

#region File selection helper (typed-path trims quotes)
function Select-File {
    param(
        [string] $Prompt = "Select a file",
        [string] $InitialDirectory = $null,
        [switch] $ShowFileInfo
    )
    if (-not $InitialDirectory) { $InitialDirectory = [Environment]::GetFolderPath('Desktop') }

    $selectedFile = $null

    if ($Global:Settings.UseFileDialog) {
        $fileDialog = $null
        try {
            Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
            $fileDialog = New-Object System.Windows.Forms.OpenFileDialog
            $fileDialog.InitialDirectory = $InitialDirectory
            $fileDialog.Filter = "All files (*.*)|*.*"
            $fileDialog.Title = $Prompt
            if ($fileDialog.ShowDialog() -eq 'OK') {
                $selectedFile = $fileDialog.FileName
            } else {
                return $null
            }
        } catch {
            Write-LogMessage -Message ("OpenFileDialog failed: {0}" -f $_.Exception.Message) -Level WARN
            return $null
        } finally { if ($fileDialog) { $fileDialog.Dispose() } }
    } else {
        # CLI mode - type or paste path
        Write-Host ""
        Write-MenuHeader -Title "File Selection" -Subtitle "Drag a file here, paste a path, or leave blank to go back"
        Write-Host ""
        
        while ($true) {
            $userInput = Read-Host ("{0} - Enter full path (or leave blank to cancel)" -f $Prompt)
            if (-not $userInput) { return $null }
            $userInput = $userInput.Trim()
            $userInput = $userInput.Trim('"','''')
            
            # Handle drag-and-drop format (may include extra quotes or spaces)
            if ($userInput -match '^&\s*(.+)$') {
                $userInput = $matches[1].Trim().Trim('"','''')
            }
            
            try {
                $resolved = Resolve-Path -LiteralPath $userInput -ErrorAction Stop
                $first = $resolved | Select-Object -First 1
                if (Test-Path -LiteralPath $first.Path -PathType Leaf) {
                    $selectedFile = $first.Path
                    break
                } else {
                    Write-Host "Error: Path is not a file. Please try again or leave blank to cancel." -ForegroundColor Yellow
                }
            } catch {
                Write-Host "Error: Path not found. Please verify the path and try again (or leave blank to cancel)." -ForegroundColor Yellow
            }
        }
    }

    # Show file info if selected and requested
    if ($selectedFile -and $ShowFileInfo) {
        try {
            $fileInfo = Show-FileSummary -Path $selectedFile -Title "Selected File"
            if (-not $fileInfo) { return $selectedFile }
            $fileSize = Format-FileSize -Bytes $fileInfo.Length
            
            # Warn for very large files (configurable threshold)
            $warningThresholdBytes = $Global:Settings.LargeFileSizeWarningGB * 1GB
            if ($fileInfo.Length -gt $warningThresholdBytes) {
                Write-Host ""
                Write-Host ("Large file: {0}." -f $fileSize) -ForegroundColor Yellow
                $confirm = Read-Host "Continue? (Y/N) [Y]"
                if ($confirm -match '^[nN]') {
                    Write-Host "Cancelled by user." -ForegroundColor Yellow
                    return $null
                }
            }
        } catch {
            Write-LogMessage -Message ("Failed to get file info: {0}" -f $_.Exception.Message) -Level WARN
        }
    }

    return $selectedFile
}
#endregion

#region Algorithm selection
function Select-AlgorithmMenu {
    param([string] $Prompt = "Select algorithm", [string] $Default = "SHA256", [switch] $AllowAll)
    $available = @(Get-SupportedChecksumAlgorithms)
    $map = @{}
    $index = 1
    foreach ($algorithm in @('SHA256','SHA384','SHA512','CRC32','MD5','SHA1','SHA3-256','SHA3-512')) {
        if ($algorithm -in $available) { $map[[string]$index] = $algorithm; $index++ }
    }
    if ($AllowAll) { $map['A'] = 'ALL' }
    if ('BLAKE3' -in $available) { $map['B'] = 'BLAKE3' }
    while ($true) {
        Write-Host ""
        Write-MenuHeader -Title $Prompt -Subtitle ("Default: {0}" -f $Default)
        foreach ($key in @($map.Keys | Where-Object { $_ -match '^\d+$' } | Sort-Object { [int]$_ })) {
            $algorithm = $map[$key]
            $detail = switch ($algorithm) {
                'SHA256' { 'Recommended default' }
                'CRC32' { 'SFV / accidental corruption' }
                'MD5' { 'Legacy' }
                'SHA1' { 'Legacy' }
                default { '' }
            }
            Write-Host ('  {0}) {1,-10} {2}' -f $key, $algorithm, $detail) -ForegroundColor White
        }
        if ($AllowAll) { Write-Host '  A) ALL        One read, all available hashes' -ForegroundColor White }
        if ($map.ContainsKey('B')) { Write-Host '  B) BLAKE3' -ForegroundColor White }
        else { Write-Host '  B) BLAKE3     Install support' -ForegroundColor DarkGray }
        Write-Host "  0) Back" -ForegroundColor DarkGray
        Write-Host ""
        
        $optRange = '1-' + ($index - 1) + $(if ($AllowAll) { ', A' }) + ', B, 0'
        Write-Host ("Choose ({0})  Enter={1}  ESC=Back" -f $optRange, $Default) -ForegroundColor DarkGray
        
        $choice = Read-SingleKey
        try { $choice = [string]$choice; $choice = $choice.Trim().ToUpperInvariant() } catch {}
        if ([string]::IsNullOrWhiteSpace($choice)) { return $Default }
        if ($choice -eq [char]27 -or $choice -match '^\x1B') { return $null }
        if ($map.ContainsKey($choice)) { return $map[$choice] }
        if ($choice -eq 'B') {
            Write-Host 'BLAKE3 requires the official b3sum.exe. Installation downloads a verified Windows x64 release from GitHub beside this script.' -ForegroundColor Yellow
            if ((Read-Host 'Download and install BLAKE3 support? [y/N]').Trim() -ieq 'y') {
                try {
                    $installed = Install-Blake3Tool -Directory (Split-Path -Parent $script:ApplicationPath)
                    if (-not (Get-Blake3Executable)) { throw 'Installed executable could not be found.' }
                    Write-Host "Installed $($installed.Version). Using BLAKE3." -ForegroundColor Green
                    return 'BLAKE3'
                } catch { Write-Host "BLAKE3 setup failed: $($_.Exception.Message)" -ForegroundColor Yellow }
            }
            continue
        }
        if ($choice -eq '0') { return $null }
        Write-Host "Invalid choice, try again." -ForegroundColor Yellow
    }
}
#endregion

#region Core checksum functions
function Get-SupportedChecksumAlgorithms {
    'MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512'
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { 'CRC32' }
    if (Get-Blake3Executable) { 'BLAKE3' }
    foreach ($name in @('SHA3-256', 'SHA3-512')) {
        $type = ('System.Security.Cryptography.' + ($name -replace '-', '_')) -as [type]
        if ($type -and $type.GetProperty('IsSupported').GetValue($null, $null)) { $name }
    }
}

function Get-ChecksumDigestLength {
    param([string] $Algorithm)
    switch ($Algorithm) {
        'CRC32' { 8 }
        'BLAKE3' { 64 }
        'MD5' { 32 }
        'SHA1' { 40 }
        'SHA256' { 64 }
        'SHA3-256' { 64 }
        'SHA384' { 96 }
        'SHA512' { 128 }
        'SHA3-512' { 128 }
        default { 0 }
    }
}

function Initialize-Crc32 {
    if ('ChecksumVerify.NativeCrc32' -as [type]) { return }
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'CRC32 requires Windows.' }
    # Windows supplies the cumulative IEEE CRC32 implementation; no CRC engine is embedded.
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace ChecksumVerify {
    public static class NativeCrc32 {
        [DllImport("ntdll.dll", ExactSpelling = true, CallingConvention = CallingConvention.Winapi)]
        public static extern uint RtlComputeCrc32(uint initial, byte[] data, uint length);
    }
}
'@ -ErrorAction Stop
}

function Get-Blake3Executable {
    if ($script:ApplicationPath) {
        $besideScript = Join-Path (Split-Path -Parent $script:ApplicationPath) 'b3sum.exe'
        if (Test-Path -LiteralPath $besideScript -PathType Leaf) { return $besideScript }
    }
    $command = Get-Command -Name b3sum.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($command) { return $command.Source }
    return $null
}

function ConvertTo-Blake3ReleaseInfo {
    param([Parameter(Mandatory=$true)] $Release)
    if ($Release.draft -or $Release.prerelease -or $Release.tag_name -cnotmatch '^[Vv]?\d+\.\d+\.\d+$') { throw 'Expected a stable BLAKE3 release.' }
    $assets = @($Release.assets | Where-Object { $_.name -ceq 'b3sum_windows_x64_bin.exe' -and $_.state -eq 'uploaded' })
    if ($assets.Count -ne 1) { throw 'The release has no unique Windows x64 b3sum asset.' }
    $asset = $assets[0]
    $url = "https://github.com/BLAKE3-team/BLAKE3/releases/download/$($Release.tag_name)/b3sum_windows_x64_bin.exe"
    if ($asset.browser_download_url -cne $url -or $asset.digest -notmatch '^sha256:[a-fA-F0-9]{64}$' -or [long]$asset.size -le 0 -or [long]$asset.size -gt 10MB) { throw 'BLAKE3 release metadata did not pass validation.' }
    [PSCustomObject]@{ DownloadUrl = $url; Digest = [string]$asset.digest; Size = [long]$asset.size; Tag = [string]$Release.tag_name }
}

function Install-Blake3Tool {
    param([Parameter(Mandatory=$true)][string] $Directory)
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitOperatingSystem) { throw 'Automatic BLAKE3 setup requires 64-bit Windows. Install a compatible b3sum manually.' }
    $Directory = (Get-Item -LiteralPath $Directory -ErrorAction Stop).FullName
    $destination = Join-Path $Directory 'b3sum.exe'
    if (Test-Path -LiteralPath $destination) { throw 'b3sum.exe already exists; it will not be overwritten.' }
    $stage = Join-Path $Directory ('.b3sum.' + [guid]::NewGuid().ToString('N') + '.download')
    $previousProtocol = [Net.ServicePointManager]::SecurityProtocol
    try {
        [Net.ServicePointManager]::SecurityProtocol = $previousProtocol -bor [Net.SecurityProtocolType]::Tls12
        $release = Invoke-RestMethod -Uri 'https://api.github.com/repos/BLAKE3-team/BLAKE3/releases/latest' `
            -Headers @{ Accept = 'application/vnd.github+json'; 'User-Agent' = 'Checksum-Verify-BLAKE3' } -TimeoutSec 20 -ErrorAction Stop
        $checked = ConvertTo-Blake3ReleaseInfo $release
        Invoke-WebRequest -Uri $checked.DownloadUrl -UseBasicParsing -TimeoutSec 60 -OutFile $stage -ErrorAction Stop | Out-Null
        if ((Get-Item -LiteralPath $stage).Length -ne $checked.Size -or ('sha256:' + (Get-FileHash -LiteralPath $stage -Algorithm SHA256).Hash) -ine $checked.Digest) { throw 'The b3sum download failed size or SHA256 verification.' }
        [IO.File]::Move($stage, $destination)
        [PSCustomObject]@{ Path = $destination; Version = $checked.Tag }
    } finally {
        [Net.ServicePointManager]::SecurityProtocol = $previousProtocol
        if ([IO.File]::Exists($stage)) { [IO.File]::Delete($stage) }
    }
}

function Start-Blake3Hasher {
    $executable = Get-Blake3Executable
    if (-not $executable) { throw 'BLAKE3 needs the official b3sum.exe beside this script or on PATH. See https://github.com/BLAKE3-team/BLAKE3/releases.' }
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $executable
    $start.Arguments = '--no-names --length 32 --no-mmap'
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { throw 'Could not start b3sum.' }
        return [PSCustomObject]@{
            Process = $process
            Output = $process.StandardOutput.ReadToEndAsync()
            Error = $process.StandardError.ReadToEndAsync()
        }
    } catch { $process.Dispose(); throw }
}

function Get-FileChecksumEx {
    [CmdletBinding(DefaultParameterSetName='ByPath')]
    param(
        [Parameter(Mandatory=$true, Position=0)][ValidateNotNullOrEmpty()][string] $Path,
        [Parameter(Mandatory=$false)][ValidateSet('MD5','SHA1','SHA256','SHA384','SHA512','SHA3-256','SHA3-512','CRC32','BLAKE3','ALL')][string[]] $Algorithm = @('SHA256'),
        [Parameter(Mandatory=$false)][ValidateRange(4096, [int]::MaxValue)][int] $BufferSize = (4 * 1MB),
        [Parameter(Mandatory=$false)][switch] $ShowProgress
    )

    begin {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { Throw "File not found: $Path" }
        $Path = (Get-Item -LiteralPath $Path -ErrorAction Stop).FullName
        if ($BufferSize -lt 4096) { Throw "BufferSize must be at least 4096 bytes." }
        $ProgressUpdateIntervalMs = [int]$Global:Settings.ProgressUpdateIntervalMs
        $ProgressMinDeltaPercent   = [double]$Global:Settings.ProgressMinDeltaPercent
        $progressId = 1
        
        if ($Algorithm -contains 'ALL') {
            $Algorithm = @(Get-SupportedChecksumAlgorithms)
        }
        $Algorithm = @($Algorithm | ForEach-Object { $_.ToUpperInvariant() } | Select-Object -Unique)
        if ($Algorithm.Count -eq 0) { throw 'At least one algorithm must be selected.' }
    }

    process {
        $fs = $null; $hashAlgos = @{}
        $blake3 = $null
        $crc = [uint32]0
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $originalTitle = $null
        
        try {
            # Save original window title
            try { $originalTitle = $Host.UI.RawUI.WindowTitle } catch { }
            
            foreach ($alg in $Algorithm) {
                if ($alg -eq 'CRC32') { Initialize-Crc32; continue }
                if ($alg -eq 'BLAKE3') { $blake3 = Start-Blake3Hasher; continue }
                if ($alg -like 'SHA3-*') {
                    $type = ('System.Security.Cryptography.' + ($alg -replace '-', '_')) -as [type]
                    if (-not $type -or $alg -notin @(Get-SupportedChecksumAlgorithms)) { throw "$alg is not supported by this PowerShell runtime." }
                    $h = $type.GetMethod('Create', [type[]]@()).Invoke($null, @())
                } else { $h = [System.Security.Cryptography.HashAlgorithm]::Create($alg) }
                if (-not $h) { Throw "Unable to create hash algorithm '$alg'." }
                $hashAlgos[$alg] = $h
            }

            $fs = [System.IO.File]::OpenRead($Path)
            $length = [int64]$fs.Length
            $buffer = New-Object byte[] $BufferSize
            $bytesRead = 0; $totalRead = 0L

            $lastUpdate = [DateTime]::UtcNow.AddMilliseconds(-$ProgressUpdateIntervalMs)
            $lastPercent = -1.0
            
            $algNameStr = if ($Algorithm.Count -gt 1) { "Multiple ($($Algorithm.Count))" } else { $Algorithm[0] }

            while (($bytesRead = $fs.Read($buffer, 0, $buffer.Length)) -gt 0) {
                foreach ($alg in $Algorithm) {
                    if ($alg -eq 'CRC32') {
                        $crc = [ChecksumVerify.NativeCrc32]::RtlComputeCrc32($crc, $buffer, [uint32]$bytesRead)
                        continue
                    }
                    if ($alg -eq 'BLAKE3') {
                        $blake3.Process.StandardInput.BaseStream.Write($buffer, 0, $bytesRead)
                        continue
                    }
                    $hashAlgos[$alg].TransformBlock($buffer, 0, $bytesRead, $null, 0) | Out-Null
                }
                $totalRead += [int64]$bytesRead

                if ($ShowProgress) {
                    $percent = if ($length -gt 0) { ([double]$totalRead / [double]$length) * 100.0 } else { 100.0 }
                    $now = [DateTime]::UtcNow
                    $timeSince = ($now - $lastUpdate).TotalMilliseconds
                    $deltaPercent = [math]::Abs($percent - $lastPercent)

                    if ($timeSince -ge $ProgressUpdateIntervalMs -and ($deltaPercent -ge $ProgressMinDeltaPercent -or $timeSince -ge ($ProgressUpdateIntervalMs * 5) -or $percent -ge 100)) {
                        $elapsedSec = [math]::Max(0.001, $sw.Elapsed.TotalSeconds)
                        $speedBytesPerSec = if ($elapsedSec -gt 0) { [double]$totalRead / $elapsedSec } else { 0.0 }

                        $remainingBytes = [math]::Max([int64]0, [int64]($length - $totalRead))
                        $etaSec = if ($speedBytesPerSec -gt 0) { [math]::Round($remainingBytes / $speedBytesPerSec) } else { 0 }
                        $processedMB = [math]::Round([double]$totalRead / 1MB, 2)
                        $totalMB = [math]::Round([double]$length / 1MB, 2)
                        $speedMBps = [math]::Round($speedBytesPerSec / 1MB, 2)

                        Write-Progress -Id $progressId -Activity ("Calculating {0} checksum(s)" -f $algNameStr) `
                                       -Status ("{0:N2}% - {1} MB of {2} MB @ {3} MB/s - ETA: {4}s" -f $percent, $processedMB, $totalMB, $speedMBps, $etaSec) `
                                       -PercentComplete ([math]::Min(100, [math]::Round($percent, 2)))
                        
                        # Update window title with progress
                        try {
                            $Host.UI.RawUI.WindowTitle = ("{0} - {1:N1}% - {2}" -f $algNameStr, $percent, (Split-Path -Leaf $Path))
                        } catch { }

                        $lastUpdate = $now
                        $lastPercent = $percent
                    }
                }
            }

            $results = @()
            foreach ($alg in $Algorithm) {
                if ($alg -eq 'CRC32') { $hex = $crc.ToString('x8') }
                elseif ($alg -eq 'BLAKE3') {
                    $blake3.Process.StandardInput.Close()
                    if (-not $blake3.Process.WaitForExit(60000)) { throw 'b3sum did not finish after its input closed.' }
                    $hex = $blake3.Output.GetAwaiter().GetResult().Trim()
                    $errorText = $blake3.Error.GetAwaiter().GetResult().Trim()
                    if ($blake3.Process.ExitCode -ne 0) { throw "b3sum failed (exit $($blake3.Process.ExitCode)): $errorText" }
                    if ($hex -notmatch '^[0-9a-fA-F]{64}$') { throw 'b3sum returned an invalid digest.' }
                    $hex = $hex.ToLowerInvariant()
                } else {
                    $hashAlgos[$alg].TransformFinalBlock($buffer, 0, 0) | Out-Null
                    $checksumBytes = $hashAlgos[$alg].Hash
                    $hex = -join ($checksumBytes | ForEach-Object { "{0:x2}" -f $_ })
                }

                Write-LogMessage -Message ("Checksum calculated for {0} ({1})" -f $Path, $alg) -Level INFO

                $results += [PSCustomObject]@{
                    Path      = (Get-Item -LiteralPath $Path).FullName
                    Algorithm = $alg
                    Checksum  = $hex
                    Length    = $length
                    Elapsed   = $sw.Elapsed
                }
            }
            $sw.Stop()
            
            # If a single algorithm was requested, return a single object for backwards compatibility
            if ($results.Count -eq 1) { return $results[0] }
            return $results

        } catch {
            Write-LogMessage -Message ("Error computing checksum: {0}" -f $_.Exception.Message) -Level ERROR
            
            # Display user-friendly error message
            Write-Host ""
            if ($_.Exception.Message -match "being used by another process") {
                Write-Host "Error: Cannot access file - it is currently open in another program." -ForegroundColor Red
                Write-Host "       Please close the file and try again." -ForegroundColor Yellow
            } elseif ($_.Exception.Message -match "Access.*denied") {
                Write-Host "Error: Access denied - insufficient permissions to read the file." -ForegroundColor Red
                Write-Host "       Try running PowerShell as Administrator." -ForegroundColor Yellow
            } elseif ($_.Exception.Message -match "could not find") {
                Write-Host "Error: File not found or path is invalid." -ForegroundColor Red
            } else {
                Write-Host "Error: Failed to compute checksum." -ForegroundColor Red
                Write-Host "       $($_.Exception.Message)" -ForegroundColor Yellow
            }
            Write-Host ""
            
            throw
        } finally {
            if ($blake3) {
                try { if (-not $blake3.Process.HasExited) { $blake3.Process.Kill() } }
                finally { $blake3.Process.Dispose() }
            }
            if ($fs) { try { $fs.Close(); $fs.Dispose() } catch {} }
            if ($hashAlgos) { 
                foreach ($h in $hashAlgos.Values) { if ($h) { $h.Dispose() } }
            }
            if ($ShowProgress) { Write-Progress -Id $progressId -Activity ("Calculating {0}" -f $algNameStr) -Completed }
            
            # Restore original window title
            if ($originalTitle) {
                try { $Host.UI.RawUI.WindowTitle = $originalTitle } catch { }
            }
        }
    }
}

function Get-ChecksumAlgorithmFromLength { param([string] $Checksum)
    switch ($Checksum.Length) {
        8   { return 'CRC32' }
        32  { return 'MD5' }
        40  { return 'SHA1' }
        64  { return 'SHA256' }
        96  { return 'SHA384' }
        128 { return 'SHA512' }
        default { Write-Verbose ("Checksum length {0} not recognized." -f $Checksum.Length); return $null }
    }
}

function ConvertTo-CanonicalChecksumAlgorithm {
    param([Parameter(Mandatory=$true)][string] $Algorithm)

    $normalized = $Algorithm.Trim().ToUpperInvariant() -replace '[^A-Z0-9]', ''
    switch ($normalized) {
        'CRC32'   { return 'CRC32' }
        'CRC'     { return 'CRC32' }
        'BLAKE3'  { return 'BLAKE3' }
        'B3'      { return 'BLAKE3' }
        'MD5'     { return 'MD5' }
        'SHA1'    { return 'SHA1' }
        'SHA256'  { return 'SHA256' }
        'SHA2256' { return 'SHA256' }
        'SHA384'  { return 'SHA384' }
        'SHA2384' { return 'SHA384' }
        'SHA512'  { return 'SHA512' }
        'SHA2512' { return 'SHA512' }
        'SHA3256' { return 'SHA3-256' }
        'SHA3512' { return 'SHA3-512' }
        default   { return $null }
    }
}

function Get-ChecksumRegexPattern {
    return '(?:[0-9A-Fa-f]{128}|[0-9A-Fa-f]{96}|[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32}|[0-9A-Fa-f]{8})'
}

function Get-ChecksumBase64RegexPattern {
    return '(?:[A-Za-z0-9+/]{86}==|[A-Za-z0-9+/]{64}|[A-Za-z0-9+/]{43}=|[A-Za-z0-9+/]{27}=|[A-Za-z0-9+/]{22}==)'
}

function Test-ChecksumValue {
    param([Parameter(Mandatory=$true)][string] $Checksum)
    return ($Checksum -match ('^(?:{0})$' -f (Get-ChecksumRegexPattern)))
}

function ConvertTo-HexChecksumFromBase64 {
    param([Parameter(Mandatory=$true)][string] $Base64)

    try {
        $bytes = [Convert]::FromBase64String($Base64.Trim())
        switch ($bytes.Length) {
            16 { break }
            20 { break }
            32 { break }
            48 { break }
            64 { break }
            default { return $null }
        }
        return (-join ($bytes | ForEach-Object { "{0:x2}" -f $_ }))
    } catch {
        return $null
    }
}

function ConvertFrom-GnuEscapedFilename {
    param([Parameter(Mandatory=$true)][string] $Filename)

    $name = $Filename.Trim()
    if (-not $name) { return $name }

    $builder = New-Object System.Text.StringBuilder
    $escaping = $false
    foreach ($ch in $name.ToCharArray()) {
        if ($escaping) {
            switch ($ch) {
                'n' { [void]$builder.Append([char]10) }
                'r' { [void]$builder.Append([char]13) }
                '\' { [void]$builder.Append('\') }
                default { [void]$builder.Append($ch) }
            }
            $escaping = $false
        } elseif ($ch -eq '\') {
            $escaping = $true
        } else {
            [void]$builder.Append($ch)
        }
    }
    if ($escaping) { [void]$builder.Append('\') }
    return $builder.ToString()
}

function Test-ChecksumFilenameMatch {
    param(
        [Parameter(Mandatory=$true)][string] $CandidateName,
        [Parameter(Mandatory=$true)][string] $TargetFilename,
        [switch] $Exact
    )

    $candidate = $CandidateName.Trim().Trim('"', '''', ':', ',', ';')
    $target = $TargetFilename.Trim().Trim('"', '''', ':', ',', ';')
    if ($Exact) {
        $candidate = $CandidateName.Trim().Trim('"', '''')
        $target = $TargetFilename.Trim().Trim('"', '''')
    }
    if (-not $candidate -or -not $target) { return $false }

    $normalizedCandidate = $candidate -replace '[\\/]', [IO.Path]::DirectorySeparatorChar
    $normalizedTarget = $target -replace '[\\/]', [IO.Path]::DirectorySeparatorChar
    $candidateLeaf = Split-Path -Leaf $normalizedCandidate
    $targetLeaf = Split-Path -Leaf $normalizedTarget

    return ($normalizedCandidate -ieq $normalizedTarget -or
            $candidateLeaf -ieq $targetLeaf -or
            $candidateLeaf -ieq $normalizedTarget)
}

function Test-ChecksumLineReferencesTarget {
    param(
        [Parameter(Mandatory=$true)][string] $Line,
        [Parameter(Mandatory=$true)][string] $TargetFilename
    )

    $quotedPattern = '(?:"(?<name>[^"]+)"|''(?<name>[^'']+)''|\((?<name>[^)]+)\)|(?<name>\S+))'
    foreach ($match in [regex]::Matches($Line, $quotedPattern)) {
        $candidate = $match.Groups['name'].Value
        if ($candidate -and (Test-ChecksumFilenameMatch -CandidateName $candidate -TargetFilename $TargetFilename)) {
            return $true
        }
    }

    return $false
}

function ConvertTo-NormalizedChecksum {
    param(
        [Parameter(Mandatory=$true)][string] $Raw,
        [Parameter(Mandatory=$false)][string] $Algorithm
    )
    if (-not $Raw) { return $null }

    $tmp = $Raw.Trim()

    $checksumPattern = Get-ChecksumRegexPattern

    # Find all complete checksum-sized hex runs without accepting partial slices of longer tokens.
    $hexMatches = [regex]::Matches($tmp, "(?<![0-9A-Fa-f])$checksumPattern(?![0-9A-Fa-f])") | ForEach-Object { $_.Value }
    
    if ($hexMatches -and $hexMatches.Count -gt 0) {
        if ($Algorithm) {
            $canonicalAlgorithm = ConvertTo-CanonicalChecksumAlgorithm -Algorithm $Algorithm
            if (-not $canonicalAlgorithm) { return $null }
            $expectedLen = Get-ChecksumDigestLength -Algorithm $canonicalAlgorithm
            if ($expectedLen -gt 0) {
                # Find matching lengths
                $lenMatches = @($hexMatches | Where-Object { $_.Length -eq $expectedLen })
                
                # If there's multiple of the same length, check if one is explicitly prefixed
                foreach ($hm in $lenMatches) {
                    $pattern = "(?i)$([regex]::Escape($Algorithm))\s*:\s*($hm)"
                    if ($tmp -match $pattern) { return $hm.ToLower() }
                }
                
                if ($lenMatches.Count -gt 0) { return $lenMatches[0].ToLower() }
                return $null
            }
        }
        
        # Fallback to picking the strongest available algorithm by digest length.
        $chosen = $hexMatches | Sort-Object { $_.Length } -Descending | Select-Object -First 1
        return $chosen.ToLower()
    }

    # Fallback: strip separators and labels, but only accept exact checksum lengths.
    $stripped = -join (($tmp.ToCharArray() | Where-Object { $_ -match '[0-9A-Fa-f]' }))
    if ($tmp -match '^[0-9A-Fa-f\s:-]+$' -and $stripped.Length -gt 0 -and (Test-ChecksumValue -Checksum $stripped)) {
        if ($Algorithm -and $stripped.Length -ne (Get-ChecksumDigestLength -Algorithm (ConvertTo-CanonicalChecksumAlgorithm -Algorithm $Algorithm))) { return $null }
        return $stripped.ToLowerInvariant()
    }

    return $null
}

function Find-ChecksumFiles {
    param(
        [Parameter(Mandatory=$true)][string] $TargetFilePath
    )

    if (-not (Test-Path -LiteralPath $TargetFilePath -PathType Leaf)) { return @() }

    $targetDir = Split-Path -Parent $TargetFilePath
    $targetName = Split-Path -Leaf $TargetFilePath
    $targetBase = [IO.Path]::GetFileNameWithoutExtension($targetName)
    $checksumPattern = Get-ChecksumRegexPattern
    $base64Pattern = Get-ChecksumBase64RegexPattern
    $algorithmExtensions = @('md5', 'sha1', 'sha256', 'sha384', 'sha512', 'sha3-256', 'sha3-512', 'crc32', 'sfv', 'blake3', 'b3')

    $foundFiles = @()
    $maxDiscoveryFileSizeBytes = 10MB
    $discoveryStats = [PSCustomObject]@{
        DirectoryCount = 1
        CandidateCount = 0
        ParsedCount = 0
        RejectedCount = 0
        LastDirectory = $targetDir
    }
    $Global:LastChecksumDiscoveryStats = $discoveryStats
    
    # Strategy 1: Check specific patterns first
    $patterns = @()
    foreach ($ext in $algorithmExtensions) {
        $upperExt = $ext.ToUpperInvariant()
        $patterns += @(
            "$targetName.$ext",
            "$targetName.$upperExt",
            "$targetName.$ext.txt",
            "$targetName.$upperExt.txt",
            "$targetBase.$ext",
            "$targetBase.$upperExt",
            "$targetBase.$ext.txt",
            "$targetBase.$upperExt.txt"
        )
    }
    $patterns += @(
        "$targetName.hash", "$targetName.hash.txt", "$targetName.hashes", "$targetName.hashes.txt",
        "$targetBase.hash", "$targetBase.hash.txt", "$targetBase.hashes", "$targetBase.hashes.txt",
        # Common multi-file checksum files
        "SHA256SUMS", "SHA512SUMS", "SHA1SUMS", "MD5SUMS",
        "CHECKSUM", "CHECKSUMS", "checksum.txt", "checksums.txt", "checksum", "checksums",
        "SHA256SUMS.txt", "SHA512SUMS.txt", "SHA1SUMS.txt", "MD5SUMS.txt",
        "hash.txt", "hashes.txt"
    )

    foreach ($pattern in $patterns) {
        try {
            $searchPath = Join-Path -Path $targetDir -ChildPath $pattern
            $matchedFiles = @(Get-ChildItem -LiteralPath $searchPath -File -Force -ErrorAction SilentlyContinue)
            foreach ($matchedFile in ($matchedFiles | Where-Object { $_.Length -le $maxDiscoveryFileSizeBytes })) {
                if ($matchedFile.FullName -ne $TargetFilePath) {
                    $discoveryStats.CandidateCount++
                    try {
                        $sample = Get-Content -LiteralPath $matchedFile.FullName -Encoding UTF8 -ErrorAction SilentlyContinue
                        if ($sample) {
                            $hasChecksum = $sample | Where-Object {
                                $_ -match "(?<![0-9A-Fa-f])$checksumPattern(?![0-9A-Fa-f])" -or
                                $_ -match "(?<![A-Za-z0-9+/=])$base64Pattern(?![A-Za-z0-9+/=])"
                            }
                            $targetChecksum = Get-ChecksumFromFile -Path $matchedFile.FullName -TargetFilename $targetName
                            if ($hasChecksum -and $targetChecksum) {
                                $discoveryStats.ParsedCount++
                                Write-Verbose ("Found checksum file: {0}" -f $matchedFile.Name)
                                $foundFiles += [PSCustomObject]@{
                                    Path = $matchedFile.FullName
                                    Name = $matchedFile.Name
                                    Size = $matchedFile.Length
                                    Algorithm = Get-AlgorithmFromFilename -Filename $matchedFile.Name
                                }
                            }
                        } else {
                            $discoveryStats.RejectedCount++
                        }
                    } catch { }
                }
            }
        } catch { }
    }

    # Strategy 2: Scan directory for likely checksum files, including metadata files that mention the target.
    try {
        $scanDirs = @($targetDir)
        try {
            $scanDirs += @(Get-ChildItem -LiteralPath $targetDir -Directory -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '(?i)^(checksum|checksums|hash|hashes|verification|verify)$' } |
                Select-Object -ExpandProperty FullName)
        } catch {}
        $scanDirs = @($scanDirs | Where-Object { $_ } | Sort-Object -Unique)
        $discoveryStats.DirectoryCount = $scanDirs.Count

        $allFiles = foreach ($scanDir in $scanDirs) {
            Get-ChildItem -LiteralPath $scanDir -File -Force -ErrorAction SilentlyContinue
        }

        $allFiles = $allFiles |
            Where-Object { 
                $_.FullName -ne $TargetFilePath -and $_.Length -le $maxDiscoveryFileSizeBytes -and
                ($_.Name -match ('(?i){0}' -f [regex]::Escape($targetName)) -or
                 $_.Name -match ('(?i){0}' -f [regex]::Escape($targetBase)) -or
                 $_.Name -match '(?i)^(checksum|checksums|sha\d+|md5|hash)' -or
                 $_.Name -match '(?i)\.(sha1|sha256|sha384|sha512|md5|checksum|hash|hashes)($|\.)' -or
                 $_.Name -match '(?i)(checksum|checksums|hash|hashes)' -or
                 $_.Name -match '(?i)\.(txt|sfv|crc|crc32)$' -or
                 $_.Name -match '(?i)sums$')
            }
        
        foreach ($file in $allFiles) {
            # Skip if already found
            if ($foundFiles | Where-Object { $_.Path -eq $file.FullName }) { continue }
            $discoveryStats.CandidateCount++
            
            try {
                $sample = Get-Content -LiteralPath $file.FullName -Encoding UTF8 -ErrorAction SilentlyContinue
                if ($sample) {
                    $hasChecksum = $sample | Where-Object {
                        $_ -match "(?<![0-9A-Fa-f])$checksumPattern(?![0-9A-Fa-f])" -or
                        $_ -match "(?<![A-Za-z0-9+/=])$base64Pattern(?![A-Za-z0-9+/=])"
                    }
                    $parsedForTarget = $null
                    try { $parsedForTarget = Get-ChecksumFromFile -Path $file.FullName -TargetFilename $targetName } catch {}
                    if ($hasChecksum -and $parsedForTarget -and $parsedForTarget.Checksum) {
                        $discoveryStats.ParsedCount++
                        Write-Verbose ("Found checksum file via directory scan: {0}" -f $file.Name)
                        $foundFiles += [PSCustomObject]@{
                            Path = $file.FullName
                            Name = $file.Name
                            Size = $file.Length
                            Algorithm = Get-AlgorithmFromFilename -Filename $file.Name
                        }
                    } else {
                        $discoveryStats.RejectedCount++
                    }
                }
            } catch { }
        }
    } catch { }

    # Return unique files (in case patterns overlap)
    # Ensure we return a flat array (avoid nesting when a single result exists)
    return @($foundFiles | Sort-Object -Property @{Expression={ if ($_.Name -match ('(?i)^{0}\.' -f [regex]::Escape($targetName))) { 0 } else { 1 } }}, Path -Unique | Select-Object -First 5)
}

function Get-AlgorithmFromFilename {
    param([Parameter(Mandatory=$true)][string] $Filename)

    $lower = $Filename.ToLower()
    if ($lower -match '\.(sfv|crc32|crc)(\.txt)?$') { return 'CRC32' }
    if ($lower -match '(blake3|\.b3(?:\.|$))') { return 'BLAKE3' }
    if ($lower -match 'sha3[-_]?256') { return 'SHA3-256' }
    if ($lower -match 'sha3[-_]?512') { return 'SHA3-512' }

    # Check file extension first
    if ($lower -match '\.sha512(\.txt)?$|sha512sums') { return 'SHA512' }
    if ($lower -match '\.sha384(\.txt)?$') { return 'SHA384' }
    if ($lower -match '\.sha256(\.txt)?$|sha256sums') { return 'SHA256' }
    if ($lower -match '\.sha1(\.txt)?$|sha1sums') { return 'SHA1' }
    if ($lower -match '\.md5(\.txt)?$|md5sums') { return 'MD5' }

    # Check filename contains algorithm name
    if ($lower -match 'sha512') { return 'SHA512' }
    if ($lower -match 'sha384') { return 'SHA384' }
    if ($lower -match 'sha256') { return 'SHA256' }
    if ($lower -match 'sha1') { return 'SHA1' }
    if ($lower -match 'md5') { return 'MD5' }

    return $null
}

function Get-ChecksumFromFile {
    param(
        [Parameter(Mandatory=$true)][string] $Path,
        [Parameter(Mandatory=$false)][string] $TargetFilename,
        [string] $Algorithm
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { Throw "Checksum file not found: $Path" }

    try {
        # Attempt to read with UTF-8 encoding (most common for checksum files)
        # This handles BOM and non-ASCII characters properly
        $lines = Get-Content -LiteralPath $Path -Encoding UTF8 -ErrorAction Stop
        if (-not $lines -or $lines.Count -eq 0) {
            # Fallback: try default encoding if UTF-8 produces no lines
            $lines = Get-Content -LiteralPath $Path -ErrorAction Stop
        }
    } catch {
        Throw "Unable to read checksum file: $($_.Exception.Message)"
    }

    $hint = if ($Algorithm) { $Algorithm } else { Get-AlgorithmFromFilename -Filename (Split-Path -Leaf $Path) }
    return ConvertFrom-ChecksumText -Text ($lines -join "`n") -TargetFilename $TargetFilename -Algorithm $Algorithm -DefaultAlgorithm $hint
}

function ConvertFrom-ChecksumText {
    param([Parameter(Mandatory=$true)][AllowEmptyString()][string] $Text,
          [string] $TargetFilename, [string] $Algorithm, [string] $DefaultAlgorithm)
    if (-not $DefaultAlgorithm -and $Algorithm) { $DefaultAlgorithm = $Algorithm }
    $lines = $Text -split '\r?\n'
    $candidates = @()
    $lineNum = 0
    $checksumPattern = Get-ChecksumRegexPattern
    $base64Pattern = Get-ChecksumBase64RegexPattern
    $algorithmPattern = 'CRC-?32|CRC|BLAKE3|B3|MD5|SHA-?1|SHA3-?256|SHA3-?512|SHA-?256|SHA2-?256|SHA-?384|SHA2-?384|SHA-?512|SHA2-?512'
    $metadataFileName = $null
    $metadataAlgorithm = $null

    foreach ($raw in $lines) {
        $lineNum++
        if (-not $raw) { continue }
        $line = $raw.Trim()
        $gnuEscapedLine = $false
        if ($line.StartsWith('\')) {
            $gnuEscapedLine = $true
            $line = $line.Substring(1)
        }

        # Skip comment lines commonly found in distros (lines starting with #, ; or //)
        if ($line -match '^\s*(#|;|//)') { continue }

        # Metadata-save style: remember nearby "File:" / "Algorithm:" labels for the next checksum line.
        if ($line -match '(?i)^\s*(?:File|Filename|Path)\s*[:=]\s*(?<file>.+?)\s*$') {
            $metadataFileName = $matches['file'].Trim()
            continue
        }

        if ($line -match ('(?i)^\s*Algorithm\s*[:=]\s*(?<alg>{0})\b' -f $algorithmPattern)) {
            $metadataAlgorithm = ConvertTo-CanonicalChecksumAlgorithm -Algorithm $matches['alg']
            $candidates += [PSCustomObject]@{ Checksum = $null; Algorithm = $metadataAlgorithm; Line = $line; LineNumber = $lineNum; FilenameMatch = $false; Preferred = $false }
            continue
        }

        # 1) Patterns like: "SHA256 (filename) = <hex>" or "SHA256 filename = <hex>" or "SHA-1 (...) = <hex>"
        if ($line -match ('(?i)^\s*(?<alg>{0})\b[^\r\n]*?(?:=|:)\s*(?<digest>{1}|{2})(?![A-Za-z0-9+/=])' -f $algorithmPattern, $checksumPattern, $base64Pattern)) {
            $digest = $matches['digest']
            $hex = if (Test-ChecksumValue -Checksum $digest) { $digest.ToLower() } else { ConvertTo-HexChecksumFromBase64 -Base64 $digest }
            if (-not $hex) { continue }
            $alg = ConvertTo-CanonicalChecksumAlgorithm -Algorithm $matches['alg']
            if (-not $alg) { $alg = Get-ChecksumAlgorithmFromLength -Checksum $hex }
            if ($hex.Length -ne (Get-ChecksumDigestLength $alg)) {
                $decoded = ConvertTo-HexChecksumFromBase64 -Base64 $digest
                if ($decoded) { $hex = $decoded }
            }
            $fileMention = $false
            $entryFilename = $null
            # Extract filename from parentheses if present: "SHA512 (filename) = hash"
            # Match the last set of parentheses before the equals/colon sign
            if ($line -match '\((.+)\)\s*(?:=|:)') {
                $entryFilename = $matches[1]
                if ($TargetFilename) { $fileMention = Test-ChecksumFilenameMatch -CandidateName $entryFilename -TargetFilename $TargetFilename }
            } elseif ($line -match ('(?i)^(?:{0})\s+(?<file>.+?)\s*=' -f $algorithmPattern)) {
                $entryFilename = $matches['file']
                if ($TargetFilename) { $fileMention = Test-ChecksumFilenameMatch -CandidateName $entryFilename -TargetFilename $TargetFilename }
            }
            $candidates += [PSCustomObject]@{ Checksum = $hex; Algorithm = $alg; Line = $line; LineNumber = $lineNum; FilenameMatch = $fileMention; Preferred = $true; Filename = $entryFilename }
            continue
        }

        # SFV lists the filename first, followed by an IEEE CRC32 digest.
        if ($line -match '^(?<fname>.+?)\s+(?<digest>[0-9A-Fa-f]{8})$') {
            $fname = $matches['fname']
            $hex = $matches['digest'].ToLowerInvariant()
            $fileMention = $TargetFilename -and (Test-ChecksumFilenameMatch $fname $TargetFilename -Exact)
            $candidates += [PSCustomObject]@{ Checksum = $hex; Algorithm = 'CRC32'; Line = $line; LineNumber = $lineNum; FilenameMatch = $fileMention; Preferred = $fileMention; Filename = $fname }
            continue
        }

        # 2) Common unix "sha256sum" style: "<hex>  filename" or "<hex> *filename"
        if ($line -match ('(?i)^\s*(?<digest>{0}|{1})\s+\*?(?<fname>.+?)\s*$' -f $checksumPattern, $base64Pattern)) {
            $digest = $matches['digest']
            $hex = if (Test-ChecksumValue -Checksum $digest) { $digest.ToLower() } else { ConvertTo-HexChecksumFromBase64 -Base64 $digest }
            if (-not $hex) { continue }
            $fname = $matches['fname'].Trim("`"", "'")
            if ($gnuEscapedLine) { $fname = ConvertFrom-GnuEscapedFilename -Filename $fname }
            $alg = if ($DefaultAlgorithm -and (Get-ChecksumDigestLength $DefaultAlgorithm) -eq $hex.Length) { $DefaultAlgorithm } else { Get-ChecksumAlgorithmFromLength -Checksum $hex }
            $fileMention = $false
            # For extracted filename, check exact match with path normalization
            if ($TargetFilename) {
                $fileMention = Test-ChecksumFilenameMatch -CandidateName $fname -TargetFilename $TargetFilename
            }
            $candidates += [PSCustomObject]@{ Checksum = $hex; Algorithm = $alg; Line = $line; LineNumber = $lineNum; FilenameMatch = $fileMention; Preferred = $fileMention; Filename = $fname }
            continue
        }

        # 3) Labeled single-value lines: "Checksum: <hex>", "Hash = <hex>", or PowerShell-style "Hash : <hex>"
        if ($line -match ('(?i)^\s*(?:Checksum|Hash|Digest)\s*[:=]\s*(?<digest>{0}|{1})(?![A-Za-z0-9+/=])' -f $checksumPattern, $base64Pattern)) {
            $digest = $matches['digest']
            $hex = if (Test-ChecksumValue -Checksum $digest) { $digest.ToLower() } else { ConvertTo-HexChecksumFromBase64 -Base64 $digest }
            if (-not $hex) { continue }
            $alg = if ($metadataAlgorithm) { $metadataAlgorithm } elseif ($DefaultAlgorithm) { $DefaultAlgorithm } else { Get-ChecksumAlgorithmFromLength -Checksum $hex }
            $fileMention = ($TargetFilename -and (
                (Test-ChecksumLineReferencesTarget -Line $line -TargetFilename $TargetFilename) -or
                ($metadataFileName -and (Test-ChecksumFilenameMatch -CandidateName $metadataFileName -TargetFilename $TargetFilename))
            ))
            $candidates += [PSCustomObject]@{ Checksum = $hex; Algorithm = $alg; Line = $line; LineNumber = $lineNum; FilenameMatch = $fileMention; Preferred = $true; Filename = $metadataFileName }
            continue
        }

        # 4.5) Single digest dump (just a raw checksum without filename, common in .md5 or .sha256 files)
        if ($line -match ('^\s*(?<digest>{0}|{1})\s*$' -f $checksumPattern, $base64Pattern)) {
            $digest = $matches['digest']
            $hex = if (Test-ChecksumValue -Checksum $digest) { $digest.ToLower() } else { ConvertTo-HexChecksumFromBase64 -Base64 $digest }
            if (-not $hex) { continue }
            $alg = if ($DefaultAlgorithm -and (Get-ChecksumDigestLength $DefaultAlgorithm) -eq $hex.Length) { $DefaultAlgorithm } else { Get-ChecksumAlgorithmFromLength -Checksum $hex }
            $candidates += [PSCustomObject]@{ Checksum = $hex; Algorithm = $alg; Line = $line; LineNumber = $lineNum; FilenameMatch = $false; Preferred = $true }
            continue
        }

        # 5) Generic: find any hex runs (32..128) on the line and treat them as potential checksums
        if ($line -match '(?i)^Algorithm\s*[:=]' -or $line -match '(?i)^(?:MD\d+|SHA[\w-]+|BLAKE[\w-]+)\b.*(?:=|:)') {
            throw "Unsupported algorithm label on line $lineNum."
        }
        $hexMatches = [regex]::Matches($line, "(?<![0-9A-Fa-f])$checksumPattern(?![0-9A-Fa-f])") | ForEach-Object { $_.Value }
        if ($hexMatches -and $hexMatches.Count -gt 0) {
            foreach ($hm in $hexMatches) {
                if ($hm.Length -eq 8) { continue }
                $hex = $hm.ToLower()
                $alg = Get-ChecksumAlgorithmFromLength -Checksum $hex
                $fileMention = $false
                if ($TargetFilename -and (Test-ChecksumLineReferencesTarget -Line $line -TargetFilename $TargetFilename)) { $fileMention = $true }
                # prefer lines that also contain the word 'checksum' or an algorithm name
                $preferred = ($line -match '(?i)checksum') -or ($line -match '(?i)\b(md5|sha1|sha256|sha384|sha512)\b')
                $candidates += [PSCustomObject]@{ Checksum = $hex; Algorithm = $alg; Line = $line; LineNumber = $lineNum; FilenameMatch = $fileMention; Preferred = $preferred }
            }
        }
    }

    $candidates = @($candidates | Where-Object { $_.Checksum })
    if ($TargetFilename) {
        foreach ($candidate in $candidates) {
            if ($candidate.Filename) { $candidate.FilenameMatch = Test-ChecksumFilenameMatch -CandidateName $candidate.Filename -TargetFilename $TargetFilename -Exact }
        }
        $namedMatches = @($candidates | Where-Object { $_.FilenameMatch })
        if ($namedMatches.Count -gt 0) { $candidates = $namedMatches }
        elseif (@($candidates | Where-Object { $_.Filename }).Count -gt 0) { return $null }
    }
    if ($Algorithm) {
        $canonical = ConvertTo-CanonicalChecksumAlgorithm -Algorithm $Algorithm
        $candidates = @($candidates | Where-Object { $_.Algorithm -eq $canonical })
    }
    if ($candidates.Count -eq 0) { return $null }
    foreach ($candidate in $candidates) {
        if ($candidate.Checksum.Length -ne (Get-ChecksumDigestLength -Algorithm $candidate.Algorithm)) {
            throw "Algorithm label and digest length disagree on line $($candidate.LineNumber)."
        }
    }
    foreach ($group in ($candidates | Group-Object Algorithm)) {
        if (@($group.Group.Checksum | Select-Object -Unique).Count -gt 1) {
            throw "Conflicting $($group.Name) checksums. Select an unambiguous checksum source."
        }
    }

    # Scoring: highest weight to FilenameMatch + Preferred label, then explicit Preferred, then algorithm known, then length, then earliest line number.
    $scored = $candidates | ForEach-Object {
        $score = 0
        if ($_.FilenameMatch) { $score += 1000 }
        if ($_.Preferred) { $score += 500 }
        if ($_.Algorithm) { $score += 50 }
        if ($_.Checksum) { $score += $_.Checksum.Length } else { $score += 0 }
        # penalize null checksum candidates (algorithm-only hints)
        if (-not $_.Checksum) { $score -= 100 }
        [PSCustomObject]@{ Candidate = $_; Score = $score }
    }

    $best = $scored | Sort-Object -Property @{Expression='Score';Descending=$true},@{Expression={$_.Candidate.LineNumber};Descending=$false} | Select-Object -First 1

    if ($best -and $best.Candidate.Checksum) {
        # Check for ambiguous matches (multiple filename matches with same score)
        if ($TargetFilename) {
            $filenameMatches = $candidates | Where-Object { $_.FilenameMatch -and $_.Checksum }
            if ($filenameMatches.Count -gt 1) {
                Write-LogMessage -Message ("Multiple matches found for '{0}' in checksum file. Using line {1}" -f $TargetFilename, $best.Candidate.LineNumber) -Level WARN
                Write-Verbose ("WARNING: Found {0} potential matches for '{1}'. Selected line {2}" -f $filenameMatches.Count, $TargetFilename, $best.Candidate.LineNumber)
            }
        }
        Write-LogMessage -Message ("Selected checksum from line {0}: {1}" -f $best.Candidate.LineNumber, $best.Candidate.Line) -Level DEBUG
        # ensure Algorithm is set if possible
        if (-not $best.Candidate.Algorithm) { $best.Candidate.Algorithm = Get-ChecksumAlgorithmFromLength -Checksum $best.Candidate.Checksum }
        return $best.Candidate
    }

    # If best candidate had no checksum but provided algorithm hints and there exists any checksum candidate matching that algorithm, pick that.
    if ($best -and -not $best.Candidate.Checksum -and $best.Candidate.Algorithm) {
        $matchByAlg = $candidates | Where-Object { $_.Checksum -and (Get-ChecksumAlgorithmFromLength -Checksum $_.Checksum) -eq $best.Candidate.Algorithm } | Select-Object -First 1
        if ($matchByAlg) { return $matchByAlg }
    }

    # Fallback: return the longest checksum candidate
    $fallback = ($candidates | Where-Object { $_.Checksum } | Sort-Object @{Expression = { $_.Checksum.Length }; Descending = $true }, @{Expression = { $_.LineNumber }; Descending = $false} | Select-Object -First 1)
    if ($fallback) { if (-not $fallback.Algorithm) { $fallback.Algorithm = Get-ChecksumAlgorithmFromLength -Checksum $fallback.Checksum }; return $fallback }

    return $null
}


function Test-FileChecksum {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
        [string] $Path,
        
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $ExpectedChecksumOrFile,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('MD5','SHA1','SHA256','SHA384','SHA512','SHA3-256','SHA3-512','CRC32','BLAKE3')]
        [string] $Algorithm,
        
        [Parameter(Mandatory=$false)]
        [switch] $AutoDetectAlgorithm,
        
        [Parameter(Mandatory=$false)]
        [switch] $ShowProgress,
        
        [switch] $ShowStatus,

        [Parameter(Mandatory=$false)]
        [switch] $SaveOnMismatch,
        
        [Parameter(Mandatory=$false)]
        [string] $OutputPath
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { Throw "Target file not found: $Path" }
    $Path = (Get-Item -LiteralPath $Path -ErrorAction Stop).FullName

    $expectedChecksum = $null
    $derivedAlgorithm = $null
    $expectedSource = "Pasted input"

    # If the provided ExpectedChecksumOrFile is a path to a file, attempt to parse it; otherwise treat as literal/pasted
    if (Test-Path -LiteralPath $ExpectedChecksumOrFile -PathType Leaf -ErrorAction SilentlyContinue) {
        Write-LogMessage -Message ("Parsing checksum from file: {0}" -f $ExpectedChecksumOrFile) -Level INFO
        try {
            $parsed = Get-ChecksumFromFile -Path $ExpectedChecksumOrFile -TargetFilename (Split-Path -Leaf $Path) -Algorithm $Algorithm
        } catch {
            Write-LogMessage -Message ("Checksum file parse failed: {0}" -f $_.Exception.Message) -Level WARN
            Throw "Could not parse checksum file: $($_.Exception.Message)"
        }

        if (-not $parsed) {
            Write-LogMessage -Message ("No valid checksum found for '{0}' in file: {1}" -f (Split-Path -Leaf $Path), $ExpectedChecksumOrFile) -Level ERROR
            Throw "Could not find a checksum for '$(Split-Path -Leaf $Path)' in the checksum file. Ensure the filename matches exactly and the file format is supported (BSD-style or Unix sha*sum format)."
        }
        if (-not $parsed.Checksum) {
            # If parser only returned algorithm hint, keep algorithm hint and let algorithm detection handle it
            $derivedAlgorithm = $parsed.Algorithm
        } else {
            $expectedChecksum = ConvertTo-NormalizedChecksum -Raw $parsed.Checksum
            if (-not $expectedChecksum) { Throw "Extracted checksum is not valid hex." }
            $derivedAlgorithm = $parsed.Algorithm
            $expectedSource = "File: {0}, line {1}" -f (Split-Path -Leaf $ExpectedChecksumOrFile), $parsed.LineNumber
        }
    } else {
        # Pasted value or user-typed value: normalize and treat as checksum
        $parsedInput = ConvertFrom-ChecksumText -Text $ExpectedChecksumOrFile -TargetFilename (Split-Path -Leaf $Path) -Algorithm $Algorithm
        $norm = if ($parsedInput) { $derivedAlgorithm = $parsedInput.Algorithm; $parsedInput.Checksum } else { $null }
        if (-not $norm -and $ExpectedChecksumOrFile.Trim() -match '^[0-9A-Fa-f\s:-]+$') { $norm = ConvertTo-NormalizedChecksum -Raw $ExpectedChecksumOrFile -Algorithm $Algorithm }
        if (-not $norm) {
            Write-LogMessage -Message ("Invalid checksum format provided: {0}" -f $ExpectedChecksumOrFile.Substring(0, [Math]::Min(50, $ExpectedChecksumOrFile.Length))) -Level ERROR
            Throw 'No matching checksum was found. Supply a digest, a labeled checksum, or a manifest entry matching the selected file. BLAKE3 and SHA3 need a label, filename hint, or an explicit algorithm.'
        }
        $expectedChecksum = $norm
    }

    # Determine algorithm to use (precedence):
    #   1) explicit -Algorithm parameter
    #   2) explicit algorithm label parsed from the source
    #   3) length-based detection for unlabeled digests (legacy MD5/SHA families)
    #   4) if AutoDetectAlgorithm requested but detection fails -> error
    #   5) otherwise require -Algorithm
    $chosenAlgorithm = $null

    if ($Algorithm) {
        $chosenAlgorithm = $Algorithm
    } else {
        if ($derivedAlgorithm) { $chosenAlgorithm = $derivedAlgorithm }
        if (-not $chosenAlgorithm -and $expectedChecksum) {
            $lenAlg = Get-ChecksumAlgorithmFromLength -Checksum $expectedChecksum
            if ($lenAlg) { $chosenAlgorithm = $lenAlg }
        }

        if (-not $chosenAlgorithm -and $derivedAlgorithm) {
            # normalize derivedAlgorithm label if present
            $da = $derivedAlgorithm.ToUpper() -replace 'SHA-1','SHA1'
            switch ($da) {
                'SHA1'  { $da = 'SHA1' }
                'SHA256'{ $da = 'SHA256' }
                'SHA384'{ $da = 'SHA384' }
                'SHA512'{ $da = 'SHA512' }
                'MD5'   { $da = 'MD5' }
            }
            if ($da) { $chosenAlgorithm = $da }
        }

        if (-not $chosenAlgorithm) {
            if ($AutoDetectAlgorithm) {
                Throw "Unable to detect algorithm from checksum length or file hints. Please specify -Algorithm."
            } else {
                Throw "Algorithm must be specified (use -Algorithm) or supply an ExpectedChecksumOrFile value that indicates algorithm length."
            }
        }
    }

    # Compute checksum of target file
    if ($ShowStatus) { Write-Host ("  Algorithm: {0}" -f $chosenAlgorithm) -ForegroundColor DarkGray }
    try {
        $calc = Get-FileChecksumEx -Path $Path -Algorithm $chosenAlgorithm -ShowProgress:$ShowProgress
        
        if (-not $calc) {
            Write-LogMessage -Message ("Checksum computation returned null for {0} with algorithm {1}" -f $Path, $chosenAlgorithm) -Level ERROR
            Throw "Failed to compute checksum - file may be inaccessible"
        }
    } catch {
        Write-LogMessage -Message ("Checksum computation failed for {0} with algorithm {1}: {2}" -f $Path, $chosenAlgorithm, $_.Exception.Message) -Level ERROR
        Throw "Failed to compute checksum: $($_.Exception.Message)"
    }

    # Normalize both for reliable comparison
    if ($expectedChecksum) { $expectedChecksum = ConvertTo-NormalizedChecksum -Raw $expectedChecksum -Algorithm $chosenAlgorithm }
    $calculatedChecksum = ConvertTo-NormalizedChecksum -Raw $calc.Checksum -Algorithm $chosenAlgorithm

    $match = $false
    if ($expectedChecksum -and $calculatedChecksum) { $match = ($calculatedChecksum -ieq $expectedChecksum) }

    $result = [PSCustomObject]@{
        Path             = $calc.Path
        Algorithm        = $chosenAlgorithm
        ExpectedChecksum = $expectedChecksum
        Calculated       = $calculatedChecksum
        Length           = $calc.Length
        Elapsed          = $calc.Elapsed
        Match            = $match
        ExpectedSource   = $expectedSource
    }

    if (-not $match -and $SaveOnMismatch) {
        if (-not $OutputPath) {
            $dir = Split-Path -Parent $Path
            $base = [IO.Path]::GetFileName($Path)
            $suffix = if ($Global:Settings.IncludeUsernameInMetadata) { ".$($env:USERNAME)" } else { "" }
            $OutputPath = Join-Path -Path $dir -ChildPath ("{0}.{1}{2}.calculated.txt" -f $base, $chosenAlgorithm, $suffix)
        }
        try {
            if ([IO.Path]::GetFullPath($OutputPath) -eq [IO.Path]::GetFullPath($Path)) { throw 'Cannot overwrite the target file.' }
            Write-ChecksumFile -Path $OutputPath -Content $calculatedChecksum
            $result | Add-Member -NotePropertyName SavedChecksumPath -NotePropertyValue $OutputPath -Force
            Write-LogMessage -Message ("Saved checksum to {0} due to mismatch" -f $OutputPath) -Level INFO
        } catch {
            Write-LogMessage -Message ("Failed to save checksum on mismatch: {0}" -f $_.Exception.Message) -Level WARN
            throw
        }
    }

    Write-LogMessage -Message ("Verification for {0}: match={1} (alg={2})" -f $Path, $result.Match, $chosenAlgorithm) -Level INFO
    return $result
}

function Write-ChecksumFile {
    param([Parameter(Mandatory=$true)][string] $Path, [Parameter(Mandatory=$true)][string] $Content)
    $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Content)
        $stream.Write($bytes, 0, $bytes.Length)
    } finally { $stream.Dispose() }
}

function Save-ChecksumQuick { param([string] $TargetPath,[string] $Checksum)
    try { Write-ChecksumFile -Path $TargetPath -Content $Checksum; return $true } catch { Write-LogMessage -Message ("Quick save failed for {0}: {1}" -f $TargetPath,$_.Exception.Message) -Level WARN; return $false }
}

function Save-ChecksumWithMetadata { param([string] $TargetPath,[string] $Checksum,[string] $Algorithm,[string] $FilePath)
    $now = (Get-Date).ToUniversalTime().ToString("u")
    $user = if ($Global:Settings.IncludeUsernameInMetadata) { $env:USERNAME } else { "[Not recorded - Privacy setting]" }
    $displayPath = if ($Global:Settings.IncludeUsernameInMetadata) { 
        $FilePath 
    } else { 
        # Privacy mode: only show filename, not full path
        Split-Path -Leaf $FilePath
    }
    $content = @"
File:      $displayPath
Algorithm: $Algorithm
Checksum:  $Checksum

CreatedBy: $user
CreatedOn: $now
"@
    try { Write-ChecksumFile -Path $TargetPath -Content $content; return $true } catch { Write-LogMessage -Message ("Metadata save failed for {0}: {1}" -f $TargetPath,$_.Exception.Message) -Level WARN; return $false }
}

function Test-FileChecksums {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string[]] $Path,
          [Parameter(Mandatory=$true)][string] $ChecksumFile,
          [string] $Algorithm, [switch] $ShowProgress, [switch] $ShowStatus)
    $index = 0
    foreach ($file in $Path) {
        $index++
        if ($ShowStatus) {
            Write-Host ''
            Write-Host ("[{0}/{1}] Verifying {2}" -f $index, $Path.Count, (Split-Path -Leaf $file)) -ForegroundColor Cyan
            Write-Host ("  Path:      {0}" -f $file) -ForegroundColor DarkGray
            try { Write-Host ("  Size:      {0}" -f (Format-FileSize (Get-Item -LiteralPath $file -ErrorAction Stop).Length)) -ForegroundColor DarkGray }
            catch { Write-Host '  Size:      Unavailable' -ForegroundColor DarkGray }
        }
        $parameters = @{ Path = $file; ExpectedChecksumOrFile = $ChecksumFile; ShowProgress = $ShowProgress; ShowStatus = $ShowStatus }
        if ($Algorithm) { $parameters.Algorithm = $Algorithm }
        try { $result = Test-FileChecksum @parameters }
        catch { $result = [PSCustomObject]@{ Path = $file; Match = $false; Error = $_.Exception.Message } }
        if ($ShowStatus) {
            if ($result.Error) { Write-Host ("  ERROR: {0}" -f $result.Error) -ForegroundColor Red }
            else {
                $status = if ($result.Match) { 'OK' } else { 'MISMATCH' }
                $color = if ($result.Match) { 'Green' } else { 'Red' }
                Write-Host ("  {0}  {1} | {2:N2} seconds" -f $status, $result.Algorithm, $result.Elapsed.TotalSeconds) -ForegroundColor $color
                if (-not $result.Match) {
                    Write-Host ("  Expected:  {0}" -f $result.ExpectedChecksum) -ForegroundColor Yellow
                    Write-Host ("  Calculated: {0}" -f $result.Calculated) -ForegroundColor Yellow
                }
            }
        }
        $result
    }
}

function Export-ChecksumManifest {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][array] $Results,
          [Parameter(Mandatory=$true)][string] $OutputPath,
          [ValidateSet('Auto','GNU','SFV','Tagged')][string] $Format = 'Auto')
    if (@($Results.Algorithm | Select-Object -Unique).Count -ne 1) { throw 'GNU manifests require one algorithm per manifest.' }
    $algorithm = $Results[0].Algorithm
    if ($Format -eq 'Auto') {
        $Format = if ($algorithm -eq 'CRC32') { 'SFV' } elseif ($algorithm -eq 'BLAKE3' -or $algorithm -like 'SHA3-*') { 'Tagged' } else { 'GNU' }
    }
    if ($Format -eq 'SFV' -and $algorithm -ne 'CRC32') { throw 'SFV requires CRC32 results.' }
    if ($Format -eq 'GNU' -and ($algorithm -eq 'CRC32' -or $algorithm -eq 'BLAKE3' -or $algorithm -like 'SHA3-*')) { throw 'Use Auto, SFV, or Tagged to preserve this algorithm.' }
    $names = @($Results | ForEach-Object { [IO.Path]::GetFileName($_.Path) })
    if (@($names | Select-Object -Unique).Count -ne $names.Count) { throw 'Duplicate filenames cannot be exported into one basename manifest.' }
    $lines = foreach ($result in $Results) {
        if ($result.Checksum.Length -ne (Get-ChecksumDigestLength -Algorithm $result.Algorithm) -or -not (Test-ChecksumValue $result.Checksum)) { throw 'Invalid checksum result.' }
        $name = [IO.Path]::GetFileName($result.Path)
        if (-not $name) { throw 'A filename is required for each result.' }
        if ($Format -ne 'GNU' -and $name -match '[\r\n]') { throw 'SFV and tagged filenames cannot contain newlines.' }
        if ($Format -eq 'SFV') {
            if ($name -match '^[;#]' -or $name -ne $name.Trim()) { throw 'This filename cannot be represented safely in SFV. Use Tagged instead.' }
            '{0} {1}' -f $name, $result.Checksum.ToUpperInvariant(); continue
        }
        if ($Format -eq 'Tagged') { '{0} ({1}) = {2}' -f $algorithm, $name, $result.Checksum; continue }
        $escaped = $name.Contains('\') -or $name.Contains("`n") -or $name.Contains("`r")
        $name = $name.Replace('\', '\\').Replace("`n", '\n').Replace("`r", '\r')
        $prefix = if ($escaped) { '\' } else { '' }
        '{0}{1} *{2}' -f $prefix, $result.Checksum, $name
    }
    Write-ChecksumFile -Path $OutputPath -Content (($lines -join "`n") + "`n")
}

function ConvertTo-ChecksumReleaseInfo {
    param([Parameter(Mandatory=$true)] $Release)
    if ($Release.draft -or $Release.prerelease -or $Release.tag_name -cnotmatch '^[Vv]?\d+\.\d+\.\d+$') { throw 'The release is not a supported stable version.' }
    $version = [version]($Release.tag_name -replace '^[Vv]', '')
    $assets = @($Release.assets | Where-Object { $_.name -ceq 'Checksum-Verify.ps1' -and $_.state -eq 'uploaded' })
    if ($assets.Count -ne 1) { throw 'The release must contain exactly one Checksum-Verify.ps1 asset.' }
    $asset = $assets[0]
    if ($asset.digest -notmatch '^sha256:[a-fA-F0-9]{64}$') { throw 'The release has no SHA256 asset digest. Download manually from https://github.com/Dantdmnl/Checksum-Verify/releases.' }
    if ([long]$asset.size -le 0 -or [long]$asset.size -gt 5MB) { throw 'Unexpected release asset size.' }
    $url = "https://github.com/Dantdmnl/Checksum-Verify/releases/download/$($Release.tag_name)/Checksum-Verify.ps1"
    if ($asset.browser_download_url -cne $url) { throw 'Unexpected release download URL.' }
    [PSCustomObject]@{
        Version = $version.ToString(); Tag = [string]$Release.tag_name
        DownloadUrl = $url; Digest = [string]$asset.digest; Size = [long]$asset.size
        ReleaseUrl = "https://github.com/Dantdmnl/Checksum-Verify/releases/tag/$($Release.tag_name)"
    }
}

function Get-ChecksumRelease {
    $previousProtocol = [Net.ServicePointManager]::SecurityProtocol
    try {
        [Net.ServicePointManager]::SecurityProtocol = $previousProtocol -bor [Net.SecurityProtocolType]::Tls12
        $release = Invoke-RestMethod -Uri 'https://api.github.com/repos/Dantdmnl/Checksum-Verify/releases/latest' `
            -Headers @{ Accept = 'application/vnd.github+json'; 'User-Agent' = 'Checksum-Verify-Updater' } -TimeoutSec 20 -ErrorAction Stop
        ConvertTo-ChecksumReleaseInfo $release
    } finally { [Net.ServicePointManager]::SecurityProtocol = $previousProtocol }
}

function Get-ChecksumScriptVersion {
    param([Parameter(Mandatory=$true)][string] $Path)
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$errors)
    if ($errors.Count -gt 0) { throw 'The downloaded script failed parser validation.' }
    $assignments = @($ast.EndBlock.Statements | Where-Object {
        $_ -is [Management.Automation.Language.AssignmentStatementAst] -and
        $_.Left -is [Management.Automation.Language.VariableExpressionAst] -and $_.Left.VariablePath.UserPath -eq 'ScriptVersion'
    })
    if ($assignments.Count -ne 1) { throw 'The script must have a unique version assignment.' }
    $expression = $assignments[0].Right.Expression
    if ($expression -isnot [Management.Automation.Language.StringConstantExpressionAst] -or $expression.Value -notmatch '^\d+\.\d+\.\d+$') { throw 'The script version must be a literal semantic version.' }
    $functions = @($ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.FunctionDefinitionAst] } | ForEach-Object Name)
    foreach ($required in @('Get-FileChecksumEx','Test-FileChecksum','Show-MainMenuAndReadKey')) {
        if ($required -notin $functions) { throw 'The download is not a complete Checksum-Verify script.' }
    }
    return [version]$expression.Value
}

function Install-ChecksumUpdate {
    param([Parameter(Mandatory=$true)] $Release, [Parameter(Mandatory=$true)][string] $CurrentScriptPath)
    $checked = ConvertTo-ChecksumReleaseInfo ([PSCustomObject]@{
        tag_name = $Release.Tag; draft = $false; prerelease = $false
        assets = @([PSCustomObject]@{ name = 'Checksum-Verify.ps1'; state = 'uploaded'; digest = $Release.Digest; size = $Release.Size; browser_download_url = $Release.DownloadUrl })
    })
    $current = Get-Item -LiteralPath $CurrentScriptPath -ErrorAction Stop
    if ($current.PSIsContainer -or $current.Extension -ne '.ps1') { throw 'The current script must be a .ps1 file.' }
    if ([version]$checked.Version -le (Get-ChecksumScriptVersion $current.FullName)) { throw 'This version is already installed or the local script is newer.' }
    $originalHash = (Get-FileHash -LiteralPath $current.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
    $id = [guid]::NewGuid().ToString('N')
    $stagedPath = Join-Path $current.DirectoryName ('.Checksum-Verify.' + $id + '.update.ps1')
    $backupPath = $current.FullName + '.' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.' + $id + '.bak'
    $previousProtocol = [Net.ServicePointManager]::SecurityProtocol
    try {
        [Net.ServicePointManager]::SecurityProtocol = $previousProtocol -bor [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $checked.DownloadUrl -UseBasicParsing -TimeoutSec 60 -OutFile $stagedPath -ErrorAction Stop | Out-Null
        if ((Get-Item -LiteralPath $stagedPath).Length -ne $checked.Size) { throw 'Downloaded size does not match the release asset.' }
        if ('sha256:' + (Get-FileHash -LiteralPath $stagedPath -Algorithm SHA256).Hash -ine $checked.Digest) { throw 'Downloaded SHA256 does not match the release asset.' }
        if ((Get-ChecksumScriptVersion $stagedPath) -ne [version]$checked.Version) { throw 'Script version does not match the release tag.' }
        if ((Get-FileHash -LiteralPath $current.FullName -Algorithm SHA256).Hash -ne $originalHash) { throw 'The local script changed during the download. Update cancelled.' }
        [IO.File]::Replace($stagedPath, $current.FullName, $backupPath)
        [PSCustomObject]@{ Version = $checked.Version; BackupPath = $backupPath }
    } finally {
        [Net.ServicePointManager]::SecurityProtocol = $previousProtocol
        if ([IO.File]::Exists($stagedPath)) { [IO.File]::Delete($stagedPath) }
    }
}

function Update-ChecksumTool {
    try {
        Write-StatusMessage 'Checking GitHub for a stable release...'
        $release = Get-ChecksumRelease
        if ([version]$release.Version -le [version]$ScriptVersion) { Write-Host "Already current: $ScriptVersion (latest: $($release.Version))." -ForegroundColor Green; return }
        Write-Host "Available: $($release.Version) | Running: $ScriptVersion"
        Write-Host "Release notes: $($release.ReleaseUrl)"
        Write-Host 'Installation replaces this script, including local edits, and keeps a backup. Restart afterward.' -ForegroundColor Yellow
        if ((Read-Host 'Install update? [y/N]').Trim() -ine 'y') { return }
        $installed = Install-ChecksumUpdate -Release $release -CurrentScriptPath $script:ApplicationPath
        Write-Host "Installed $($installed.Version). Restart to use it. Backup: $($installed.BackupPath)" -ForegroundColor Green
    } catch { Write-Host "Update failed: $($_.Exception.Message)" -ForegroundColor Yellow }
}
#endregion

#region View log entries
function Show-RecentLogEntries {
    param([int] $Count = 50)
    
    if (-not (Test-Path -LiteralPath $Global:LogFile)) {
        Write-Host "No log file found." -ForegroundColor Yellow
        Start-Sleep -Milliseconds 1000
        return
    }
    
    try {
        $lines = Get-Content -LiteralPath $Global:LogFile -Tail $Count -ErrorAction Stop
        
        Clear-Host
        Write-Host ("Recent Log Entries (last {0} lines)" -f $Count) -ForegroundColor Cyan
        Write-Host ("Log file: {0}" -f $Global:LogFile) -ForegroundColor DarkGray
        Write-Host ""
        
        foreach ($line in $lines) {
            try {
                $entry = $line | ConvertFrom-Json -ErrorAction Stop
                $color = switch ($entry.level) {
                    'CRITICAL' { 'Magenta' }
                    'ERROR'    { 'Red' }
                    'WARN'     { 'Yellow' }
                    'INFO'     { 'White' }
                    'DEBUG'    { 'DarkGray' }
                    default    { 'White' }
                }
                Write-Host ("{0} [{1}] {2}" -f $entry.timestamp, $entry.level, $entry.message) -ForegroundColor $color
            } catch {
                # Not JSON, display raw
                Write-Host $line -ForegroundColor DarkGray
            }
        }
        
        Write-Host ""
    } catch {
        Write-Host "Error reading log file: $($_.Exception.Message)" -ForegroundColor Red
    }
}
#endregion

#region UI Helper Functions
function Get-ExpectedChecksumInteractive {
    param([string]$TargetFile)
    
    $discoveredFiles = @(Find-ChecksumFiles -TargetFilePath $TargetFile)
    $inputValue = $null

    if ($discoveredFiles -and $discoveredFiles.Count -gt 0) {
        Write-Host ""
        Write-MenuHeader -Title "Checksum Source" -Subtitle "Matching files found beside the target"
        for ($i = 0; $i -lt $discoveredFiles.Count; $i++) {
            $df = $discoveredFiles[$i]
            $matchHint = $null
            try {
                $parsedHint = Get-ChecksumFromFile -Path $df.Path -TargetFilename (Split-Path -Leaf $TargetFile)
                if ($parsedHint -and $parsedHint.Checksum) {
                    $algHint = if ($parsedHint.Algorithm) { $parsedHint.Algorithm } else { "checksum" }
                    $matchPrefix = if ($parsedHint.FilenameMatch) { "target match" } else { "candidate" }
                    $matchHint = "{0}: {1}, line {2}" -f $matchPrefix, $algHint, $parsedHint.LineNumber
                }
            } catch { }

            if (-not $matchHint -and $df.Algorithm) { $matchHint = $df.Algorithm }
            if (-not $matchHint) { $matchHint = "checksum file" }
            Write-MenuItem -Key ($i + 1) -Label $df.Name -Detail $matchHint
        }
        Write-MenuItem -Key "P" -Label "Paste checksum"
        Write-MenuItem -Key "C" -Label "Use clipboard text"
        Write-MenuItem -Key "F" -Label "Choose another checksum file"
        Write-MenuItem -Key "0" -Label "Back"
        Write-Host ""
        $autoChoice = Read-Host "Choose source [1]"
        $autoChoice = $autoChoice.Trim()
        
        if ([string]::IsNullOrWhiteSpace($autoChoice)) {
            $inputValue = $discoveredFiles[0].Path
            Write-Host ("Using: {0}" -f $discoveredFiles[0].Name) -ForegroundColor Green
        } elseif ($autoChoice -eq '0') {
            return $null
        } elseif ($autoChoice -match '^[0-9]+$') {
            $selection = 0
            if ([int]::TryParse($autoChoice, [ref]$selection) -and $selection -ge 1 -and $selection -le $discoveredFiles.Count) {
                $idx = $selection - 1
                $inputValue = $discoveredFiles[$idx].Path
                Write-Host ("Using: {0}" -f $discoveredFiles[$idx].Name) -ForegroundColor Green
            } else {
                Write-Host "Invalid selection." -ForegroundColor Yellow
                return $null
            }
        } elseif ($autoChoice.ToUpper() -eq 'F') {
            $chkFile = Select-File -Prompt "Select checksum file to parse"
            if (-not $chkFile) { Write-Host "No checksum file selected." -ForegroundColor Yellow; return $null }
            $inputValue = $chkFile
        } elseif ($autoChoice.ToUpper() -eq 'P') {
            $inputValue = Read-Host "Enter expected checksum (paste)"
            if (-not $inputValue) { Write-Host "No checksum entered." -ForegroundColor Yellow; return $null }
        } elseif ($autoChoice.ToUpper() -eq 'C') {
            $inputValue = Get-ConfirmedClipboardChecksumText -TargetFile $TargetFile
            if (-not $inputValue) { return $null }
            Write-Host "Using confirmed clipboard text." -ForegroundColor Green
        } else {
            $inputValue = $autoChoice
        }
    } elseif ($Global:Settings.UseFileDialog) {
        Write-Host ""
        Write-MenuHeader -Title "Checksum Source" -Subtitle "No matching checksum files found beside the target"
        if ($Global:LastChecksumDiscoveryStats) {
            Write-Host ("Scanned {0} folder(s), checked {1} nearby candidate file(s), accepted {2}." -f `
                $Global:LastChecksumDiscoveryStats.DirectoryCount,
                $Global:LastChecksumDiscoveryStats.CandidateCount,
                $Global:LastChecksumDiscoveryStats.ParsedCount) -ForegroundColor DarkGray
            Write-Host ("Directory: {0}" -f $Global:LastChecksumDiscoveryStats.LastDirectory) -ForegroundColor DarkGray
        }
        Write-Host ""
        Write-MenuItem -Key "P" -Label "Paste checksum or path"
        Write-MenuItem -Key "C" -Label "Use clipboard text"
        Write-MenuItem -Key "F" -Label "Choose checksum file"
        Write-MenuItem -Key "0" -Label "Back"
        Write-Host ""
        $choice = Read-Host "Choose source [P]"
        if ([string]::IsNullOrWhiteSpace($choice)) { $choice = 'P' }
        $choice = $choice.Trim()

        if ($choice -eq '0') {
            return $null
        } elseif ($choice -eq 'C') {
            $inputValue = Get-ConfirmedClipboardChecksumText -TargetFile $TargetFile
            if (-not $inputValue) { return $null }
            Write-Host "Using confirmed clipboard text." -ForegroundColor Green
        } elseif ($choice -eq 'F') {
            $chkFile = Select-File -Prompt "Select checksum file to parse"
            if (-not $chkFile) { Write-Host "No checksum file selected." -ForegroundColor Yellow; return $null }
            $inputValue = $chkFile
        } elseif ($choice -eq 'P') {
            $inputValue = Read-Host "Enter expected checksum (paste) or a checksum file path"
        } else {
            $inputValue = $choice
            if (-not $inputValue) { Write-Host "No checksum entered." -ForegroundColor Yellow; return $null }
        }
    } else {
        $inputValue = Read-Host "Enter expected checksum or full path to a checksum file (leave blank to cancel)"
        if (-not $inputValue) { Write-Host "No checksum entered." -ForegroundColor Yellow; return $null }
    }
    
    return $inputValue
}

function Show-VerifyResult {
    param($Result, $FilePath)
    if ($Result.Match) {
        Write-Host ""
        Write-MenuHeader -Title "[OK] Checksum Match" -Subtitle (Split-Path -Leaf $FilePath)
        Write-Host ("  Algorithm: {0}" -f $Result.Algorithm) -ForegroundColor White
        if ($Result.ExpectedSource) { Write-Host ("  Expected:  {0}" -f $Result.ExpectedSource) -ForegroundColor DarkGray }
        Write-Host ("  Checksum:  {0}" -f $Result.Calculated) -ForegroundColor DarkGray
        Write-Host ("  Time:      {0:N2} seconds" -f $Result.Elapsed.TotalSeconds) -ForegroundColor DarkGray
        Write-Host ""
        if ($Global:Settings.AutoCopyToClipboard) {
            if (Copy-ToClipboard -Text $Result.Calculated) { Write-Host "Checksum copied to clipboard (auto-copy enabled)." -ForegroundColor Yellow }
        } else {
            Invoke-ChecksumResultAction -Results @([PSCustomObject]@{
                Algorithm = $Result.Algorithm
                Checksum = $Result.Calculated
                Path = $Result.Path
            }) -FilePath $FilePath -Default "N"
        }
    } else {
        Write-Host ""
        Write-MenuHeader -Title "[FAIL] Checksum Mismatch" -Subtitle (Split-Path -Leaf $FilePath)
        if ($Result.ExpectedSource) { Write-Host ("  Source:     {0}" -f $Result.ExpectedSource) -ForegroundColor DarkGray }
        Write-Host ("  Expected:   {0}" -f $Result.ExpectedChecksum) -ForegroundColor Yellow
        Write-Host ("  Calculated: {0}" -f $Result.Calculated) -ForegroundColor Red
        Write-Host ("  Time:       {0:N2} seconds" -f $Result.Elapsed.TotalSeconds) -ForegroundColor DarkGray
        Invoke-ChecksumResultAction -Results @([PSCustomObject]@{
            Algorithm = $Result.Algorithm
            Checksum = $Result.Calculated
            Path = $Result.Path
        }) -FilePath $FilePath -Default "N"
    }
}
#endregion

#region Interactive single-key main menu (host-aware, concise)
function Read-SingleKey {
    param(
        [string] $Prompt = $null,
        [switch] $AllowEscape
    )
    if ($Prompt) { Write-Host $Prompt }
    try { 
        $ck = [Console]::ReadKey($true)
        if ($AllowEscape -and $ck.Key -eq [ConsoleKey]::Escape) { return [char]27 }
        return $ck.KeyChar 
    } catch {
        try {
            while ($true) {
                $k = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                if ($AllowEscape -and $k.VirtualKeyCode -eq 27) { return [char]27 }
                if ($k.Character -and ($k.Character -ne [char]0)) { return $k.Character }
            }
        } catch {
            # Final fallback: Read-Host with no explicit -Prompt (works in ISE)
            $userInput = Read-Host
            if ($userInput) { return $userInput[0] } else { return '' }
        }
    }
}

function Write-MenuHeader {
    param(
        [Parameter(Mandatory=$true)][string] $Title,
        [string] $Subtitle
    )

    Write-Host $Title -ForegroundColor Cyan
    if ($Subtitle) { Write-Host $Subtitle -ForegroundColor DarkGray }
    Write-Host ("-" * 64) -ForegroundColor DarkGray
}

function Write-MenuItem {
    param(
        [Parameter(Mandatory=$true)][string] $Key,
        [Parameter(Mandatory=$true)][string] $Label,
        [string] $Detail
    )

    Write-Host ("  {0}) " -f $Key) -NoNewline -ForegroundColor Yellow
    Write-Host $Label -NoNewline -ForegroundColor White
    if ($Detail) { Write-Host ("  {0}" -f $Detail) -ForegroundColor DarkGray } else { Write-Host "" }
}

function Write-DisabledMenuItem {
    param(
        [Parameter(Mandatory=$true)][string] $Key,
        [Parameter(Mandatory=$true)][string] $Label,
        [string] $Detail
    )

    Write-Host ("  {0}) " -f $Key) -NoNewline -ForegroundColor DarkGray
    Write-Host $Label -NoNewline -ForegroundColor DarkGray
    if ($Detail) { Write-Host ("  {0}" -f $Detail) -ForegroundColor DarkGray } else { Write-Host "" }
}

function Wait-ForUser {
    param([string] $Message = "Press Enter to continue")
    [void](Read-Host $Message)
}

function Read-MenuChoice {
    param(
        [string] $Prompt = "Choose",
        [string] $Default = $null
    )

    $defaultText = if ($Default) { "  Enter=$Default" } else { "" }
    Write-Host ("{0}{1}  ESC=Back" -f $Prompt, $defaultText) -ForegroundColor DarkGray
    $choice = Read-SingleKey
    try { $choice = [string]$choice; $choice = $choice.Trim().ToUpper() } catch {}
    if ([string]::IsNullOrWhiteSpace($choice) -and $Default) { return $Default.ToUpper() }
    if ($choice -eq [char]27 -or $choice -match '^\x1B') { return $null }
    return $choice
}

function Invoke-ChecksumResultAction {
    param(
        [Parameter(Mandatory=$true)] [array] $Results,
        [Parameter(Mandatory=$true)] [string] $FilePath,
        [string] $Default = "N"
    )

    Write-Host ""
    Write-MenuHeader -Title "Next Action" -Subtitle "Choose what to do with the calculated checksum"
    Write-MenuItem -Key "C" -Label "Copy to clipboard"
    Write-MenuItem -Key "F" -Label "Quick-save checksum file"
    Write-MenuItem -Key "M" -Label "Save with metadata"
    Write-MenuItem -Key "E" -Label "Export manifest" -Detail "SFV, GNU, or labeled format"
    Write-MenuItem -Key "N" -Label "Done"
    Write-Host ""

    $action = Read-MenuChoice -Prompt "Choose action (C/F/M/E/N)" -Default $Default
    if (-not $action) { return }

    switch ($action.ToUpper()) {
        'E' {
            foreach ($result in $Results) {
                $extension = if ($result.Algorithm -eq 'CRC32') { '.sfv' } else { ".$($result.Algorithm).sums.txt" }
                $output = $FilePath + $extension
                try { Export-ChecksumManifest -Results @($result) -OutputPath $output; Write-Host "Saved: $output" -ForegroundColor Green }
                catch { Write-Host "Save failed: $($_.Exception.Message)" -ForegroundColor Yellow }
            }
        }
        'C' {
            if ($Results.Count -gt 1) {
                $copyText = ($Results | ForEach-Object { "$($_.Algorithm): $($_.Checksum)" }) -join "`r`n"
            } else {
                $copyText = $Results[0].Checksum
            }
            if (Copy-ToClipboard -Text $copyText) {
                Write-Host "Checksum copied to clipboard." -ForegroundColor Yellow
                Write-LogMessage -Message "Checksum copied to clipboard by user" -Level INFO
            } else {
                Write-Host "Copy to clipboard failed." -ForegroundColor Red
                Write-LogMessage -Message "User copy to clipboard failed" -Level WARN
            }
        }
        'F' {
            $dir = Split-Path -Parent $FilePath
            $base = [IO.Path]::GetFileName($FilePath)
            $suffix = if ($Global:Settings.IncludeUsernameInMetadata) { ".$($env:USERNAME)" } else { "" }
            foreach ($res in $Results) {
                $out = Join-Path -Path $dir -ChildPath ("{0}.{1}{2}.txt" -f $base, $res.Algorithm, $suffix)
                if (Save-ChecksumQuick -TargetPath $out -Checksum $res.Checksum) {
                    Write-Host ("Saved: {0}" -f $out) -ForegroundColor Yellow
                    Write-LogMessage -Message ("Quick-saved checksum to {0}" -f $out) -Level INFO
                } else {
                    Write-Host ("Quick-save failed for {0}." -f $res.Algorithm) -ForegroundColor Red
                }
            }
        }
        'M' {
            $dir = Split-Path -Parent $FilePath
            $base = [IO.Path]::GetFileName($FilePath)
            $suffix = if ($Global:Settings.IncludeUsernameInMetadata) { ".$($env:USERNAME)" } else { "" }
            foreach ($res in $Results) {
                $out = Join-Path -Path $dir -ChildPath ("{0}.{1}{2}.txt" -f $base, $res.Algorithm, $suffix)
                if (Save-ChecksumWithMetadata -TargetPath $out -Checksum $res.Checksum -Algorithm $res.Algorithm -FilePath $res.Path) {
                    Write-Host ("Saved: {0}" -f $out) -ForegroundColor Yellow
                    Write-LogMessage -Message ("Saved checksum with metadata to {0}" -f $out) -Level INFO
                } else {
                    Write-Host ("Save with metadata failed for {0}." -f $res.Algorithm) -ForegroundColor Red
                }
            }
        }
        default {
            Write-Host "Done." -ForegroundColor DarkGray
        }
    }
}

function Show-MainMenuAndReadKey {
    Clear-Host
    $userDisplay = if ($env:USERNAME) { $env:USERNAME } else { 'Unknown User' }
    $autoCopyStatus = if ($Global:Settings.AutoCopyToClipboard) { 'On' } else { 'Off' }
    $fileMode = if ($Global:Settings.UseFileDialog) { 'GUI picker' } else { 'CLI path' }
    $recentStatus = Get-RecentFilesStatus
    $promptSuffix = if ($Host.Name -eq 'ConsoleHost') { 'no Enter required' } else { 'press number then Enter' }

    Write-MenuHeader -Title ("Checksum Tool v{0}" -f $ScriptVersion) -Subtitle ("User: {0} | AutoCopy: {1} | File mode: {2}" -f $userDisplay, $autoCopyStatus, $fileMode)
    Write-Host '  CHECKSUMS' -ForegroundColor Cyan
    Write-MenuItem -Key "1" -Label "Calculate checksum" -Detail "Generate one or all available hashes"
    Write-MenuItem -Key "2" -Label "Verify checksum" -Detail "Auto-detect algorithm from pasted value or file"
    Write-MenuItem -Key "3" -Label "Verify with chosen algorithm" -Detail "Choose CRC32, SHA, or BLAKE3"
    Write-MenuItem -Key 'B' -Label 'Batch verify' -Detail 'Check several files against one manifest'
    Write-Host ''
    Write-Host '  TOOLS & SETTINGS' -ForegroundColor Cyan
    if ($recentStatus.Enabled -and $recentStatus.Count -gt 0) {
        Write-MenuItem -Key "4" -Label "Recent files" -Detail $recentStatus.Detail
    } else {
        Write-DisabledMenuItem -Key "4" -Label "Recent files" -Detail $recentStatus.Detail
    }
    Write-MenuItem -Key "5" -Label "Preferences"
    Write-MenuItem -Key "6" -Label "Privacy & data"
    Write-MenuItem -Key 'U' -Label 'Check for updates'
    Write-MenuItem -Key 'H' -Label 'Help & algorithms'
    Write-MenuItem -Key "7" -Label "Exit"
    Write-Host ""
    Write-Host ("Choose a number or letter ({0})." -f $promptSuffix)
    $key = Read-SingleKey
    try { $key = [string]$key; $key = $key.Trim().ToUpperInvariant() } catch {}
    return $key
}

function Show-PrivacyMenu {
    Clear-Host
    Write-MenuHeader -Title "Privacy & Data" -Subtitle "Local settings, logs, and recent-file history"
    Write-Host "Data Storage Locations:" -ForegroundColor Yellow
    Write-Host ("  Settings: {0}" -f (Get-SettingsFilePath))
    Write-Host ("  Log File: {0}" -f $Global:LogFile)
    Write-Host ""
    
    $recentCount = if ($Global:Settings.RecentFiles) { $Global:Settings.RecentFiles.Count } else { 0 }
    $includeUsername = if ($Global:Settings.IncludeUsernameInMetadata) { "Yes" } else { "No (Privacy Protected)" }
    $anonymizeLogs = if ($Global:Settings.AnonymizeLogPaths) { "Yes (Privacy Protected)" } else { "No" }
    $enableHistory = if ($Global:Settings.EnableRecentFiles) { "Yes" } else { "No (Privacy Protected)" }
    
    Write-Host "Current Privacy Settings:" -ForegroundColor Yellow
    Write-Host ("  Include username in file metadata: {0}" -f $includeUsername)
    Write-Host ("  Anonymize file paths in logs: {0}" -f $anonymizeLogs)
    Write-Host ("  Enable recent files tracking: {0}" -f $enableHistory)
    Write-Host ("  Recent files currently stored: {0}" -f $recentCount)
    Write-Host ""
    
    Write-MenuItem -Key "1" -Label "Username in metadata" -Detail $includeUsername
    Write-MenuItem -Key "2" -Label "Path anonymization in logs" -Detail $anonymizeLogs
    Write-MenuItem -Key "3" -Label "Recent files tracking" -Detail $enableHistory
    Write-MenuItem -Key "4" -Label "View stored data"
    Write-MenuItem -Key "5" -Label "Clear recent files"
    Write-MenuItem -Key "6" -Label "Clear logs"
    Write-MenuItem -Key "7" -Label "Export all data" -Detail "JSON"
    Write-MenuItem -Key "8" -Label "Delete all stored data" -Detail "settings, logs, history"
    Write-MenuItem -Key "0" -Label "Back"
    Write-Host ""
    return (Read-MenuChoice -Prompt "Choose option (0-8)")
}

function Export-ChecksumData {
    param([string] $OutputPath)
    if (-not $OutputPath) {
        $OutputPath = Join-Path ([Environment]::GetFolderPath('Desktop')) ("ChecksumTool_DataExport_{0}_{1}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'), [Guid]::NewGuid().ToString('N').Substring(0,8))
    }
    $data = @{ ExportDate=(Get-Date).ToUniversalTime().ToString('o'); Settings=$Global:Settings; LogFile=$Global:LogFile; ScriptVersion=$ScriptVersion }
    Write-ChecksumFile -Path $OutputPath -Content ($data | ConvertTo-Json -Depth 10)
    return $OutputPath
}

function Show-ChecksumHelp {
    Clear-Host
    Write-MenuHeader -Title 'Help & Algorithms'
    $available = @(Get-SupportedChecksumAlgorithms)
    Write-Host '  ALGORITHMS' -ForegroundColor Cyan
    foreach ($algorithm in @('SHA256', 'SHA384', 'SHA512', 'MD5', 'SHA1', 'CRC32', 'SHA3-256', 'SHA3-512', 'BLAKE3')) {
        $detail = switch ($algorithm) {
            'SHA256' { 'Default' }
            'MD5' { 'Legacy' }
            'SHA1' { 'Legacy' }
            'CRC32' { 'SFV / accidental corruption' }
            default { 'Available' }
        }
        $color = 'White'
        if ($algorithm -notin $available) {
            $detail = if ($algorithm -eq 'BLAKE3') { 'Needs b3sum.exe (install below)' } else { 'Unavailable in this runtime' }
            $color = 'DarkGray'
        }
        Write-Host ('  {0,-12} {1}' -f $algorithm, $detail) -ForegroundColor $color
    }
    Write-Host ''
    Write-Host '  CHECKSUM FILES' -ForegroundColor Cyan
    Write-Host '  SFV          Filename, then CRC32 hash'
    Write-Host '  GNU          Hash, then filename'
    Write-Host '  Tagged       Algorithm, filename, and hash'
    Write-Host '  For SHA3/BLAKE3, keep the algorithm label or select it explicitly.' -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '  SAVES & UPDATES' -ForegroundColor Cyan
    Write-Host '  Saves        Existing files are protected; move them to save again.'
    Write-Host '  Updates      Choose U in the main menu to check GitHub.'
    Write-Host '               Downloads are verified; installation keeps a backup.' -ForegroundColor DarkGray
    if ('BLAKE3' -notin $available) {
        Write-Host ''
        Write-Host '  BLAKE3 SETUP' -ForegroundColor Cyan
        Write-Host '  Install the official Windows x64 tool, or put b3sum.exe'
        Write-Host '  beside this script or on PATH.'
        Write-Host '  https://github.com/BLAKE3-team/BLAKE3/releases' -ForegroundColor DarkGray
        Write-Host ''
        Write-MenuItem -Key 'I' -Label 'Install BLAKE3 support'
        Write-MenuItem -Key '0' -Label 'Back'
        if ((Read-MenuChoice -Prompt 'Choose (I/0)' -Default '0') -eq 'I') {
            Write-Host 'This downloads b3sum.exe from the official BLAKE3 GitHub release and stores it beside this script.' -ForegroundColor Yellow
            if ((Read-Host 'Download and install b3sum.exe? [y/N]').Trim() -ieq 'y') {
                try {
                    $installed = Install-Blake3Tool -Directory (Split-Path -Parent $script:ApplicationPath)
                    Write-Host "Installed $($installed.Version): $($installed.Path)" -ForegroundColor Green
                } catch { Write-Host "BLAKE3 setup failed: $($_.Exception.Message)" -ForegroundColor Yellow }
            }
        }
    }
}

function Invoke-BatchChecksumVerification {
    $manifest = Select-File -Prompt 'Choose checksum manifest (SFV, GNU, or labeled)'
    if (-not $manifest) { return }
    $paths = @()
    if ($Global:Settings.UseFileDialog) {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $dialog = New-Object Windows.Forms.OpenFileDialog
        try {
            $dialog.Title = 'Select files to verify'
            $dialog.Multiselect = $true
            $dialog.InitialDirectory = Split-Path -Parent $manifest
            if ($dialog.ShowDialog() -ne [Windows.Forms.DialogResult]::OK) { return }
            $paths = @($dialog.FileNames)
        } finally { $dialog.Dispose() }
    } else {
        do {
            $inputPath = Read-Host 'File path (Enter finishes selection)'
            if (-not [string]::IsNullOrWhiteSpace($inputPath)) {
                $inputPath = $inputPath.Trim().Trim('"', "'")
                if (Test-Path -LiteralPath $inputPath -PathType Leaf) { $paths += (Get-Item -LiteralPath $inputPath).FullName }
                else { Write-Host 'File not found.' -ForegroundColor Yellow }
            }
        } while (-not [string]::IsNullOrWhiteSpace($inputPath))
    }
    if ($paths.Count -eq 0) { return }
    $paths = @($paths | Select-Object -Unique)
    Write-Host ''
    Write-MenuHeader -Title 'Batch Verification'
    Write-Host ("  Manifest: {0}" -f $manifest) -ForegroundColor White
    Write-Host ("  Files:    {0}" -f $paths.Count) -ForegroundColor White
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $results = @(Test-FileChecksums -Path $paths -ChecksumFile $manifest -ShowProgress -ShowStatus)
    $timer.Stop()
    $passed = @($results | Where-Object Match).Count
    $errors = @($results | Where-Object Error).Count
    $mismatches = $results.Count - $passed - $errors
    Write-Host ''
    Write-Host ("{0} of {1} files verified." -f $passed, $results.Count)
    Write-Host ("  Mismatches: {0} | Errors: {1} | Time: {2:N2} seconds" -f $mismatches, $errors, $timer.Elapsed.TotalSeconds) -ForegroundColor DarkGray
}
#endregion

#region Main loop
if ($NoMenu -or $MyInvocation.InvocationName -eq '.') { return }
while ($true) {
    $k = Show-MainMenuAndReadKey

    switch ($k) {
        'B' {
            try { Invoke-BatchChecksumVerification }
            catch { Show-FriendlyError -Action 'Batch verification' -ErrorRecord $_ }
            Wait-ForUser
        }
        'U' { Update-ChecksumTool; Wait-ForUser }
        'H' { Show-ChecksumHelp; Wait-ForUser }
        'Q' { Save-Settings -Settings $Global:Settings | Out-Null; return }
        '1' {
            $file = Select-File -Prompt "Choose file to calculate checksum" -ShowFileInfo
            if (-not $file) { Write-Host "No file selected." -ForegroundColor Yellow; Start-Sleep -Milliseconds 700; continue }

            Add-RecentFile -FilePath $file

            $alg = Select-AlgorithmMenu -Prompt "Choose hash algorithm" -Default "SHA256" -AllowAll
            if (-not $alg) { Write-Host "Cancelled algorithm selection." -ForegroundColor DarkGray; Start-Sleep -Milliseconds 700; continue }

            Write-LogMessage -Message ("User requested checksum for {0} using {1}" -f $file, $alg) -Level INFO
            
            try {
                Write-StatusMessage -Message ("Calculating {0} checksum for {1}" -f $alg, (Split-Path -Leaf $file))
                $results = Get-FileChecksumEx -Path $file -Algorithm $alg -ShowProgress
                
                if (-not $results) {
                    # Error already displayed by Get-FileChecksumEx
                    Wait-ForUser
                    continue
                }
                
                # Force into array to handle both single and ALL (multiple) responses nicely
                $results = @($results)
                
                Show-ChecksumResults -Results $results -FilePath $file

                if ($Global:Settings.AutoCopyToClipboard) {
                    if ($results.Count -gt 1) {
                        $copyText = ($results | ForEach-Object { "$($_.Algorithm): $($_.Checksum)" }) -join "`r`n"
                    } else {
                        $copyText = $results[0].Checksum
                    }
                    if (Copy-ToClipboard -Text $copyText) {
                        Write-Host "Checksum(s) automatically copied to clipboard (preference enabled)." -ForegroundColor Yellow
                        Write-LogMessage -Message "Checksum copied to clipboard automatically" -Level INFO
                    } else {
                        Write-Host "Auto-copy failed (see verbose)." -ForegroundColor Red
                        Write-LogMessage -Message "Auto-copy failed" -Level WARN
                    }
                }

                Invoke-ChecksumResultAction -Results $results -FilePath $file -Default "N"
                Wait-ForUser
            } catch {
                Show-FriendlyError -Action "Checksum Calculation" -ErrorRecord $_
                Write-LogMessage -Message ("Checksum calculation failed: {0}" -f $_.Exception.Message) -Level ERROR
                Wait-ForUser
            }
        }

        '2' {
            # Verify checksum (auto-detect algorithm)
            $file = Select-File -Prompt "Choose file to verify checksum" -ShowFileInfo
            if (-not $file) { Write-Host "No file selected." -ForegroundColor Yellow; Start-Sleep -Milliseconds 700; continue }

            Add-RecentFile -FilePath $file

            Write-Host ""
            Write-Host "Searching for checksum files in directory..." -ForegroundColor DarkGray

            $inputValue = Get-ExpectedChecksumInteractive -TargetFile $file
            if (-not $inputValue) { Start-Sleep -Milliseconds 700; continue }

            Write-LogMessage -Message ("User requested verify (auto-detect) for {0}" -f $file) -Level INFO
            try {
                Write-StatusMessage -Message ("Verifying {0}" -f (Split-Path -Leaf $file))
                $res = Test-FileChecksum -Path $file -ExpectedChecksumOrFile $inputValue -AutoDetectAlgorithm -ShowProgress
                Show-VerifyResult -Result $res -FilePath $file
            } catch {
                Show-FriendlyError -Action "Verification" -ErrorRecord $_
                Write-LogMessage -Message ("Verification error: {0}" -f $_.Exception.Message) -Level ERROR
            }

            Wait-ForUser
        }

        '3' {
            # Verify checksum with explicit algorithm
            $file = Select-File -Prompt "Choose file to verify checksum (specify algorithm)" -ShowFileInfo
            if (-not $file) { Write-Host "No file selected." -ForegroundColor Yellow; Start-Sleep -Milliseconds 700; continue }

            Add-RecentFile -FilePath $file

            $alg = Select-AlgorithmMenu -Prompt "Choose hash algorithm for verification" -Default "SHA256"
            if (-not $alg) { Write-Host "Cancelled algorithm selection." -ForegroundColor DarkGray; Start-Sleep -Milliseconds 700; continue }

            Write-Host ""
            Write-Host "Searching for checksum files in directory..." -ForegroundColor DarkGray

            $inputValue = Get-ExpectedChecksumInteractive -TargetFile $file
            if (-not $inputValue) { Start-Sleep -Milliseconds 700; continue }

            Write-LogMessage -Message ("User requested verify (explicit {0}) for {1}" -f $alg, $file) -Level INFO
            try {
                Write-StatusMessage -Message ("Verifying {0} with {1}" -f (Split-Path -Leaf $file), $alg)
                $res = Test-FileChecksum -Path $file -ExpectedChecksumOrFile $inputValue -Algorithm $alg -ShowProgress
                Show-VerifyResult -Result $res -FilePath $file
            } catch {
                Show-FriendlyError -Action "Verification" -ErrorRecord $_
                Write-LogMessage -Message ("Verification error: {0}" -f $_.Exception.Message) -Level ERROR
            }
            Wait-ForUser
        }

        '4' {
            # Recent files
            $recentStatus = Get-RecentFilesStatus
            if (-not $recentStatus.Enabled) {
                Write-Host ""
                Write-Host "Recent files tracking is off." -ForegroundColor Yellow
                Write-Host "Enable it from Privacy & data > Recent files tracking." -ForegroundColor DarkGray
                Start-Sleep -Milliseconds 1400
                continue
            } elseif ($recentStatus.Count -eq 0) {
                Write-Host ""
                Write-Host "Recent files is empty." -ForegroundColor Yellow
                Write-Host "Process a file first, or enable tracking if it was recently turned on." -ForegroundColor DarkGray
                Start-Sleep -Milliseconds 1400
                continue
            }

            $file = Show-RecentFilesMenu
            if (-not $file) { continue }
            
            # Quick action menu for recent file
            Clear-Host
            Write-MenuHeader -Title ("Recent: {0}" -f (Split-Path -Leaf $file)) -Subtitle $file
            Write-MenuItem -Key "1" -Label "Calculate checksum"
            Write-MenuItem -Key "2" -Label "Verify checksum" -Detail "auto-detect"
            Write-MenuItem -Key "3" -Label "Verify with chosen algorithm"
            Write-MenuItem -Key "0" -Label "Back"
            Write-Host ""
            
            $action = Read-MenuChoice -Prompt "Choose action (0-3)"
            
            if ([string]::IsNullOrWhiteSpace($action) -or $action -eq '0') {
                continue
            }
            
            if ($action -eq '1') {
                $alg = Select-AlgorithmMenu -Prompt "Choose hash algorithm" -Default "SHA256" -AllowAll
                if (-not $alg) { Write-Host "Cancelled." -ForegroundColor DarkGray; Start-Sleep -Milliseconds 700; continue }
                
                Write-LogMessage -Message ("User requested checksum for recent file {0} using {1}" -f $file, $alg) -Level INFO
                
                try {
                    Write-StatusMessage -Message ("Calculating {0} checksum for {1}" -f $alg, (Split-Path -Leaf $file))
                    $res = Get-FileChecksumEx -Path $file -Algorithm $alg -ShowProgress
                    
                    if (-not $res) {
                        Wait-ForUser
                        continue
                    }
                    
                    Show-ChecksumResults -Results @($res) -FilePath $file
                    
                    if ($Global:Settings.AutoCopyToClipboard) {
                        $copyText = if (@($res).Count -gt 1) { ($res | ForEach-Object { "$($_.Algorithm): $($_.Checksum)" }) -join "`r`n" } else { $res.Checksum }
                        if (Copy-ToClipboard -Text $copyText) {
                            Write-Host "Checksum automatically copied to clipboard." -ForegroundColor Yellow
                        }
                    }
                    
                    Invoke-ChecksumResultAction -Results @($res) -FilePath $file -Default "N"
                    Wait-ForUser
                } catch {
                    Show-FriendlyError -Action "Checksum Calculation" -ErrorRecord $_
                    Write-LogMessage -Message ("Checksum calculation failed: {0}" -f $_.Exception.Message) -Level ERROR
                    Wait-ForUser
                }
            } elseif ($action -eq '2' -or $action -eq '3') {
                $alg = $null
                if ($action -eq '3') {
                    $alg = Select-AlgorithmMenu -Prompt "Choose hash algorithm for verification" -Default "SHA256"
                    if (-not $alg) { Write-Host "Cancelled." -ForegroundColor DarkGray; Start-Sleep -Milliseconds 700; continue }
                }
                
                $inputValue = Get-ExpectedChecksumInteractive -TargetFile $file
                if (-not $inputValue) { Start-Sleep -Milliseconds 700; continue }
                
                try {
                    if ($alg) {
                        Write-StatusMessage -Message ("Verifying {0} with {1}" -f (Split-Path -Leaf $file), $alg)
                        $res = Test-FileChecksum -Path $file -ExpectedChecksumOrFile $inputValue -Algorithm $alg -ShowProgress
                    } else {
                        Write-StatusMessage -Message ("Verifying {0}" -f (Split-Path -Leaf $file))
                        $res = Test-FileChecksum -Path $file -ExpectedChecksumOrFile $inputValue -AutoDetectAlgorithm -ShowProgress
                    }
                    Show-VerifyResult -Result $res -FilePath $file
                } catch {
                    Show-FriendlyError -Action "Verification" -ErrorRecord $_
                }
                
                Wait-ForUser
            }
        }

        '5' {
            $inPrefs = $true
            while ($inPrefs) {
                Clear-Host
                $prefAutoCopy = if ($Global:Settings.AutoCopyToClipboard) { 'On' } else { 'Off' }
                $prefInterval = $Global:Settings.ProgressUpdateIntervalMs
                $prefMinDelta = $Global:Settings.ProgressMinDeltaPercent
                $prefFileDlg = if ($Global:Settings.UseFileDialog) { 'GUI (File Explorer)' } else { 'CLI (Type/Paste Path)' }
                $prefLogDir = $Global:Settings.LogDirectory
                $prefWarningGB = $Global:Settings.LargeFileSizeWarningGB

                Write-MenuHeader -Title "Preferences" -Subtitle "Changes are saved immediately"
                Write-MenuItem -Key "1" -Label "Auto-copy checksum" -Detail $prefAutoCopy
                Write-MenuItem -Key "2" -Label "Progress update interval" -Detail ("{0} ms" -f $prefInterval)
                Write-MenuItem -Key "3" -Label "Progress minimum delta" -Detail ("{0}%" -f $prefMinDelta)
                Write-MenuItem -Key "4" -Label "File selection method" -Detail $prefFileDlg
                Write-MenuItem -Key "5" -Label "Large file warning" -Detail ("{0:N1} GB" -f $prefWarningGB)
                Write-MenuItem -Key "6" -Label "Log directory" -Detail $prefLogDir
                Write-MenuItem -Key "7" -Label "View recent log entries"
                Write-MenuItem -Key "0" -Label "Back"
                Write-Host ""

                $prefKey = Read-MenuChoice -Prompt "Choose setting (0-7)"
                
                # Check for ESC key
                if (-not $prefKey) {
                    $inPrefs = $false
                    continue
                }

                switch ($prefKey) {
                    '1' {
                        $Global:Settings.AutoCopyToClipboard = -not $Global:Settings.AutoCopyToClipboard
                        $state = if ($Global:Settings.AutoCopyToClipboard) { 'On' } else { 'Off' }
                        if (Save-Settings -Settings $Global:Settings) {
                            Write-Host ("AutoCopyToClipboard set to: {0}" -f $state) -ForegroundColor Yellow
                            Write-LogMessage -Message ("AutoCopyToClipboard set to {0}" -f $state) -Level INFO
                        } else {
                            Write-Host "Failed to save settings." -ForegroundColor Red
                            Write-LogMessage -Message "Failed to save AutoCopy change" -Level ERROR
                        }
                        Start-Sleep -Milliseconds 700
                    }
                    '2' {
                        $val = Read-Host ("Enter progress update interval in ms [Current: {0}] (min 50)" -f $Global:Settings.ProgressUpdateIntervalMs)
                        if ($val) {
                            $tmp = 0
                            if ([int]::TryParse($val, [ref]$tmp) -and $tmp -ge 50) {
                                $Global:Settings.ProgressUpdateIntervalMs = [int]$tmp
                                if (Save-Settings -Settings $Global:Settings) {
                                    Write-Host ("Set ProgressUpdateIntervalMs to {0}" -f $Global:Settings.ProgressUpdateIntervalMs) -ForegroundColor Yellow
                                    Write-LogMessage -Message ("ProgressUpdateIntervalMs set to {0}" -f $tmp) -Level INFO
                                } else { Write-Host "Failed to save settings." -ForegroundColor Red }
                            } else { Write-Host "Invalid value; must be integer >= 50. No change." -ForegroundColor Yellow }
                        } else { Write-Host "No change." -ForegroundColor Yellow }
                        Start-Sleep -Milliseconds 700
                    }
                    '3' {
                        $val = Read-Host ("Enter progress minimum delta percent (e.g. 0.25) [Current: {0}]" -f $Global:Settings.ProgressMinDeltaPercent)
                        if ($val) {
                            try {
                                $d = [double]$val
                                if (-not [double]::IsNaN($d) -and -not [double]::IsInfinity($d) -and $d -ge 0 -and $d -le 100) {
                                    $Global:Settings.ProgressMinDeltaPercent = $d
                                    if (Save-Settings -Settings $Global:Settings) {
                                        Write-Host ("Set ProgressMinDeltaPercent to {0}" -f $Global:Settings.ProgressMinDeltaPercent) -ForegroundColor Yellow
                                        Write-LogMessage -Message ("ProgressMinDeltaPercent set to {0}" -f $d) -Level INFO
                                    } else { Write-Host "Failed to save settings." -ForegroundColor Red }
                                } else { Write-Host "Must be between 0 and 100. No change." -ForegroundColor Yellow }
                            } catch { Write-Host "Invalid value; no change." -ForegroundColor Yellow }
                        } else { Write-Host "No change." -ForegroundColor Yellow }
                        Start-Sleep -Milliseconds 700
                    }
                    '4' {
                        $Global:Settings.UseFileDialog = -not $Global:Settings.UseFileDialog
                        $method = if ($Global:Settings.UseFileDialog) { 'GUI (File Explorer)' } else { 'CLI (Type/Paste Path)' }
                        if (Save-Settings -Settings $Global:Settings) {
                            Write-Host ("File selection method set to: {0}" -f $method) -ForegroundColor Yellow
                            Write-LogMessage -Message ("File selection method set to {0}" -f $method) -Level INFO
                        } else { Write-Host "Failed to save settings." -ForegroundColor Red }
                        Start-Sleep -Milliseconds 700
                    }
                    '5' {
                        $val = Read-Host ("Enter large file warning threshold in GB (e.g. 1.5) [Current: {0:N1}]" -f $Global:Settings.LargeFileSizeWarningGB)
                        if ($val) {
                            try {
                                $gb = [double]$val
                                if (-not [double]::IsNaN($gb) -and -not [double]::IsInfinity($gb) -and $gb -gt 0) {
                                    $Global:Settings.LargeFileSizeWarningGB = $gb
                                    if (Save-Settings -Settings $Global:Settings) {
                                        Write-Host ("Large file warning threshold set to {0:N1} GB" -f $gb) -ForegroundColor Yellow
                                        Write-LogMessage -Message ("LargeFileSizeWarningGB set to {0:N1}" -f $gb) -Level INFO
                                    } else { Write-Host "Failed to save settings." -ForegroundColor Red }
                                } else { Write-Host "Must be > 0. No change." -ForegroundColor Yellow }
                            } catch { Write-Host "Invalid value; no change." -ForegroundColor Yellow }
                        } else { Write-Host "No change." -ForegroundColor Yellow }
                        Start-Sleep -Milliseconds 700
                    }
                    '6' {
                        $new = $null
                        if ($Global:Settings.UseFileDialog) {
                            $dlg = $null
                            try {
                                Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
                                $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
                                $dlg.Description = "Select folder to store logs"
                                if (Test-Path -LiteralPath $Global:Settings.LogDirectory -PathType Container) { $dlg.SelectedPath = $Global:Settings.LogDirectory }
                                if ($dlg.ShowDialog() -eq 'OK') { $new = $dlg.SelectedPath }
                            } catch {
                                Write-LogMessage -Message ("Folder dialog failed: {0}" -f $_.Exception.Message) -Level WARN
                                $new = $null
                            } finally { if ($dlg) { $dlg.Dispose() } }
                        } else {
                            $userInput = Read-Host ("Enter log directory full path (leave blank to cancel) [Current: {0}]" -f $Global:Settings.LogDirectory)
                            if ($userInput) { $new = $userInput.Trim().Trim('"','''') } else { $new = $null }
                        }

                        if ($new) {
                            try { [void][IO.Directory]::CreateDirectory($new) } catch {}
                            if (Test-Path -LiteralPath $new -PathType Container) {
                                $Global:Settings.LogDirectory = $new
                                $Global:LogDirectory = $new
                                $Global:LogFile = Join-Path -Path $Global:LogDirectory -ChildPath "checksum_tool.log"
                                if (Save-Settings -Settings $Global:Settings) {
                                    Write-Host ("LogDirectory set to: {0}" -f $new) -ForegroundColor Yellow
                                    Write-LogMessage -Message ("LogDirectory set to {0}" -f $new) -Level INFO
                                } else { Write-Host "Failed to save settings." -ForegroundColor Red }
                            } else { Write-Host "Unable to set log directory." -ForegroundColor Red }
                        } else { Write-Host "No change." -ForegroundColor Yellow }
                        Start-Sleep -Milliseconds 700
                    }
                    '7' {
                        Show-RecentLogEntries -Count 50
                        Wait-ForUser
                    }
                    '0' { $inPrefs = $false }
                    default { Write-Host "Invalid option" -ForegroundColor Red; Start-Sleep -Milliseconds 700 }
                }
            }
        }

        '6' {
            # Privacy & Data Management
            while ($true) {
                $choice = Show-PrivacyMenu
                
                if ([string]::IsNullOrWhiteSpace($choice) -or $choice -eq [char]27 -or $choice -match '^\x1B' -or $choice -eq '0') {
                    break
                }
                
                switch ($choice) {
                    '1' {
                        $Global:Settings.IncludeUsernameInMetadata = -not $Global:Settings.IncludeUsernameInMetadata
                        $state = if ($Global:Settings.IncludeUsernameInMetadata) { 'Enabled' } else { 'Disabled (Privacy Protected)' }
                        if (Save-Settings -Settings $Global:Settings) {
                            Write-Host ("Username in metadata: {0}" -f $state) -ForegroundColor Yellow
                            Write-LogMessage -Message ("Privacy: Username in metadata set to {0}" -f $Global:Settings.IncludeUsernameInMetadata) -Level INFO
                        }
                        Start-Sleep -Milliseconds 1000
                    }
                    '2' {
                        $Global:Settings.AnonymizeLogPaths = -not $Global:Settings.AnonymizeLogPaths
                        $state = if ($Global:Settings.AnonymizeLogPaths) { 'Enabled (Privacy Protected)' } else { 'Disabled' }
                        if (Save-Settings -Settings $Global:Settings) {
                            Write-Host ("Path anonymization in logs: {0}" -f $state) -ForegroundColor Yellow
                            Write-LogMessage -Message ("Privacy: Path anonymization set to {0}" -f $Global:Settings.AnonymizeLogPaths) -Level INFO
                        }
                        Start-Sleep -Milliseconds 1000
                    }
                    '3' {
                        $Global:Settings.EnableRecentFiles = -not $Global:Settings.EnableRecentFiles
                        $state = if ($Global:Settings.EnableRecentFiles) { 'Enabled' } else { 'Disabled (Privacy Protected)' }
                        if (-not $Global:Settings.EnableRecentFiles) {
                            $Global:Settings.RecentFiles = @()
                        }
                        if (Save-Settings -Settings $Global:Settings) {
                            Write-Host ("Recent files tracking: {0}" -f $state) -ForegroundColor Yellow
                            Write-LogMessage -Message ("Privacy: Recent files tracking set to {0}" -f $Global:Settings.EnableRecentFiles) -Level INFO
                        }
                        Start-Sleep -Milliseconds 1000
                    }
                    '4' {
                        Clear-Host
                        Write-Host "All Stored Data" -ForegroundColor Cyan
                        Write-Host ("=" * 70) -ForegroundColor DarkGray
                        Write-Host ""
                        Write-Host "Settings:" -ForegroundColor Yellow
                        $Global:Settings | ConvertTo-Json -Depth 5 | Write-Host -ForegroundColor White
                        Write-Host ""
                        Wait-ForUser
                    }
                    '5' {
                        $confirm = Read-Host "Clear recent files history? (Y/N) [N]"
                        if ($confirm -match '^[yY]') {
                            $Global:Settings.RecentFiles = @()
                            if (Save-Settings -Settings $Global:Settings) {
                                Write-Host "Recent files history cleared." -ForegroundColor Green
                                Write-LogMessage -Message "User cleared recent files history" -Level INFO
                            }
                        } else {
                            Write-Host "Cancelled." -ForegroundColor Yellow
                        }
                        Start-Sleep -Milliseconds 1000
                    }
                    '6' {
                        $confirm = Read-Host "Clear all log files? This cannot be undone. (Y/N) [N]"
                        if ($confirm -match '^[yY]') {
                            try {
                                if (Test-Path -LiteralPath $Global:LogFile) { Remove-Item -LiteralPath $Global:LogFile -Force -ErrorAction Stop }
                                for ($i = 1; $i -le $Global:MaxLogArchives; $i++) {
                                    $archiveLog = "$Global:LogFile.$i.log"
                                    if (Test-Path -LiteralPath $archiveLog) { Remove-Item -LiteralPath $archiveLog -Force -ErrorAction Stop }
                                }
                                Write-Host "All log files cleared." -ForegroundColor Green
                                Write-LogMessage -Message "User cleared all log files" -Level INFO
                            } catch {
                                Write-Host "Failed to clear logs: $($_.Exception.Message)" -ForegroundColor Red
                            }
                        } else {
                            Write-Host "Cancelled." -ForegroundColor Yellow
                        }
                        Start-Sleep -Milliseconds 1000
                    }
                    '7' {
                        try {
                            $exportPath = Export-ChecksumData
                            Write-Host ("Data exported to: {0}" -f $exportPath) -ForegroundColor Green
                            Write-LogMessage -Message "User exported all data" -Level INFO
                        } catch {
                            Write-Host "Export failed: $($_.Exception.Message)" -ForegroundColor Red
                        }
                        Start-Sleep -Milliseconds 1500
                    }
                    '8' {
                        Write-Host ""
                        Write-Host "WARNING: This will permanently delete:" -ForegroundColor Red
                        Write-Host "  - All settings" -ForegroundColor Yellow
                        Write-Host "  - All log files" -ForegroundColor Yellow
                        Write-Host "  - Recent files history" -ForegroundColor Yellow
                        Write-Host ""
                        $confirm = Read-Host "Type 'DELETE' to confirm"
                        if ($confirm -eq 'DELETE') {
                            try {
                                # Delete settings
                                $settingsPath = Get-SettingsFilePath
                                if (Test-Path -LiteralPath $settingsPath) { Remove-Item -LiteralPath $settingsPath -Force -ErrorAction Stop }
                                
                                # Delete logs
                                if (Test-Path -LiteralPath $Global:LogFile) { Remove-Item -LiteralPath $Global:LogFile -Force -ErrorAction Stop }
                                for ($i = 1; $i -le $Global:MaxLogArchives; $i++) {
                                    $archiveLog = "$Global:LogFile.$i.log"
                                    if (Test-Path -LiteralPath $archiveLog) { Remove-Item -LiteralPath $archiveLog -Force -ErrorAction Stop }
                                }
                                
                                Write-Host ""
                                Write-Host "All data deleted. The tool will now exit." -ForegroundColor Green
                                Start-Sleep -Seconds 2
                                return
                            } catch {
                                Write-Host "Deletion failed: $($_.Exception.Message)" -ForegroundColor Red
                                Start-Sleep -Milliseconds 2000
                            }
                        } else {
                            Write-Host "Cancelled." -ForegroundColor Yellow
                            Start-Sleep -Milliseconds 1000
                        }
                    }
                    default {
                        Write-Host "Invalid option" -ForegroundColor Red
                        Start-Sleep -Milliseconds 700
                    }
                }
            }
        }

        '7' {
            if (Save-Settings -Settings $Global:Settings) { Write-LogMessage -Message "Settings saved on exit" -Level INFO }
            Write-LogMessage -Message "Checksum tool exiting" -Level INFO
            return
        }

        default { Write-Host "Invalid option" -ForegroundColor Red; Start-Sleep -Milliseconds 700 }
    }
}
#endregion
