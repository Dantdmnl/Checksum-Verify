<#
.SYNOPSIS
    Checksum Tool with persistent settings and single-key main-menu navigation.

.DESCRIPTION
    - Streaming checksum calculation with progress (MD5/SHA1/SHA256/SHA384/SHA512)
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
    - Support for checksum files in various common formats
    - Auto-discovery of checksum files in target file directory
    - Cross-platform path handling for checksum files
    - All functions use approved PowerShell verbs
    - GDPR compliant with privacy controls

.PRIVACY
    This tool stores local data for functionality:
    - Settings file: %LOCALAPPDATA%\checksum-tool\settings.json
    - Log file: %LOCALAPPDATA%\checksum-tool\checksum_tool.log
    - Recent files: File paths only (no file contents)
    - Username: Optional, only in file metadata if enabled
    
    All data is stored locally on your device. No data is transmitted externally.
    You can view, export, or delete all stored data via the Privacy menu.

.NOTES
    - Author: Ruben Draaisma
    - Version: 1.4.0
    - Tested on: Windows 11 24H2
    - Tested with: PowerShell ISE, PowerShell 5.1 and PowerShell 7
#>

#region Version & helper: settings path
$ScriptVersion = '1.4.0'

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
        if (-not (Test-Path -Path $Global:LogFile)) { return }
        $fileSizeMB = (Get-Item $Global:LogFile).Length / 1MB
        if ($fileSizeMB -lt $Global:MaxLogSizeMB) { return }

        $oldest = "$Global:LogFile.$Global:MaxLogArchives.log"
        if (Test-Path $oldest) { Remove-Item -Path $oldest -Force -ErrorAction SilentlyContinue }

        for ($i = $Global:MaxLogArchives - 1; $i -ge 1; $i--) {
            $oldLog = "$Global:LogFile.$i.log"
            $newLog = "$Global:LogFile.$($i + 1).log"
            if (Test-Path $oldLog) { Rename-Item -Path $oldLog -NewName $newLog -Force -ErrorAction SilentlyContinue }
        }

        Rename-Item -Path $Global:LogFile -NewName "$Global:LogFile.1.log" -Force -ErrorAction SilentlyContinue
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
            $Message = $Message -replace '([C-Z]:\\[^"'']+)', '[PATH_REDACTED]'
            $Message = $Message -replace '(\\\\[^"'']+)', '[UNC_PATH_REDACTED]'
        }
        
        $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $entry = "{""timestamp"":""$ts"",""level"":""$Level"",""message"":""$Message""}"
        $entry | Out-File -FilePath $Global:LogFile -Append -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {}
}
#endregion

#region Settings persistence (load/save/normalize)
function Save-Settings {
    param([Parameter(Mandatory=$true)] $Settings)
    $path = Get-SettingsFilePath
    try {
        $dir = Split-Path -Parent $path
        if (-not (Test-Path -LiteralPath $dir)) { try { New-Item -ItemType Directory -Path $dir -Force | Out-Null } catch {} }
        $json = $Settings | ConvertTo-Json -Depth 4 -ErrorAction Stop
        $json | Set-Content -LiteralPath $path -Encoding UTF8 -Force
        Write-LogMessage -Message ("Settings saved to {0}" -f $path) -Level INFO
        return $true
    } catch {
        Write-LogMessage -Message ("Failed saving settings: {0}" -f $_.Exception.Message) -Level ERROR
        return $false
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
        if (-not $Obj.LogDirectory) { $Obj.LogDirectory = $defaults.LogDirectory }
        $ld = $Obj.LogDirectory.Trim()
        $Obj.LogDirectory = $ld
    } catch { $Obj.LogDirectory = $defaults.LogDirectory }

    try {
        $gb = [double]::Parse("$($Obj.LargeFileSizeWarningGB)") 2>$null
        if ($gb -lt 0) { $Obj.LargeFileSizeWarningGB = $defaults.LargeFileSizeWarningGB } else { $Obj.LargeFileSizeWarningGB = [double]$gb }
    } catch { $Obj.LargeFileSizeWarningGB = $defaults.LargeFileSizeWarningGB }

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
        try { Set-Clipboard -Value $Text; return $true } catch { Write-LogMessage -Message ("Set-Clipboard failed: {0}" -f $_.Exception.Message) -Level WARN }
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
#endregion

#region Recent files management
function Add-RecentFile {
    param([Parameter(Mandatory=$true)][string] $FilePath)
    
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
    Write-Host "Recent Files" -ForegroundColor Cyan
    Write-Host ""
    
    $validFiles = @()
    $index = 1
    foreach ($file in $Global:Settings.RecentFiles) {
        if (Test-Path -LiteralPath $file -PathType Leaf) {
            $fileName = Split-Path -Leaf $file
            $fileSize = Format-FileSize -Bytes (Get-Item -LiteralPath $file).Length
            Write-Host ("{0}) {1} ({2})" -f $index, $fileName, $fileSize)
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
    Write-Host "0) Cancel / Back"
    Write-Host ""
    
    if ($validFiles.Count -le 9) {
        Write-Host "Press ESC to cancel" -ForegroundColor DarkGray
        Write-Host "Choose a file (0-$($validFiles.Count)):"
        
        $choice = Read-SingleKey
        try { $choice = [string]$choice; $choice = $choice.Trim() } catch {}
    } else {
        Write-Host "Press ESC to cancel or press Enter after typing your choice" -ForegroundColor DarkGray
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
        }
    } else {
        # CLI mode - type or paste path
        Write-Host ""
        Write-Host "File Selection (CLI Mode)" -ForegroundColor Cyan
        Write-Host "Tip: You can drag & drop a file into this window, or copy/paste the path" -ForegroundColor DarkGray
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
            $fileInfo = Get-Item -LiteralPath $selectedFile
            $fileSize = Format-FileSize -Bytes $fileInfo.Length
            $lastModified = $fileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
            
            Write-Host ""
            Write-Host "Selected File:" -ForegroundColor Cyan
            Write-Host ("  Name: {0}" -f $fileInfo.Name) -ForegroundColor White
            Write-Host ("  Size: {0} ({1:N0} bytes)" -f $fileSize, $fileInfo.Length) -ForegroundColor White
            Write-Host ("  Modified: {0}" -f $lastModified) -ForegroundColor White
            Write-Host ("  Path: {0}" -f $selectedFile) -ForegroundColor DarkGray
            
            # Warn for very large files (configurable threshold)
            $warningThresholdBytes = [int64]($Global:Settings.LargeFileSizeWarningGB * 1GB)
            if ($fileInfo.Length -gt $warningThresholdBytes) {
                Write-Host ""
                Write-Host ("WARNING: Large file ({0}). Processing may take several minutes." -f $fileSize) -ForegroundColor Yellow
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
    param([string] $Prompt = "Select algorithm", [string] $Default = "SHA256")
    $map = @{ '1'='MD5'; '2'='SHA1'; '3'='SHA256'; '4'='SHA384'; '5'='SHA512' }
    while ($true) {
        Write-Host ""
        Write-Host ("{0}:" -f $Prompt)
        Write-Host "  1) MD5"
        Write-Host "  2) SHA-1"
        Write-Host "  3) SHA-256"
        Write-Host "  4) SHA-384"
        Write-Host "  5) SHA-512"
        Write-Host "  0) Cancel / Back"
        Write-Host ""
        Write-Host "Press ESC to cancel" -ForegroundColor DarkGray
        Write-Host ("{0} (0-5) [Default: {1}]:" -f $Prompt, $Default)
        
        $choice = Read-SingleKey
        try { $choice = [string]$choice; $choice = $choice.Trim() } catch {}
        if ([string]::IsNullOrWhiteSpace($choice)) { return $Default }
        if ($choice -eq [char]27 -or $choice -match '^\x1B') { return $null }
        if ($map.ContainsKey($choice)) { return $map[$choice] }
        if ($choice -eq '0') { return $null }
        Write-Host "Invalid choice, try again." -ForegroundColor Yellow
    }
}
#endregion

#region Core checksum functions
function Get-FileChecksumEx {
    [CmdletBinding(DefaultParameterSetName='ByPath')]
    param(
        [Parameter(Mandatory=$true, Position=0)][ValidateNotNullOrEmpty()][string] $Path,
        [Parameter(Mandatory=$false)][ValidateSet('MD5','SHA1','SHA256','SHA384','SHA512')][string] $Algorithm = 'SHA256',
        [Parameter(Mandatory=$false)][ValidateRange(4096, [int]::MaxValue)][int] $BufferSize = (4 * 1MB),
        [Parameter(Mandatory=$false)][switch] $ShowProgress
    )

    begin {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { Throw "File not found: $Path" }
        if ($BufferSize -lt 4096) { Throw "BufferSize must be at least 4096 bytes." }
        $ProgressUpdateIntervalMs = [int]$Global:Settings.ProgressUpdateIntervalMs
        $ProgressMinDeltaPercent   = [double]$Global:Settings.ProgressMinDeltaPercent
        $progressId = 1
    }

    process {
        $fs = $null; $hashAlgo = $null
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $originalTitle = $null
        
        try {
            # Save original window title
            try { $originalTitle = $Host.UI.RawUI.WindowTitle } catch { }
            
            $hashAlgo = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm)
            if (-not $hashAlgo) { Throw "Unable to create hash algorithm '$Algorithm'." }

            $fs = [System.IO.File]::OpenRead($Path)
            $length = [int64]$fs.Length
            $buffer = New-Object byte[] $BufferSize
            $bytesRead = 0; $totalRead = 0L

            $lastUpdate = [DateTime]::UtcNow.AddMilliseconds(-$ProgressUpdateIntervalMs)
            $lastPercent = -1.0

            while (($bytesRead = $fs.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $hashAlgo.TransformBlock($buffer, 0, $bytesRead, $null, 0) | Out-Null
                $totalRead += [int64]$bytesRead

                if ($ShowProgress) {
                    $percent = if ($length -gt 0) { ([double]$totalRead / [double]$length) * 100.0 } else { 100.0 }
                    $now = [DateTime]::UtcNow
                    $timeSince = ($now - $lastUpdate).TotalMilliseconds
                    $deltaPercent = [math]::Abs($percent - $lastPercent)

                    if ($timeSince -ge $ProgressUpdateIntervalMs -or $deltaPercent -ge $ProgressMinDeltaPercent) {
                        $elapsedSec = [math]::Max(0.001, $sw.Elapsed.TotalSeconds)
                        $speedBytesPerSec = if ($elapsedSec -gt 0) { [double]$totalRead / $elapsedSec } else { 0.0 }

                        $remainingBytes = [math]::Max([int64]0, [int64]($length - $totalRead))
                        $etaSec = if ($speedBytesPerSec -gt 0) { [math]::Round($remainingBytes / $speedBytesPerSec) } else { 0 }
                        $remainingMB = [math]::Round([double]$remainingBytes / 1MB, 2)
                        $totalMB = [math]::Round([double]$length / 1MB, 2)
                        $speedMBps = [math]::Round($speedBytesPerSec / 1MB, 2)

                        Write-Progress -Id $progressId -Activity ("Calculating {0} checksum" -f $Algorithm) `
                                       -Status ("{0:N2}% - {1} MB of {2} MB @ {3} MB/s - ETA: {4}s" -f $percent, $remainingMB, $totalMB, $speedMBps, $etaSec) `
                                       -PercentComplete ([math]::Min(100, [math]::Round($percent, 2)))
                        
                        # Update window title with progress
                        try {
                            $Host.UI.RawUI.WindowTitle = ("{0} - {1:N1}% - {2}" -f $Algorithm, $percent, (Split-Path -Leaf $Path))
                        } catch { }

                        $lastUpdate = $now
                        $lastPercent = $percent
                    }
                }
            }

            $hashAlgo.TransformFinalBlock($buffer, 0, 0) | Out-Null
            $checksumBytes = $hashAlgo.Hash
            $hex = -join ($checksumBytes | ForEach-Object { "{0:x2}" -f $_ })

            $sw.Stop()

            Write-LogMessage -Message ("Checksum calculated for {0} ({1})" -f $Path, $Algorithm) -Level INFO

            [PSCustomObject]@{
                Path      = (Get-Item -LiteralPath $Path).FullName
                Algorithm = $Algorithm
                Checksum  = $hex
                Length    = $length
                Elapsed   = $sw.Elapsed
            }

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
            
            return $null
        } finally {
            if ($fs) { try { $fs.Close(); $fs.Dispose() } catch {} }
            if ($hashAlgo) { $hashAlgo.Dispose() }
            if ($ShowProgress) { Write-Progress -Id $progressId -Activity ("Calculating {0}" -f $Algorithm) -Completed }
            
            # Restore original window title
            if ($originalTitle) {
                try { $Host.UI.RawUI.WindowTitle = $originalTitle } catch { }
            }
        }
    }
}

function Get-ChecksumAlgorithmFromLength { param([string] $Checksum)
    switch ($Checksum.Length) {
        32  { return 'MD5' }
        40  { return 'SHA1' }
        64  { return 'SHA256' }
        96  { return 'SHA384' }
        128 { return 'SHA512' }
        default { Write-Verbose ("Checksum length {0} not recognized." -f $Checksum.Length); return $null }
    }
}

function ConvertTo-NormalizedChecksum {
    param([Parameter(Mandatory=$true)][string] $Raw)
    if (-not $Raw) { return $null }

    $tmp = $Raw.Trim()

    # Find all contiguous hex runs of lengths between 32 and 128 and pick the longest.
    $hexMatches = [regex]::Matches($tmp, '[0-9A-Fa-f]{32,128}') | ForEach-Object { $_.Value }
    if ($hexMatches -and $hexMatches.Count -gt 0) {
        $chosen = $hexMatches | Sort-Object { $_.Length } -Descending | Select-Object -First 1
        return $chosen.ToLower()
    }

    # Fallback: strip non-hex characters and return what's left
    $stripped = -join (($tmp.ToCharArray() | Where-Object { $_ -match '[0-9A-Fa-f]' }))
    if ($stripped.Length -gt 0) { return $stripped.ToLower() }

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

    $foundFiles = @()
    
    # Strategy 1: Check specific patterns first
    $patterns = @(
        # Exact file-specific checksums
        "$targetName.md5", "$targetName.sha1", "$targetName.sha256", "$targetName.sha384", "$targetName.sha512",
        "$targetBase.md5", "$targetBase.sha1", "$targetBase.sha256", "$targetBase.sha384", "$targetBase.sha512",
        # Common multi-file checksum files
        "SHA256SUMS", "SHA512SUMS", "SHA1SUMS", "MD5SUMS",
        "CHECKSUM", "CHECKSUMS", "checksum.txt", "checksums.txt", "checksum", "checksums",
        "SHA256SUMS.txt", "SHA512SUMS.txt", "SHA1SUMS.txt", "MD5SUMS.txt"
    )

    foreach ($pattern in $patterns) {
        try {
            $searchPath = Join-Path -Path $targetDir -ChildPath $pattern
            $matchedFiles = Get-ChildItem -Path $searchPath -File -ErrorAction SilentlyContinue
            foreach ($matchedFile in $matchedFiles) {
                if ($matchedFile.FullName -ne $TargetFilePath) {
                    try {
                        $sample = Get-Content -LiteralPath $matchedFile.FullName -First 10 -ErrorAction SilentlyContinue
                        if ($sample) {
                            $hasHex = $sample | Where-Object { $_ -match '[0-9A-Fa-f]{32,128}' }
                            if ($hasHex) {
                                Write-Verbose ("Found checksum file: {0}" -f $matchedFile.Name)
                                $foundFiles += [PSCustomObject]@{
                                    Path = $matchedFile.FullName
                                    Name = $matchedFile.Name
                                    Size = $matchedFile.Length
                                    Algorithm = Get-AlgorithmFromFilename -Filename $matchedFile.Name
                                }
                            }
                        }
                    } catch { }
                }
            }
        } catch { }
    }

    # Strategy 2: Scan directory for files matching common patterns (for files like CHECKSUM.SHA512-FreeBSD-...)
    try {
        $allFiles = Get-ChildItem -Path $targetDir -File -ErrorAction SilentlyContinue | 
            Where-Object { 
                $_.FullName -ne $TargetFilePath -and
                ($_.Name -match '(?i)^(checksum|checksums|sha\d+|md5)' -or
                 $_.Name -match '(?i)\.(sha1|sha256|sha384|sha512|md5|checksum)($|\.)' -or
                 $_.Name -match '(?i)sums$')
            }
        
        foreach ($file in $allFiles) {
            # Skip if already found
            if ($foundFiles | Where-Object { $_.Path -eq $file.FullName }) { continue }
            
            try {
                $sample = Get-Content -LiteralPath $file.FullName -First 10 -ErrorAction SilentlyContinue
                if ($sample) {
                    $hasHex = $sample | Where-Object { $_ -match '[0-9A-Fa-f]{32,128}' }
                    if ($hasHex) {
                        Write-Verbose ("Found checksum file via directory scan: {0}" -f $file.Name)
                        $foundFiles += [PSCustomObject]@{
                            Path = $file.FullName
                            Name = $file.Name
                            Size = $file.Length
                            Algorithm = Get-AlgorithmFromFilename -Filename $file.Name
                        }
                    }
                }
            } catch { }
        }
    } catch { }

    # Return unique files (in case patterns overlap)
    # Ensure we return a flat array (avoid nesting when a single result exists)
    return @($foundFiles | Sort-Object -Property Path -Unique | Select-Object -First 5)
}

function Get-AlgorithmFromFilename {
    param([Parameter(Mandatory=$true)][string] $Filename)

    $lower = $Filename.ToLower()

    # Check file extension first
    if ($lower -match '\.sha512$|sha512sums') { return 'SHA512' }
    if ($lower -match '\.sha384$') { return 'SHA384' }
    if ($lower -match '\.sha256$|sha256sums') { return 'SHA256' }
    if ($lower -match '\.sha1$|sha1sums') { return 'SHA1' }
    if ($lower -match '\.md5$|md5sums') { return 'MD5' }

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
        [Parameter(Mandatory=$false)][string] $TargetFilename
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

    $candidates = @()
    $lineNum = 0
    $targetPattern = if ($TargetFilename) { '\b' + [regex]::Escape($TargetFilename) + '\b' } else { $null }

    foreach ($raw in $lines) {
        $lineNum++
        if (-not $raw) { continue }
        $line = $raw.Trim()

        # Skip comment lines commonly found in distros (lines starting with #, ; or //)
        if ($line -match '^\s*(#|;|//)') { continue }

        # 1) Patterns like: "SHA256 (filename) = <hex>" or "SHA256 filename = <hex>" or "SHA-1 (...) = <hex>"
        if ($line -match '(?i)^\s*(?<alg>MD5|SHA-1|SHA1|SHA256|SHA384|SHA512)\b[^\r\n]*?(?:=|:)\s*(?<hex>[0-9A-Fa-f]{32,128})\b') {
            $hex = $matches['hex'].ToLower()
            $alg = $matches['alg'].ToUpper() -replace 'SHA-1','SHA1'
            switch ($alg) {
                'SHA1'  { $alg = 'SHA1' }
                'SHA256'{ $alg = 'SHA256' }
                'SHA384'{ $alg = 'SHA384' }
                'SHA512'{ $alg = 'SHA512' }
                'MD5'   { $alg = 'MD5' }
            }
            $fileMention = $false
            # Extract filename from parentheses if present: "SHA512 (filename) = hash"
            # Match the last set of parentheses before the equals/colon sign
            if ($TargetFilename -and $line -match '\(([^)]+)\)\s*(?:=|:)') {
                $extractedName = $matches[1].Trim()
                # Normalize path separators for comparison (/ vs \)
                $normalizedExtracted = $extractedName -replace '[\\/]', [IO.Path]::DirectorySeparatorChar
                $normalizedTarget = $TargetFilename -replace '[\\/]', [IO.Path]::DirectorySeparatorChar
                # Try exact match, then basename match (in case checksum file has path)
                if ($normalizedExtracted -eq $normalizedTarget -or (Split-Path -Leaf $normalizedExtracted) -eq $normalizedTarget) {
                    $fileMention = $true
                }
            } elseif ($targetPattern -and ($line -match $targetPattern)) {
                $fileMention = $true
            }
            $candidates += [PSCustomObject]@{ Checksum = $hex; Algorithm = $alg; Line = $line; LineNumber = $lineNum; FilenameMatch = $fileMention; Preferred = $true }
            continue
        }

        # 2) Common unix "sha256sum" style: "<hex>  filename" or "<hex> *filename"
        if ($line -match '(?i)^\s*(?<hex>[0-9A-Fa-f]{32,128})\s+\*?(?<fname>.+?)\s*$') {
            $hex = $matches['hex'].ToLower()
            $fname = $matches['fname'].Trim("`"", "'")
            $alg = Get-ChecksumAlgorithmFromLength -Checksum $hex
            $fileMention = $false
            # For extracted filename, check exact match with path normalization
            if ($TargetFilename) {
                $normalizedFname = $fname -replace '[\\/]', [IO.Path]::DirectorySeparatorChar
                $normalizedTarget = $TargetFilename -replace '[\\/]', [IO.Path]::DirectorySeparatorChar
                # Match exact, or basename (file only), or target pattern
                if ($normalizedFname -eq $normalizedTarget -or (Split-Path -Leaf $normalizedFname) -eq $normalizedTarget -or ($targetPattern -and $line -match $targetPattern)) {
                    $fileMention = $true
                }
            }
            $candidates += [PSCustomObject]@{ Checksum = $hex; Algorithm = $alg; Line = $line; LineNumber = $lineNum; FilenameMatch = $fileMention; Preferred = $fileMention }
            continue
        }

        # 3) Labeled single-value lines: "Checksum: <hex>" or "checksum = <hex>"
        if ($line -match '(?i)^\s*Checksum\s*[:=]\s*(?<hex>[0-9A-Fa-f]{32,128})\b') {
            $hex = $matches['hex'].ToLower()
            $alg = Get-ChecksumAlgorithmFromLength -Checksum $hex
            $fileMention = ($targetPattern -and ($line -match $targetPattern))
            $candidates += [PSCustomObject]@{ Checksum = $hex; Algorithm = $alg; Line = $line; LineNumber = $lineNum; FilenameMatch = $fileMention; Preferred = $true }
            continue
        }

        # 4) Algorithm hint only: "Algorithm: SHA256"
        if ($line -match '(?i)^\s*Algorithm\s*[:=]\s*(?<alg>MD5|SHA-1|SHA1|SHA256|SHA384|SHA512)\b') {
            $alg = $matches['alg'].ToUpper() -replace 'SHA-1','SHA1'
            switch ($alg) {
                'SHA1'  { $alg = 'SHA1' }
                'SHA256'{ $alg = 'SHA256' }
                'SHA384'{ $alg = 'SHA384' }
                'SHA512'{ $alg = 'SHA512' }
                'MD5'   { $alg = 'MD5' }
            }
            $candidates += [PSCustomObject]@{ Checksum = $null; Algorithm = $alg; Line = $line; LineNumber = $lineNum; FilenameMatch = $false; Preferred = $false }
            continue
        }

        # 5) Generic: find any hex runs (32..128) on the line and treat them as potential checksums
        $hexMatches = [regex]::Matches($line, '[0-9A-Fa-f]{32,128}') | ForEach-Object { $_.Value }
        if ($hexMatches -and $hexMatches.Count -gt 0) {
            foreach ($hm in $hexMatches) {
                $hex = $hm.ToLower()
                $alg = Get-ChecksumAlgorithmFromLength -Checksum $hex
                $fileMention = $false
                if ($targetPattern -and ($line -match $targetPattern)) { $fileMention = $true }
                # prefer lines that also contain the word 'checksum' or an algorithm name
                $preferred = ($line -match '(?i)checksum') -or ($line -match '(?i)\b(md5|sha1|sha256|sha384|sha512)\b')
                $candidates += [PSCustomObject]@{ Checksum = $hex; Algorithm = $alg; Line = $line; LineNumber = $lineNum; FilenameMatch = $fileMention; Preferred = $preferred }
            }
        }
    }

    if ($candidates.Count -eq 0) { return $null }

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

    $best = $scored | Sort-Object -Property @{Expression='Score';Descending=$true},@{Expression={'$_.Candidate.LineNumber'};Descending=$false} | Select-Object -First 1

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
        [ValidateSet('MD5','SHA1','SHA256','SHA384','SHA512')]
        [string] $Algorithm,
        
        [Parameter(Mandatory=$false)]
        [switch] $AutoDetectAlgorithm,
        
        [Parameter(Mandatory=$false)]
        [switch] $ShowProgress,
        
        [Parameter(Mandatory=$false)]
        [switch] $SaveOnMismatch,
        
        [Parameter(Mandatory=$false)]
        [string] $OutputPath
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { Throw "Target file not found: $Path" }

    $expectedChecksum = $null
    $derivedAlgorithm = $null

    # If the provided ExpectedChecksumOrFile is a path to a file, attempt to parse it; otherwise treat as literal/pasted
    if (Test-Path -LiteralPath $ExpectedChecksumOrFile -PathType Leaf) {
        Write-LogMessage -Message ("Parsing checksum from file: {0}" -f $ExpectedChecksumOrFile) -Level INFO
        try {
            $parsed = Get-ChecksumFromFile -Path $ExpectedChecksumOrFile -TargetFilename (Split-Path -Leaf $Path)
        } catch {
            Write-LogMessage -Message ("Checksum file parse failed: {0}" -f $_.Exception.Message) -Level WARN
            Throw "Could not parse checksum file: $ExpectedChecksumOrFile"
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
        }
    } else {
        # Pasted value or user-typed value: normalize and treat as checksum
        $norm = ConvertTo-NormalizedChecksum -Raw $ExpectedChecksumOrFile
        if (-not $norm) {
            Write-LogMessage -Message ("Invalid checksum format provided: {0}" -f $ExpectedChecksumOrFile.Substring(0, [Math]::Min(50, $ExpectedChecksumOrFile.Length))) -Level ERROR
            Throw "Provided checksum string does not contain a valid hexadecimal checksum. Expected format: 32 (MD5), 40 (SHA1), 64 (SHA256), 96 (SHA384), or 128 (SHA512) hex characters."
        }
        $expectedChecksum = $norm
    }

    # Determine algorithm to use (precedence):
    #   1) explicit -Algorithm parameter
    #   2) length-based detection from expected checksum (works for pasted and parsed checksums)
    #   3) algorithm hint parsed from checksum file (derivedAlgorithm)
    #   4) if AutoDetectAlgorithm requested but detection fails -> error
    #   5) otherwise require -Algorithm
    $chosenAlgorithm = $null

    if ($Algorithm) {
        $chosenAlgorithm = $Algorithm
    } else {
        if ($expectedChecksum) {
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
                Throw "Algorithm must be specified (use -Algorithm) or supply an ExpectedChecksum that indicates algorithm length."
            }
        }
    }

    # Compute checksum of target file
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
    if ($expectedChecksum) { $expectedChecksum = ConvertTo-NormalizedChecksum -Raw $expectedChecksum }
    $calculatedChecksum = ConvertTo-NormalizedChecksum -Raw $calc.Checksum

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
    }

    if (-not $match -and $SaveOnMismatch) {
        if (-not $OutputPath) {
            $dir = Split-Path -Parent $Path
            $base = [IO.Path]::GetFileName($Path)
            $suffix = if ($Global:Settings.IncludeUsernameInMetadata) { ".$($env:USERNAME)" } else { "" }
            $OutputPath = Join-Path -Path $dir -ChildPath ("{0}.{1}{2}.txt" -f $base, $chosenAlgorithm, $suffix)
        }
        try {
            [System.IO.File]::WriteAllText($OutputPath, $calculatedChecksum, [System.Text.Encoding]::UTF8)
            $result | Add-Member -NotePropertyName SavedChecksumPath -NotePropertyValue $OutputPath -Force
            Write-LogMessage -Message ("Saved checksum to {0} due to mismatch" -f $OutputPath) -Level INFO
        } catch {
            Write-LogMessage -Message ("Failed to save checksum on mismatch: {0}" -f $_.Exception.Message) -Level WARN
        }
    }

    Write-LogMessage -Message ("Verification for {0}: match={1} (alg={2})" -f $Path, $result.Match, $chosenAlgorithm) -Level INFO
    return $result
}

function Save-ChecksumQuick { param([string] $TargetPath,[string] $Checksum)
    try { [System.IO.File]::WriteAllText($TargetPath,$Checksum,[System.Text.Encoding]::UTF8); return $true } catch { Write-LogMessage -Message ("Quick save failed for {0}: {1}" -f $TargetPath,$_.Exception.Message) -Level WARN; return $false }
}

function Save-ChecksumWithMetadata { param([string] $TargetPath,[string] $Checksum,[string] $Algorithm,[string] $FilePath)
    $now = (Get-Date).ToString("u")
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
    try { [System.IO.File]::WriteAllText($TargetPath,$content,[System.Text.Encoding]::UTF8); return $true } catch { Write-LogMessage -Message ("Metadata save failed for {0}: {1}" -f $TargetPath,$_.Exception.Message) -Level WARN; return $false }
}
#endregion

#region View log entries
function Show-RecentLogEntries {
    param([int] $Count = 50)
    
    if (-not (Test-Path -Path $Global:LogFile)) {
        Write-Host "No log file found." -ForegroundColor Yellow
        Start-Sleep -Milliseconds 1000
        return
    }
    
    try {
        $lines = Get-Content -Path $Global:LogFile -Tail $Count -ErrorAction Stop
        
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

function Show-MainMenuAndReadKey {
    Clear-Host
    $userDisplay = if ($env:USERNAME) { $env:USERNAME } else { 'Unknown User' }
    $autoCopyStatus = if ($Global:Settings.AutoCopyToClipboard) { 'On' } else { 'Off' }
    $recentCount = if ($Global:Settings.RecentFiles) { $Global:Settings.RecentFiles.Count } else { 0 }
    $promptSuffix = if ($Host.Name -eq 'ConsoleHost') { 'no Enter required' } else { 'press number then Enter' }

    Write-Host ("Checksum Tool v{0} - User: {1}    AutoCopy: {2}" -f $ScriptVersion, $userDisplay, $autoCopyStatus) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1) Calculate checksum"
    Write-Host "2) Verify checksum (auto-detect algorithm, supports pasted value or checksum-file)"
    Write-Host "3) Verify checksum (specify algorithm, supports pasted value or checksum-file)"
    Write-Host ("4) Recent files ({0} available)" -f $recentCount)
    Write-Host "5) Preferences"
    Write-Host "6) Privacy & Data Management"
    Write-Host "7) Exit"
    Write-Host ""
    Write-Host ("Press the number key for your choice ({0})." -f $promptSuffix)
    $key = Read-SingleKey
    try { $key = [string]$key; $key = $key.Trim() } catch {}
    return $key
}

function Show-PrivacyMenu {
    Clear-Host
    Write-Host "Privacy & Data Management (GDPR Compliance)" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Data Storage Locations:" -ForegroundColor Yellow
    Write-Host ("  Settings: {0}" -f (Get-SettingsFilePath))
    Write-Host ("  Log File: {0}" -f $Global:LogFile)
    Write-Host ""
    
    $recentCount = if ($Global:Settings.RecentFiles) { $Global:Settings.RecentFiles.Count } else { 0 }
    $includeUsername = if ($Global:Settings.IncludeUsernameInMetadata) { "Yes" } else { "No (Privacy Protected)" }
    $anonymizeLogs = if ($Global:Settings.AnonymizeLogPaths) { "Yes (Privacy Protected)" } else { "No" }
    
    Write-Host "Current Privacy Settings:" -ForegroundColor Yellow
    Write-Host ("  Include username in file metadata: {0}" -f $includeUsername)
    Write-Host ("  Anonymize file paths in logs: {0}" -f $anonymizeLogs)
    Write-Host ("  Recent files stored: {0}" -f $recentCount)
    Write-Host ""
    
    Write-Host "Privacy Options:" -ForegroundColor Yellow
    Write-Host "1) Toggle username in file metadata (currently: $includeUsername)"
    Write-Host "2) Toggle path anonymization in logs (currently: $anonymizeLogs)"
    Write-Host "3) View all stored data"
    Write-Host "4) Clear recent files history"
    Write-Host "5) Clear all logs"
    Write-Host "6) Export all data (JSON)"
    Write-Host "7) Delete ALL stored data (settings, logs, history)"
    Write-Host "0) Back to main menu"
    Write-Host ""
    Write-Host "Press ESC to cancel" -ForegroundColor DarkGray
    Write-Host "Choose an option (0-7):"
    
    $choice = Read-SingleKey
    try { $choice = [string]$choice; $choice = $choice.Trim() } catch {}
    return $choice
}
#endregion

#region Main loop (Preferences: LogDirectory is option 5, Back is 6)
while ($true) {
    $k = Show-MainMenuAndReadKey

    switch ($k) {
        '1' {
            $file = Select-File -Prompt "Choose file to calculate checksum" -ShowFileInfo
            if (-not $file) { Write-Host "No file selected." -ForegroundColor Yellow; Start-Sleep -Milliseconds 700; continue }

            Add-RecentFile -FilePath $file

            $alg = Select-AlgorithmMenu -Prompt "Choose hash algorithm" -Default "SHA256"
            if (-not $alg) { Write-Host "Cancelled algorithm selection." -ForegroundColor DarkGray; Start-Sleep -Milliseconds 700; continue }

            Write-LogMessage -Message ("User requested checksum for {0} using {1}" -f $file, $alg) -Level INFO
            
            try {
                $res = Get-FileChecksumEx -Path $file -Algorithm $alg -ShowProgress
                
                if (-not $res) {
                    # Error already displayed by Get-FileChecksumEx
                    Read-Host "Press Enter to continue..."
                    continue
                }
                
                $fileSize = Format-FileSize -Bytes $res.Length
            Write-Host ""
            Write-Host ("File: {0} ({1})" -f (Split-Path -Leaf $file), $fileSize) -ForegroundColor Cyan
            Write-Host ("Checksum ({0}): {1}" -f $res.Algorithm, $res.Checksum) -ForegroundColor Green
            Write-Host ("Time elapsed: {0:N2} seconds" -f $res.Elapsed.TotalSeconds) -ForegroundColor DarkGray

            if ($Global:Settings.AutoCopyToClipboard) {
                if (Copy-ToClipboard -Text $res.Checksum) {
                    Write-Host "Checksum automatically copied to clipboard (preference enabled)." -ForegroundColor Yellow
                    Write-LogMessage -Message "Checksum copied to clipboard automatically" -Level INFO
                } else {
                    Write-Host "Auto-copy failed (see verbose)." -ForegroundColor Red
                    Write-LogMessage -Message "Auto-copy failed" -Level WARN
                }
            }

            Write-Host ""
            Write-Host "Actions: (C)opy to Clipboard  (F)ile quick-save  (M)etadata save  (N)one"
            $action = Read-Host "Choose an action (C/F/M/N) [N]"

            switch (($action).ToUpper()) {
                'C' {
                    if (Copy-ToClipboard -Text $res.Checksum) {
                        Write-Host "Checksum copied to clipboard." -ForegroundColor Yellow
                        Write-LogMessage -Message "Checksum copied to clipboard by user" -Level INFO
                    } else {
                        Write-Host "Copy to clipboard failed (see verbose)." -ForegroundColor Red
                        Write-LogMessage -Message "User copy to clipboard failed" -Level WARN
                    }
                }
                'F' {
                    $dir = Split-Path -Parent $file; $base = [IO.Path]::GetFileName($file)
                    $suffix = if ($Global:Settings.IncludeUsernameInMetadata) { ".$($env:USERNAME)" } else { "" }
                    $out = Join-Path -Path $dir -ChildPath ("{0}.{1}{2}.txt" -f $base, $res.Algorithm, $suffix)
                    if (Save-ChecksumQuick -TargetPath $out -Checksum $res.Checksum) {
                        Write-Host "Quick-saved checksum to: $out" -ForegroundColor Yellow
                        Write-LogMessage -Message ("Quick-saved checksum to {0}" -f $out) -Level INFO
                    } else { Write-Host "Quick-save failed." -ForegroundColor Red }
                }
                'M' {
                    $dir = Split-Path -Parent $file; $base = [IO.Path]::GetFileName($file)
                    $suffix = if ($Global:Settings.IncludeUsernameInMetadata) { ".$($env:USERNAME)" } else { "" }
                    $out = Join-Path -Path $dir -ChildPath ("{0}.{1}{2}.txt" -f $base, $res.Algorithm, $suffix)
                    if (Save-ChecksumWithMetadata -TargetPath $out -Checksum $res.Checksum -Algorithm $res.Algorithm -FilePath $res.Path) {
                        Write-Host "Saved checksum with metadata to: $out" -ForegroundColor Yellow
                        Write-LogMessage -Message ("Saved checksum with metadata to {0}" -f $out) -Level INFO
                    } else { Write-Host "Save with metadata failed." -ForegroundColor Red }
                }
                default { Write-Host "No action taken." -ForegroundColor DarkGray }
            }

            Read-Host "Press Enter to continue..."
            } catch {
                Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
                Write-LogMessage -Message ("Checksum calculation failed: {0}" -f $_.Exception.Message) -Level ERROR
                Read-Host "Press Enter to continue..."
            }
        }

        '2' {
            # Verify checksum (auto-detect algorithm)
            $file = Select-File -Prompt "Choose file to verify checksum" -ShowFileInfo
            if (-not $file) { Write-Host "No file selected." -ForegroundColor Yellow; Start-Sleep -Milliseconds 700; continue }

            Add-RecentFile -FilePath $file

            Write-Host ""
            Write-Host "Searching for checksum files in directory..." -ForegroundColor DarkGray

            # Auto-discover checksum files
            $discoveredFiles = @(Find-ChecksumFiles -TargetFilePath $file)
            $inputValue = $null

            if ($discoveredFiles -and $discoveredFiles.Count -gt 0) {
                Write-Host ""
                Write-Host "Found checksum file(s) in the same directory:" -ForegroundColor Cyan
                for ($i = 0; $i -lt $discoveredFiles.Count; $i++) {
                    $df = $discoveredFiles[$i]
                    $algHint = if ($df.Algorithm) { " ({0})" -f $df.Algorithm } else { "" }
                    Write-Host ("  [{0}] {1}{2}" -f ($i+1), $df.Name, $algHint) -ForegroundColor White
                }
                Write-Host ""
                Write-Host "Options: 1-$($discoveredFiles.Count)=Use file, P=Paste checksum, F=File picker, [Enter]=Use #1" -ForegroundColor DarkGray
                $autoChoice = Read-Host "Your choice"
                
                if ([string]::IsNullOrWhiteSpace($autoChoice)) {
                    # Default to first discovered file
                    $inputValue = $discoveredFiles[0].Path
                    Write-Host ("Using: {0}" -f $discoveredFiles[0].Name) -ForegroundColor Green
                } elseif ($autoChoice -match '^[0-9]+$') {
                    $idx = [int]$autoChoice - 1
                    if ($idx -ge 0 -and $idx -lt $discoveredFiles.Count) {
                        $inputValue = $discoveredFiles[$idx].Path
                        Write-Host ("Using: {0}" -f $discoveredFiles[$idx].Name) -ForegroundColor Green
                    } else {
                        Write-Host "Invalid selection." -ForegroundColor Yellow
                        Start-Sleep -Milliseconds 700
                        continue
                    }
                } elseif ($autoChoice.ToUpper() -eq 'F') {
                    $chkFile = Select-File -Prompt "Select checksum file to parse"
                    if (-not $chkFile) { Write-Host "No checksum file selected." -ForegroundColor Yellow; Start-Sleep -Milliseconds 700; continue }
                    $inputValue = $chkFile
                } elseif ($autoChoice.ToUpper() -eq 'P') {
                    $inputValue = Read-Host "Enter expected checksum (paste)"
                    if (-not $inputValue) { Write-Host "No checksum entered." -ForegroundColor Yellow; Start-Sleep -Milliseconds 700; continue }
                } else {
                    # Treat as pasted checksum
                    $inputValue = $autoChoice
                }
            } elseif ($Global:Settings.UseFileDialog) {
                # No checksum files found - use traditional prompt
                Write-Host "No checksum files found in directory." -ForegroundColor DarkGray
                Write-Host ""
                # GUI/file-dialog mode: explicit choice between paste or pick checksum file
                $choice = Read-Host "Provide expected checksum by (P)aste or (F)ile? (P/F) [P]"
                if ([string]::IsNullOrWhiteSpace($choice)) { $choice = 'P' }
                $choice = $choice.Substring(0,1).ToUpper()

                if ($choice -eq 'F') {
                    $chkFile = Select-File -Prompt "Select checksum file to parse"
                    if (-not $chkFile) { Write-Host "No checksum file selected." -ForegroundColor Yellow; Start-Sleep -Milliseconds 700; continue }
                    $inputValue = $chkFile
                } else {
                    $inputValue = Read-Host "Enter expected checksum (paste) or a checksum file path"
                    if (-not $inputValue) { Write-Host "No checksum entered." -ForegroundColor Yellow; Start-Sleep -Milliseconds 700; continue }
                }
            } else {
                # CLI mode: single prompt - user may paste checksum OR type a checksum-file path
                $inputValue = Read-Host "Enter expected checksum or full path to a checksum file (leave blank to cancel)"
                if (-not $inputValue) { Write-Host "No checksum entered." -ForegroundColor Yellow; Start-Sleep -Milliseconds 700; continue }
            }

            Write-LogMessage -Message ("User requested verify (auto-detect) for {0}" -f $file) -Level INFO
            try {
                $res = Test-FileChecksum -Path $file -ExpectedChecksumOrFile $inputValue -AutoDetectAlgorithm -ShowProgress
            } catch {
                Write-Host ""
                # Check if it's a file access error
                if ($_.Exception.Message -match "being used by another process") {
                    Write-Host "Error: Cannot access file - it is currently open in another program." -ForegroundColor Red
                    Write-Host "       Please close the file and try again." -ForegroundColor Yellow
                } elseif ($_.Exception.Message -match "Access.*denied") {
                    Write-Host "Error: Access denied - insufficient permissions to read the file." -ForegroundColor Red
                    Write-Host "       Try running PowerShell as Administrator." -ForegroundColor Yellow
                } elseif ($_.Exception.Message -match "Failed to compute checksum") {
                    Write-Host "Error: Failed to compute checksum." -ForegroundColor Red
                    Write-Host "       $($_.Exception.Message)" -ForegroundColor Yellow
                } else {
                    Write-Host "Verification Failed" -ForegroundColor Red
                    Write-Host ("Error: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
                    Write-Host ""
                    Write-Host "Possible solutions:" -ForegroundColor Cyan
                    Write-Host "  - Ensure the checksum file is in a supported format" -ForegroundColor White
                    Write-Host "  - Try specifying the algorithm manually (option 3)" -ForegroundColor White
                    Write-Host "  - Check that the checksum value is valid hexadecimal" -ForegroundColor White
                }
                Write-Host ""
                Write-LogMessage -Message ("Verification error: {0}" -f $_.Exception.Message) -Level ERROR
                Read-Host "Press Enter to continue..."
                continue
            }

            if ($res.Match) {
                Write-Host ""
                Write-Host "[OK] MATCH - Checksum Verified Successfully!" -ForegroundColor Green
                Write-Host ("  Algorithm: {0}" -f $res.Algorithm) -ForegroundColor White
                Write-Host ("  Checksum:  {0}" -f $res.Calculated) -ForegroundColor DarkGray
                Write-Host ("  Time:      {0:N2} seconds" -f $res.Elapsed.TotalSeconds) -ForegroundColor DarkGray
                Write-Host ""
                if ($Global:Settings.AutoCopyToClipboard) {
                    if (Copy-ToClipboard -Text $res.Calculated) { Write-Host "Checksum copied to clipboard (auto-copy enabled)." -ForegroundColor Yellow } else { Write-Host "Auto-copy failed." -ForegroundColor Red }
                } else {
                    $copy = Read-Host "Copy calculated checksum to clipboard? (Y/N) [N]"
                    if ($copy -match '^[yY]') { if (Copy-ToClipboard -Text $res.Calculated) { Write-Host "Copied." -ForegroundColor Yellow } else { Write-Host "Copy failed." -ForegroundColor Red } }
                }
            } else {
                Write-Host ""
                Write-Host "[FAIL] MISMATCH - Checksum Does Not Match!" -ForegroundColor Red
                Write-Host ("  Expected:   {0}" -f $res.ExpectedChecksum) -ForegroundColor Yellow
                Write-Host ("  Calculated: {0}" -f $res.Calculated) -ForegroundColor Red
                Write-Host ("  Time:       {0:N2} seconds" -f $res.Elapsed.TotalSeconds) -ForegroundColor DarkGray
                Write-Host ""
                Write-Host "Actions: (C)opy to Clipboard  (F)ile quick-save  (M)etadata save  (N)one"
                $save = Read-Host "Choose an action (C/F/M/N) [N]"
                switch (($save).ToUpper()) {
                    'C' { if (Copy-ToClipboard -Text $res.Calculated) { Write-Host "Copied to clipboard." -ForegroundColor Yellow } else { Write-Host "Copy failed." -ForegroundColor Red } }
                    'F' {
                        $dir = Split-Path -Parent $file; $base = [IO.Path]::GetFileName($file)
                        $suffix = if ($Global:Settings.IncludeUsernameInMetadata) { ".$($env:USERNAME)" } else { "" }
                        $out = Join-Path -Path $dir -ChildPath ("{0}.{1}{2}.txt" -f $base, $res.Algorithm, $suffix)
                        if (Save-ChecksumQuick -TargetPath $out -Checksum $res.Calculated) { Write-Host "Saved: $out" -ForegroundColor Yellow } else { Write-Host "Save failed." -ForegroundColor Red }
                    }
                    'M' {
                        $dir = Split-Path -Parent $file; $base = [IO.Path]::GetFileName($file)
                        $suffix = if ($Global:Settings.IncludeUsernameInMetadata) { ".$($env:USERNAME)" } else { "" }
                        $out = Join-Path -Path $dir -ChildPath ("{0}.{1}{2}.txt" -f $base, $res.Algorithm, $suffix)
                        if (Save-ChecksumWithMetadata -TargetPath $out -Checksum $res.Calculated -Algorithm $res.Algorithm -FilePath $res.Path) { Write-Host "Saved: $out" -ForegroundColor Yellow } else { Write-Host "Save failed." -ForegroundColor Red }
                    }
                    default { Write-Host "Not saved." -ForegroundColor DarkGray }
                }
            }

            Read-Host "Press Enter to continue..."
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

            # Auto-discover checksum files
            $discoveredFiles = Find-ChecksumFiles -TargetFilePath $file
            $inputValue = $null

            if ($discoveredFiles -and $discoveredFiles.Count -gt 0) {
                Write-Host ""
                Write-Host "Found checksum file(s) in the same directory:" -ForegroundColor Cyan
                for ($i = 0; $i -lt $discoveredFiles.Count; $i++) {
                    $df = $discoveredFiles[$i]
                    $algHint = if ($df.Algorithm) { " ({0})" -f $df.Algorithm } else { "" }
                    Write-Host ("  [{0}] {1}{2}" -f ($i+1), $df.Name, $algHint) -ForegroundColor White
                }
                Write-Host ""
                Write-Host "Options: 1-$($discoveredFiles.Count)=Use file, P=Paste checksum, F=File picker, [Enter]=Use #1" -ForegroundColor DarkGray
                $autoChoice = Read-Host "Your choice"
                
                if ([string]::IsNullOrWhiteSpace($autoChoice)) {
                    # Default to first discovered file
                    $inputValue = $discoveredFiles[0].Path
                    Write-Host ("Using: {0}" -f $discoveredFiles[0].Name) -ForegroundColor Green
                } elseif ($autoChoice -match '^[0-9]+$') {
                    $idx = [int]$autoChoice - 1
                    if ($idx -ge 0 -and $idx -lt $discoveredFiles.Count) {
                        $inputValue = $discoveredFiles[$idx].Path
                        Write-Host ("Using: {0}" -f $discoveredFiles[$idx].Name) -ForegroundColor Green
                    } else {
                        Write-Host "Invalid selection." -ForegroundColor Yellow
                        Start-Sleep -Milliseconds 700
                        continue
                    }
                } elseif ($autoChoice.ToUpper() -eq 'F') {
                    $chkFile = Select-File -Prompt "Select checksum file to parse"
                    if (-not $chkFile) { Write-Host "No checksum file selected." -ForegroundColor Yellow; Start-Sleep -Milliseconds 700; continue }
                    $inputValue = $chkFile
                } elseif ($autoChoice.ToUpper() -eq 'P') {
                    $inputValue = Read-Host "Enter expected checksum (paste)"
                    if (-not $inputValue) { Write-Host "No checksum entered." -ForegroundColor Yellow; Start-Sleep -Milliseconds 700; continue }
                } else {
                    # Treat as pasted checksum
                    $inputValue = $autoChoice
                }
            } elseif ($Global:Settings.UseFileDialog) {
                # No checksum files found - use traditional prompt
                Write-Host "No checksum files found in directory." -ForegroundColor DarkGray
                Write-Host ""
                $choice = Read-Host "Provide expected checksum by (P)aste or (F)ile? (P/F) [P]"
                if ([string]::IsNullOrWhiteSpace($choice)) { $choice = 'P' }
                $choice = $choice.Substring(0,1).ToUpper()

                if ($choice -eq 'F') {
                    $chkFile = Select-File -Prompt "Select checksum file to parse"
                    if (-not $chkFile) { Write-Host "No checksum file selected." -ForegroundColor Yellow; Start-Sleep -Milliseconds 700; continue }
                    $inputValue = $chkFile
                } else {
                    $inputValue = Read-Host "Enter expected checksum (paste) or a checksum file path"
                    if (-not $inputValue) { Write-Host "No checksum entered." -ForegroundColor Yellow; Start-Sleep -Milliseconds 700; continue }
                }
            } else {
                # CLI mode: single prompt (paste checksum or type path)
                $inputValue = Read-Host "Enter expected checksum or full path to a checksum file (leave blank to cancel)"
                if (-not $inputValue) { Write-Host "No checksum entered." -ForegroundColor Yellow; Start-Sleep -Milliseconds 700; continue }
            }

            Write-LogMessage -Message ("User requested verify (explicit {0}) for {1}" -f $alg, $file) -Level INFO
            try {
                $res = Test-FileChecksum -Path $file -ExpectedChecksumOrFile $inputValue -Algorithm $alg -ShowProgress
            } catch {
                Write-Host ""
                # Check if it's a file access error
                if ($_.Exception.Message -match "being used by another process") {
                    Write-Host "Error: Cannot access file - it is currently open in another program." -ForegroundColor Red
                    Write-Host "       Please close the file and try again." -ForegroundColor Yellow
                } elseif ($_.Exception.Message -match "Access.*denied") {
                    Write-Host "Error: Access denied - insufficient permissions to read the file." -ForegroundColor Red
                    Write-Host "       Try running PowerShell as Administrator." -ForegroundColor Yellow
                } elseif ($_.Exception.Message -match "Failed to compute checksum") {
                    Write-Host "Error: Failed to compute checksum." -ForegroundColor Red
                    Write-Host "       $($_.Exception.Message)" -ForegroundColor Yellow
                } else {
                    Write-Host "Verification Failed" -ForegroundColor Red
                    Write-Host ("Error: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
                    Write-Host ""
                    Write-Host "Possible solutions:" -ForegroundColor Cyan
                    Write-Host "  - Ensure the checksum is valid hexadecimal" -ForegroundColor White
                    Write-Host "  - Verify the algorithm matches the checksum" -ForegroundColor White
                }
                Write-Host ""
                Write-LogMessage -Message ("Verification error: {0}" -f $_.Exception.Message) -Level ERROR
                Read-Host "Press Enter to continue..."
                continue
            }

            if ($res.Match) {
                Write-Host ""
                Write-Host "[OK] MATCH - Checksum Verified Successfully!" -ForegroundColor Green
                Write-Host ("  Algorithm: {0}" -f $res.Algorithm) -ForegroundColor White
                Write-Host ("  Checksum:  {0}" -f $res.Calculated) -ForegroundColor DarkGray
            } else {
                Write-Host ""
                Write-Host "[FAIL] MISMATCH - Checksum Does Not Match!" -ForegroundColor Red
                Write-Host ("  Expected:  {0}" -f $res.ExpectedChecksum) -ForegroundColor Yellow
                Write-Host ("  Calculated: {0}" -f $res.Calculated) -ForegroundColor Red
            }
            Read-Host "Press Enter to continue..."
        }

        '4' {
            # Recent files
            $file = Show-RecentFilesMenu
            if (-not $file) { continue }
            
            # Quick action menu for recent file
            Clear-Host
            Write-Host ("Selected: {0}" -f (Split-Path -Leaf $file)) -ForegroundColor Cyan
            Write-Host ("Path: {0}" -f $file) -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "1) Calculate checksum"
            Write-Host "2) Verify checksum (auto-detect)"
            Write-Host "3) Verify checksum (specify algorithm)"
            Write-Host "0) Cancel"
            Write-Host ""
            Write-Host "Press ESC to cancel" -ForegroundColor DarkGray
            Write-Host "Choose action (0-3):"
            
            $action = Read-SingleKey
            try { $action = [string]$action; $action = $action.Trim() } catch {}
            
            if ([string]::IsNullOrWhiteSpace($action) -or $action -eq '0' -or $action -eq [char]27 -or $action -match '^\x1B' -or $action -eq '4') {
                continue
            }
            
            if ($action -eq '1') {
                $alg = Select-AlgorithmMenu -Prompt "Choose hash algorithm" -Default "SHA256"
                if (-not $alg) { Write-Host "Cancelled." -ForegroundColor DarkGray; Start-Sleep -Milliseconds 700; continue }
                
                Write-LogMessage -Message ("User requested checksum for recent file {0} using {1}" -f $file, $alg) -Level INFO
                
                try {
                    $res = Get-FileChecksumEx -Path $file -Algorithm $alg -ShowProgress
                    
                    if (-not $res) {
                        # Error already displayed by Get-FileChecksumEx
                        Read-Host "Press Enter to continue..."
                        continue
                    }
                    
                    $fileSize = Format-FileSize -Bytes $res.Length
                    Write-Host ""
                    Write-Host ("File: {0} ({1})" -f (Split-Path -Leaf $file), $fileSize) -ForegroundColor Cyan
                    Write-Host ("Checksum ({0}): {1}" -f $res.Algorithm, $res.Checksum) -ForegroundColor Green
                    Write-Host ("Time elapsed: {0:N2} seconds" -f $res.Elapsed.TotalSeconds) -ForegroundColor DarkGray
                    
                    if ($Global:Settings.AutoCopyToClipboard) {
                        if (Copy-ToClipboard -Text $res.Checksum) {
                            Write-Host "Checksum automatically copied to clipboard." -ForegroundColor Yellow
                        }
                    }
                    
                    Read-Host "Press Enter to continue..."
                } catch {
                    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
                    Write-LogMessage -Message ("Checksum calculation failed: {0}" -f $_.Exception.Message) -Level ERROR
                    Read-Host "Press Enter to continue..."
                }
            } elseif ($action -eq '2' -or $action -eq '3') {
                $alg = $null
                if ($action -eq '3') {
                    $alg = Select-AlgorithmMenu -Prompt "Choose hash algorithm for verification" -Default "SHA256"
                    if (-not $alg) { Write-Host "Cancelled." -ForegroundColor DarkGray; Start-Sleep -Milliseconds 700; continue }
                }
                
                # Auto-discover checksum files
                $discoveredFiles = Find-ChecksumFiles -TargetFilePath $file
                $inputValue = $null

                if ($discoveredFiles -and $discoveredFiles.Count -gt 0) {
                    Write-Host ""
                    Write-Host "Found checksum file(s) in the same directory:" -ForegroundColor Cyan
                    for ($i = 0; $i -lt $discoveredFiles.Count; $i++) {
                        $df = $discoveredFiles[$i]
                        $algHint = if ($df.Algorithm) { " ({0})" -f $df.Algorithm } else { "" }
                        Write-Host ("  [{0}] {1}{2}" -f ($i+1), $df.Name, $algHint) -ForegroundColor White
                    }
                    Write-Host ""
                    Write-Host "Options: 1-$($discoveredFiles.Count)=Use file, P=Paste checksum, [Enter]=Use #1" -ForegroundColor DarkGray
                    $autoChoice = Read-Host "Your choice"
                    
                    if ([string]::IsNullOrWhiteSpace($autoChoice)) {
                        $inputValue = $discoveredFiles[0].Path
                        Write-Host ("Using: {0}" -f $discoveredFiles[0].Name) -ForegroundColor Green
                    } elseif ($autoChoice -match '^[0-9]+$') {
                        $idx = [int]$autoChoice - 1
                        if ($idx -ge 0 -and $idx -lt $discoveredFiles.Count) {
                            $inputValue = $discoveredFiles[$idx].Path
                            Write-Host ("Using: {0}" -f $discoveredFiles[$idx].Name) -ForegroundColor Green
                        } else {
                            Write-Host "Invalid selection." -ForegroundColor Yellow
                            Start-Sleep -Milliseconds 700
                            continue
                        }
                    } else {
                        # Treat as pasted checksum
                        $inputValue = $autoChoice
                    }
                } else {
                    $inputValue = Read-Host "Enter expected checksum or path to checksum file"
                    if (-not $inputValue) { Write-Host "No checksum entered." -ForegroundColor Yellow; Start-Sleep -Milliseconds 700; continue }
                }
                
                try {
                    if ($alg) {
                        $res = Test-FileChecksum -Path $file -ExpectedChecksumOrFile $inputValue -Algorithm $alg -ShowProgress
                    } else {
                        $res = Test-FileChecksum -Path $file -ExpectedChecksumOrFile $inputValue -AutoDetectAlgorithm -ShowProgress
                    }
                    
                    if ($res.Match) {
                        Write-Host ""
                        Write-Host "[OK] MATCH - Checksum Verified Successfully!" -ForegroundColor Green
                        Write-Host ("  Algorithm: {0}" -f $res.Algorithm) -ForegroundColor White
                        Write-Host ("  Checksum:  {0}" -f $res.Calculated) -ForegroundColor DarkGray
                        Write-Host ("  Time:      {0:N2} seconds" -f $res.Elapsed.TotalSeconds) -ForegroundColor DarkGray
                    } else {
                        Write-Host ""
                        Write-Host "[FAIL] MISMATCH - Checksum Does Not Match!" -ForegroundColor Red
                        Write-Host ("  Expected:   {0}" -f $res.ExpectedChecksum) -ForegroundColor Yellow
                        Write-Host ("  Calculated: {0}" -f $res.Calculated) -ForegroundColor Red
                        Write-Host ("  Time:       {0:N2} seconds" -f $res.Elapsed.TotalSeconds) -ForegroundColor DarkGray
                    }
                } catch {
                    Write-Host ""
                    # Check if it's a file access error
                    if ($_.Exception.Message -match "being used by another process") {
                        Write-Host "Error: Cannot access file - it is currently open in another program." -ForegroundColor Red
                        Write-Host "       Please close the file and try again." -ForegroundColor Yellow
                    } elseif ($_.Exception.Message -match "Access.*denied") {
                        Write-Host "Error: Access denied - insufficient permissions to read the file." -ForegroundColor Red
                        Write-Host "       Try running PowerShell as Administrator." -ForegroundColor Yellow
                    } else {
                        Write-Host "Verification failed: $($_.Exception.Message)" -ForegroundColor Red
                    }
                    Write-Host ""
                }
                
                Read-Host "Press Enter to continue..."
            }
        }

        '5' {
            $inPrefs = $true
            while ($inPrefs) {
                Clear-Host
                Write-Host "Preferences" -ForegroundColor Cyan
                $prefAutoCopy = if ($Global:Settings.AutoCopyToClipboard) { 'On' } else { 'Off' }
                $prefInterval = $Global:Settings.ProgressUpdateIntervalMs
                $prefMinDelta = $Global:Settings.ProgressMinDeltaPercent
                $prefFileDlg = if ($Global:Settings.UseFileDialog) { 'GUI (File Explorer)' } else { 'CLI (Type/Paste Path)' }
                $prefLogDir = $Global:Settings.LogDirectory
                $prefWarningGB = $Global:Settings.LargeFileSizeWarningGB

                Write-Host ("1) AutoCopyToClipboard: {0}" -f $prefAutoCopy)
                Write-Host ("2) Progress update interval (ms): {0}" -f $prefInterval)
                Write-Host ("3) Progress minimum delta percent: {0}" -f $prefMinDelta)
                Write-Host ("4) File selection method: {0}" -f $prefFileDlg)
                Write-Host ("5) Large file warning threshold (GB): {0:N1}" -f $prefWarningGB)
                Write-Host ("6) Set log directory (current: {0})" -f $prefLogDir)
                Write-Host ("7) View recent log entries")
                Write-Host ("0) Back to main menu")
                Write-Host ""
                Write-Host "Press ESC to cancel" -ForegroundColor DarkGray
                Write-Host "Press the number key to change a setting (changes are saved immediately)."

                $prefKey = Read-SingleKey
                try { $prefKey = [string]$prefKey; $prefKey = $prefKey.Trim().ToUpper() } catch {}
                
                # Check for ESC key
                if ($prefKey -eq [char]27 -or $prefKey -match '^\x1B') {
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
                                if ($d -ge 0) {
                                    $Global:Settings.ProgressMinDeltaPercent = $d
                                    if (Save-Settings -Settings $Global:Settings) {
                                        Write-Host ("Set ProgressMinDeltaPercent to {0}" -f $Global:Settings.ProgressMinDeltaPercent) -ForegroundColor Yellow
                                        Write-LogMessage -Message ("ProgressMinDeltaPercent set to {0}" -f $d) -Level INFO
                                    } else { Write-Host "Failed to save settings." -ForegroundColor Red }
                                } else { Write-Host "Must be >= 0. No change." -ForegroundColor Yellow }
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
                                if ($gb -gt 0) {
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
                            try {
                                Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
                                $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
                                $dlg.Description = "Select folder to store logs"
                                if (Test-Path $Global:Settings.LogDirectory) { $dlg.SelectedPath = $Global:Settings.LogDirectory }
                                if ($dlg.ShowDialog() -eq 'OK') { $new = $dlg.SelectedPath }
                            } catch {
                                Write-LogMessage -Message ("Folder dialog failed: {0}" -f $_.Exception.Message) -Level WARN
                                $new = $null
                            }
                        } else {
                            $userInput = Read-Host ("Enter log directory full path (leave blank to cancel) [Current: {0}]" -f $Global:Settings.LogDirectory)
                            if ($userInput) { $new = $userInput.Trim().Trim('"','''') } else { $new = $null }
                        }

                        if ($new) {
                            try { if (-not (Test-Path -Path $new)) { New-Item -ItemType Directory -Path $new -Force | Out-Null } } catch {}
                            if (Test-Path -Path $new) {
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
                        Read-Host "Press Enter to continue..."
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
                        Clear-Host
                        Write-Host "All Stored Data" -ForegroundColor Cyan
                        Write-Host ("=" * 70) -ForegroundColor DarkGray
                        Write-Host ""
                        Write-Host "Settings:" -ForegroundColor Yellow
                        $Global:Settings | ConvertTo-Json -Depth 5 | Write-Host -ForegroundColor White
                        Write-Host ""
                        Read-Host "Press Enter to continue..."
                    }
                    '4' {
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
                    '5' {
                        $confirm = Read-Host "Clear all log files? This cannot be undone. (Y/N) [N]"
                        if ($confirm -match '^[yY]') {
                            try {
                                if (Test-Path $Global:LogFile) { Remove-Item -Path $Global:LogFile -Force }
                                for ($i = 1; $i -le $Global:MaxLogArchives; $i++) {
                                    $archiveLog = "$Global:LogFile.$i.log"
                                    if (Test-Path $archiveLog) { Remove-Item -Path $archiveLog -Force }
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
                    '6' {
                        try {
                            $exportData = @{
                                ExportDate = (Get-Date).ToString("o")
                                Settings = $Global:Settings
                                LogFile = $Global:LogFile
                                ScriptVersion = $ScriptVersion
                            }
                            $json = $exportData | ConvertTo-Json -Depth 10
                            $exportPath = Join-Path -Path ([Environment]::GetFolderPath('Desktop')) -ChildPath ("ChecksumTool_DataExport_{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
                            [System.IO.File]::WriteAllText($exportPath, $json, [System.Text.Encoding]::UTF8)
                            Write-Host ("Data exported to: {0}" -f $exportPath) -ForegroundColor Green
                            Write-LogMessage -Message "User exported all data" -Level INFO
                        } catch {
                            Write-Host "Export failed: $($_.Exception.Message)" -ForegroundColor Red
                        }
                        Start-Sleep -Milliseconds 1500
                    }
                    '7' {
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
                                if (Test-Path $settingsPath) { Remove-Item -Path $settingsPath -Force }
                                
                                # Delete logs
                                if (Test-Path $Global:LogFile) { Remove-Item -Path $Global:LogFile -Force }
                                for ($i = 1; $i -le $Global:MaxLogArchives; $i++) {
                                    $archiveLog = "$Global:LogFile.$i.log"
                                    if (Test-Path $archiveLog) { Remove-Item -Path $archiveLog -Force }
                                }
                                
                                Write-Host ""
                                Write-Host "All data deleted. The tool will now exit." -ForegroundColor Green
                                Start-Sleep -Seconds 2
                                exit
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
            exit
        }

        default { Write-Host "Invalid option" -ForegroundColor Red; Start-Sleep -Milliseconds 700 }
    }
}
#endregion
