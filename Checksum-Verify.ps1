<#
.SYNOPSIS
    Checksum Tool with persistent settings and single-key main-menu navigation.

.DESCRIPTION
    - Streaming checksum calculation with progress (MD5/SHA1/SHA256/SHA384/SHA512)
    - Stable throttled Write-Progress and Int64-safe math for large files
    - Quick-save and metadata-save functions (fast file writes)
    - Clipboard copy (Set-Clipboard preferred, fallback to Windows.Forms clipboard)
    - Algorithm selection menu
    - Settings persisted to %LOCALAPPDATA%\checksum-tool\settings.json
    - Main menu accepts single-key input (no Enter required)

.NOTES
    - Author: Ruben Draaisma
    - Version: 1.0.1
    - Tested on: Windows 11 24H2
    - Tested with: PowerShell ISE, PowerShell 5.1 and PowerShell 7
#>

#region Settings persistence (robust, first-run safe)

function Get-SettingsFilePath {
    try {
        # Safer: use Environment API (works even when $env:LOCALAPPDATA isn't set)
        $localApp = [Environment]::GetFolderPath('LocalApplicationData')
        if (-not $localApp -or [string]::IsNullOrWhiteSpace($localApp)) {
            # Fallback to TEMP (guaranteed)
            $localApp = $env:TEMP
        }
    } catch {
        $localApp = $env:TEMP
    }

    $dir = Join-Path -Path $localApp -ChildPath 'checksum-tool'

    # Ensure directory exists (best-effort)
    if (-not (Test-Path -LiteralPath $dir)) {
        try { New-Item -ItemType Directory -Path $dir -Force | Out-Null } catch {}
    }

    return Join-Path -Path $dir -ChildPath 'settings.json'
}

function Get-DefaultSettings {
    # Return a PSCustomObject so callers can reliably use dot-property access.
    return [PSCustomObject]@{ 
        AutoCopyToClipboard       = $false
        ProgressUpdateIntervalMs  = 200
        ProgressMinDeltaPercent   = 0.25
    }
}

function Save-Settings {
    param([Parameter(Mandatory=$true)] $Settings)
    $path = Get-SettingsFilePath

    try {
        # Ensure folder exists before writing (defensive)
        $dir = Split-Path -Parent $path
        if (-not (Test-Path -LiteralPath $dir)) {
            try { New-Item -ItemType Directory -Path $dir -Force | Out-Null } catch {}
        }

        # Convert and write atomically (best-effort)
        $json = $Settings | ConvertTo-Json -Depth 3 -ErrorAction Stop
        # Use Set-Content with UTF8 (works reliably across PS editions)
        $json | Set-Content -LiteralPath $path -Encoding UTF8 -Force
        return $true
    } catch {
        Write-Verbose ("Failed to save settings to '{0}': {1}" -f $path, $_.Exception.Message)
        return $false
    }
}

function Normalize-SettingsObject {
    param([Parameter(Mandatory=$true)] $Obj)

    # Ensure PSCustomObject
    if (-not ($Obj -is [PSCustomObject])) {
        try { $Obj = [PSCustomObject]$Obj } catch { $Obj = [PSCustomObject]@{} }
    }

    # Apply defaults for missing properties
    $defaults = Get-DefaultSettings
    foreach ($prop in $defaults.PSObject.Properties.Name) {
        if (-not $Obj.PSObject.Properties.Name -contains $prop) {
            $Obj | Add-Member -MemberType NoteProperty -Name $prop -Value ($defaults.$prop)
        }
    }

    # Coerce types & validate values (best-effort)
    try {
        $tmp = 0
        if (-not [int]::TryParse("$($Obj.ProgressUpdateIntervalMs)", [ref]$tmp) -or $tmp -le 0) {
            $Obj.ProgressUpdateIntervalMs = $defaults.ProgressUpdateIntervalMs
        } else {
            $Obj.ProgressUpdateIntervalMs = [int]$tmp
        }
    } catch { $Obj.ProgressUpdateIntervalMs = $defaults.ProgressUpdateIntervalMs }

    try {
        $d = [double]::Parse("$($Obj.ProgressMinDeltaPercent)") 2>$null
        if ($d -lt 0) { $Obj.ProgressMinDeltaPercent = $defaults.ProgressMinDeltaPercent } else { $Obj.ProgressMinDeltaPercent = [double]$d }
    } catch { $Obj.ProgressMinDeltaPercent = $defaults.ProgressMinDeltaPercent }

    # Ensure boolean for AutoCopyToClipboard
    try {
        $b = $Obj.AutoCopyToClipboard
        if ($b -is [string]) {
            $Obj.AutoCopyToClipboard = $b -match '^(1|true|yes)$'
        } else {
            $Obj.AutoCopyToClipboard = [bool]$b
        }
    } catch { $Obj.AutoCopyToClipboard = $defaults.AutoCopyToClipboard }

    return $Obj
}

function Load-Settings {
    $path = Get-SettingsFilePath

    # If file doesn't exist -> create defaults and return them
    if (-not (Test-Path -LiteralPath $path)) {
        $defaults = Get-DefaultSettings
        Save-Settings -Settings $defaults | Out-Null
        return [PSCustomObject]$defaults
    }

    # File exists - try to read, handle empty or malformed JSON gracefully
    try {
        $json = Get-Content -LiteralPath $path -Raw -ErrorAction Stop

        if (-not $json -or $json.Trim().Length -eq 0) {
            # empty file: recreate defaults
            Write-Verbose "Settings file empty; recreating defaults."
            $defaults = Get-DefaultSettings
            Save-Settings -Settings $defaults | Out-Null
            return [PSCustomObject]$defaults
        }

        $o = $json | ConvertFrom-Json -ErrorAction Stop

        # Normalize (add missing keys and fix types)
        $o = Normalize-SettingsObject -Obj $o

        return $o
    } catch {
        # Something went wrong reading or parsing -> fallback to defaults and overwrite file
        Write-Verbose ("Failed to read/parse settings; recreating defaults: {0}" -f $_.Exception.Message)
        $defaults = Get-DefaultSettings
        Save-Settings -Settings $defaults | Out-Null
        return [PSCustomObject]$defaults
    }
}

# Load settings into global variable and ensure PSCustomObject
try {
    $loaded = Load-Settings
    if (-not $loaded) { $loaded = Get-DefaultSettings }
    $Global:Settings = Normalize-SettingsObject -Obj $loaded
} catch {
    Write-Verbose ("Unexpected error while loading settings; using defaults: {0}" -f $_.Exception.Message)
    $Global:Settings = Get-DefaultSettings
}

#endregion

#region Utility: Clipboard

function Copy-ToClipboard {
    param(
        [Parameter(Mandatory=$true)]
        [string] $Text
    )
    # Prefer Set-Clipboard
    if (Get-Command -Name Set-Clipboard -ErrorAction SilentlyContinue) {
        try {
            Set-Clipboard -Value $Text
            return $true
        } catch {
            Write-Verbose ("Set-Clipboard failed: {0}" -f $_.Exception.Message)
        }
    }

    # Fallback using Windows Forms (may require interactive desktop session)
    try {
        # Ensure assembly loaded
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
        [void][System.Windows.Forms.Clipboard]::SetText($Text)
        return $true
    } catch {
        Write-Verbose ("Fallback clipboard failed: {0}" -f $_.Exception.Message)
        return $false
    }
}

#endregion

#region Algorithm selection (menu)

function Select-AlgorithmMenu {
    param(
        [string] $Prompt = "Select algorithm",
        [string] $Default = "SHA256"
    )

    $map = @{
        '1' = 'MD5'
        '2' = 'SHA1'
        '3' = 'SHA256'
        '4' = 'SHA384'
        '5' = 'SHA512'
    }

    while ($true) {
        Write-Host ""
        Write-Host ("{0}:" -f $Prompt)
        Write-Host "  1) MD5"
        Write-Host "  2) SHA-1"
        Write-Host "  3) SHA-256"
        Write-Host "  4) SHA-384"
        Write-Host "  5) SHA-512"
        Write-Host "  6) Cancel / Back"

        $choice = Read-Host ("Choose an option (1-6) [Default: {0}]" -f $Default)

        if ([string]::IsNullOrWhiteSpace($choice)) {
            return $Default
        }
        if ($map.ContainsKey($choice)) {
            return $map[$choice]
        }
        if ($choice -eq '6') { return $null }

        Write-Host "Invalid choice, try again." -ForegroundColor Yellow
    }
}

#endregion

#region Core checksum functions (improved)

function Get-FileChecksumEx {
    [CmdletBinding(DefaultParameterSetName='ByPath')]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string] $Path,

        [Parameter(Mandatory=$true)]
        [ValidateSet('MD5','SHA1','SHA256','SHA384','SHA512')]
        [string] $Algorithm = 'SHA256',

        # Use an explicit arithmetic expression for compatibility (PowerShell 5.1)
        [Parameter(Mandatory=$false)]
        [int] $BufferSize = (4 * 1MB),

        [Parameter(Mandatory=$false)]
        [switch] $ShowProgress
    )

    begin {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            Throw "File not found: $Path"
        }
        if ($BufferSize -lt 4096) {
            Throw "BufferSize must be at least 4096 bytes."
        }
        # read progress settings from persisted settings
        $ProgressUpdateIntervalMs = [int]$Global:Settings.ProgressUpdateIntervalMs
        $ProgressMinDeltaPercent   = [double]$Global:Settings.ProgressMinDeltaPercent
        $progressId = 1
    }

    process {
        $fs = $null
        $hashAlgo = $null
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $hashAlgo = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm)
            if (-not $hashAlgo) { Throw "Unable to create hash algorithm '$Algorithm'." }

            $fs = [System.IO.File]::OpenRead($Path)
            $length = [int64]$fs.Length
            $buffer = New-Object byte[] $BufferSize
            $bytesRead = 0
            $totalRead = 0L

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

                        Write-Progress -Id $progressId `
                                       -Activity ("Calculating {0}" -f $Algorithm) `
                                       -Status ("{0:N2}% — {1} MB remaining of {2} MB. ETA: {3}s" -f $percent, $remainingMB, $totalMB, $etaSec) `
                                       -PercentComplete ([math]::Min(100, [math]::Round($percent, 2)))

                        $lastUpdate = $now
                        $lastPercent = $percent
                    }
                }
            }

            $hashAlgo.TransformFinalBlock($buffer, 0, 0) | Out-Null
            $checksumBytes = $hashAlgo.Hash
            $hex = -join ($checksumBytes | ForEach-Object { "{0:x2}" -f $_ })

            $sw.Stop()

            [PSCustomObject]@{
                Path      = (Get-Item -LiteralPath $Path).FullName
                Algorithm = $Algorithm
                Checksum  = $hex
                Length    = $length
                Elapsed   = $sw.Elapsed
            }

        } catch {
            Throw "Error computing checksum: $($_.Exception.Message)"
        } finally {
            if ($fs) { try { $fs.Close(); $fs.Dispose() } catch {} }
            if ($hashAlgo) { $hashAlgo.Dispose() }
            if ($ShowProgress) { Write-Progress -Id $progressId -Activity ("Calculating {0}" -f $Algorithm) -Completed }
        }
    }
}

function Get-ChecksumAlgorithmFromLength {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string] $Checksum
    )

    switch ($Checksum.Length) {
        32  { return 'MD5'    }
        40  { return 'SHA1'   }
        64  { return 'SHA256' }
        96  { return 'SHA384' }
        128 { return 'SHA512' }
        default {
            Write-Verbose ("Checksum length {0} not recognized." -f $Checksum.Length)
            return $null
        }
    }
}

function Test-FileChecksum {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string] $Path,

        [Parameter(Mandatory=$true, Position=1)]
        [ValidateNotNullOrEmpty()]
        [string] $ExpectedChecksum,

        [Parameter(Mandatory=$false)]
        [ValidateSet('MD5','SHA1','SHA256','SHA384','SHA512')]
        [string] $Algorithm,

        [Parameter(Mandatory=$false)]
        [switch] $AutoDetectAlgorithm,

        [Parameter(Mandatory=$false)]
        [switch] $ShowProgress,

        [Parameter(Mandatory=$false)]
        [switch] $SaveOnMismatch,   # save calculated checksum if mismatch

        [Parameter(Mandatory=$false)]
        [string] $OutputPath
    )

    if (-not $Algorithm) {
        if ($AutoDetectAlgorithm) {
            $Algorithm = Get-ChecksumAlgorithmFromLength -Checksum $ExpectedChecksum
            if (-not $Algorithm) { Throw "Unable to detect algorithm from provided checksum length." }
        } else {
            Throw "Algorithm must be specified or use -AutoDetectAlgorithm."
        }
    }

    $calc = Get-FileChecksumEx -Path $Path -Algorithm $Algorithm -ShowProgress:$ShowProgress -ErrorAction Stop

    $match = ($calc.Checksum -ieq $ExpectedChecksum)

    $result = [PSCustomObject]@{
        Path             = $calc.Path
        Algorithm        = $Algorithm
        ExpectedChecksum = $ExpectedChecksum
        Calculated       = $calc.Checksum
        Length           = $calc.Length
        Elapsed          = $calc.Elapsed
        Match            = $match
    }

    if (-not $match -and $SaveOnMismatch) {
        if (-not $OutputPath) {
            $dir = Split-Path -Parent $Path
            $base = [IO.Path]::GetFileName($Path)
            $OutputPath = Join-Path -Path $dir -ChildPath ("{0}.{1}.{2}.checksum.txt" -f $base, $Algorithm, $env:USERNAME)
        }
        try {
            [System.IO.File]::WriteAllText($OutputPath, $calc.Checksum, [System.Text.Encoding]::UTF8)
            $result | Add-Member -NotePropertyName SavedChecksumPath -NotePropertyValue $OutputPath -Force
        } catch {
            Write-Verbose ("Failed to save checksum to '{0}': {1}" -f $OutputPath, $_.Exception.Message)
        }
    }

    return $result
}

function Save-ChecksumQuick {
    param(
        [Parameter(Mandatory=$true)]
        [string] $TargetPath,
        [Parameter(Mandatory=$true)]
        [string] $Checksum
    )
    try {
        [System.IO.File]::WriteAllText($TargetPath, $Checksum, [System.Text.Encoding]::UTF8)
        return $true
    } catch {
        Write-Verbose ("Quick save failed for '{0}': {1}" -f $TargetPath, $_.Exception.Message)
        return $false
    }
}

function Save-ChecksumWithMetadata {
    param(
        [Parameter(Mandatory=$true)]
        [string] $TargetPath,
        [Parameter(Mandatory=$true)]
        [string] $Checksum,
        [Parameter(Mandatory=$true)]
        [string] $Algorithm,
        [Parameter(Mandatory=$true)]
        [string] $FilePath
    )

    $now = (Get-Date).ToString("u")
    $user = $env:USERNAME
    $content = @"
File:      $FilePath
Algorithm: $Algorithm
Checksum:  $Checksum

CreatedBy: $user
CreatedOn: $now
"@

    try {
        [System.IO.File]::WriteAllText($TargetPath, $content, [System.Text.Encoding]::UTF8)
        return $true
    } catch {
        Write-Verbose ("Metadata save failed for '{0}': {1}" -f $TargetPath, $_.Exception.Message)
        return $false
    }
}

#endregion

#region Interactive single-key main menu

# Ensure Windows.Forms assembly present for file dialog & clipboard fallback
Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue

# Helper that reads a single keypress across different hosts (console, ISE, etc.)
function Read-SingleKey {
    param(
        [string] $Prompt = $null
    )

    if ($Prompt) { Write-Host $Prompt }

    try {
        # Preferred: real console (blocks until a keypress, no echo when $true)
        $ck = [Console]::ReadKey($true)
        return $ck.KeyChar
    } catch {
        # ISE / other hosts: use the host RawUI ReadKey (no Enter required)
        try {
            while ($true) {
                $k = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                if ($k.Character -and ($k.Character -ne [char]0)) { return $k.Character }
            }
        } catch {
            # Final fallback: require Enter (preserves functionality but needs Enter)
            $input = Read-Host "Choose an option (Enter required in this host)"
            if ($input) { return $input[0] } else { return '' }
        }
    }
}

function Show-MainMenuAndReadKey {
    param()

    Clear-Host

    # explicit assignments to avoid using inline if-expressions (compatibility with PowerShell 5.1)
    if ($env:USERNAME) { $userDisplay = $env:USERNAME } else { $userDisplay = 'Unknown User' }
    if ($Global:Settings.AutoCopyToClipboard) { $autoCopyStatus = 'On' } else { $autoCopyStatus = 'Off' }

    Write-Host ("Checksum Tool — User: {0}    AutoCopy: {1}" -f $userDisplay, $autoCopyStatus) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1) Calculate checksum"
    Write-Host "2) Verify checksum (auto-detect algorithm)"
    Write-Host "3) Verify checksum (specify algorithm)"
    Write-Host "4) Preferences"
    Write-Host "5) Exit"
    Write-Host ""
    Write-Host "Press the number key for your choice (no Enter required)."

    # Use cross-host single-key reader
    $keyChar = Read-SingleKey
    return $keyChar
}

while ($true) {
    $k = Show-MainMenuAndReadKey

    switch ($k) {
        '1' {
            $fileDialog = New-Object System.Windows.Forms.OpenFileDialog
            $fileDialog.InitialDirectory = [Environment]::GetFolderPath('Desktop')
            $fileDialog.Filter = "All files (*.*)|*.*"
            if ($fileDialog.ShowDialog() -eq 'OK') { $file = $fileDialog.FileName } else { Write-Host "No file selected." -ForegroundColor Yellow; Start-Sleep -Milliseconds 700; continue }

            $alg = Select-AlgorithmMenu -Prompt "Choose hash algorithm" -Default "SHA256"
            if (-not $alg) { Write-Host "Cancelled algorithm selection." -ForegroundColor DarkGray; Start-Sleep -Milliseconds 700; continue }

            $res = Get-FileChecksumEx -Path $file -Algorithm $alg -ShowProgress

            Write-Host ("Checksum ({0}): {1}" -f $res.Algorithm, $res.Checksum) -ForegroundColor Green

            if ($Global:Settings.AutoCopyToClipboard) {
                if (Copy-ToClipboard -Text $res.Checksum) { Write-Host "Checksum automatically copied to clipboard (preference enabled)." -ForegroundColor Yellow } else { Write-Host "Auto-copy failed (see verbose)." -ForegroundColor Red }
            }

            Write-Host ""
            Write-Host "Actions: (C)opy to Clipboard  (F)ile quick-save  (M)etadata save  (N)one"
            $action = Read-Host "Choose an action (C/F/M/N) [N]"

            switch ($action.ToUpper()) {
                'C' {
                    if (Copy-ToClipboard -Text $res.Checksum) { Write-Host "Checksum copied to clipboard." -ForegroundColor Yellow } else { Write-Host "Copy to clipboard failed (see verbose)." -ForegroundColor Red }
                }
                'F' {
                    $dir = Split-Path -Parent $file
                    $base = [IO.Path]::GetFileName($file)
                    $out = Join-Path -Path $dir -ChildPath ("{0}.{1}.{2}.checksum.txt" -f $base, $res.Algorithm, $env:USERNAME)
                    if (Save-ChecksumQuick -TargetPath $out -Checksum $res.Checksum) { Write-Host "Quick-saved checksum to: $out" -ForegroundColor Yellow } else { Write-Host "Quick-save failed." -ForegroundColor Red }
                }
                'M' {
                    $dir = Split-Path -Parent $file
                    $base = [IO.Path]::GetFileName($file)
                    $out = Join-Path -Path $dir -ChildPath ("{0}.{1}.{2}.checksum.txt" -f $base, $res.Algorithm, $env:USERNAME)
                    if (Save-ChecksumWithMetadata -TargetPath $out -Checksum $res.Checksum -Algorithm $res.Algorithm -FilePath $res.Path) { Write-Host "Saved checksum with metadata to: $out" -ForegroundColor Yellow } else { Write-Host "Save with metadata failed." -ForegroundColor Red }
                }
                default { Write-Host "No action taken." -ForegroundColor DarkGray }
            }

            Read-Host "Press Enter to continue..."
        }

        '2' {
            $fileDialog = New-Object System.Windows.Forms.OpenFileDialog
            $fileDialog.InitialDirectory = [Environment]::GetFolderPath('Desktop')
            $fileDialog.Filter = "All files (*.*)|*.*"
            if ($fileDialog.ShowDialog() -eq 'OK') { $file = $fileDialog.FileName } else { Write-Host "No file selected." -ForegroundColor Yellow; Start-Sleep -Milliseconds 700; continue }

            $chk  = Read-Host "Enter expected checksum"
            $res = Test-FileChecksum -Path $file -ExpectedChecksum $chk -AutoDetectAlgorithm -ShowProgress
            if ($res.Match) {
                Write-Host "Match!" -ForegroundColor Green
                if ($Global:Settings.AutoCopyToClipboard) {
                    if (Copy-ToClipboard -Text $res.Calculated) { Write-Host "Calculated checksum copied to clipboard (preference enabled)." -ForegroundColor Yellow } else { Write-Host "Auto-copy failed." -ForegroundColor Red }
                } else {
                    $copy = Read-Host "Copy calculated checksum to clipboard? (Y/N) [N]"
                    if ($copy -match '^[yY]') { if (Copy-ToClipboard -Text $res.Calculated) { Write-Host "Copied." -ForegroundColor Yellow } else { Write-Host "Copy failed." -ForegroundColor Red } }
                }
            } else {
                Write-Host ("Mismatch. Calculated: {0}" -f $res.Calculated) -ForegroundColor Red
                Write-Host "Actions: (C)opy to Clipboard  (F)ile quick-save  (M)etadata save  (N)one"
                $save = Read-Host "Choose an action (C/F/M/N) [N]"
                switch ($save.ToUpper()) {
                    'C' {
                        if (Copy-ToClipboard -Text $res.Calculated) { Write-Host "Copied to clipboard." -ForegroundColor Yellow } else { Write-Host "Copy failed." -ForegroundColor Red }
                    }
                    'F' {
                        $dir = Split-Path -Parent $file
                        $base = [IO.Path]::GetFileName($file)
                        $out = Join-Path -Path $dir -ChildPath ("{0}.{1}.{2}.checksum.txt" -f $base, $res.Algorithm, $env:USERNAME)
                        if (Save-ChecksumQuick -TargetPath $out -Checksum $res.Calculated) { Write-Host "Saved: $out" -ForegroundColor Yellow } else { Write-Host "Save failed." -ForegroundColor Red }
                    }
                    'M' {
                        $dir = Split-Path -Parent $file
                        $base = [IO.Path]::GetFileName($file)
                        $out = Join-Path -Path $dir -ChildPath ("{0}.{1}.{2}.checksum.txt" -f $base, $res.Algorithm, $env:USERNAME)
                        if (Save-ChecksumWithMetadata -TargetPath $out -Checksum $res.Calculated -Algorithm $res.Algorithm -FilePath $res.Path) { Write-Host "Saved: $out" -ForegroundColor Yellow } else { Write-Host "Save failed." -ForegroundColor Red }
                    }
                    default { Write-Host "Not saved." -ForegroundColor DarkGray }
                }
            }
            Read-Host "Press Enter to continue..."
        }

        '3' {
            $fileDialog = New-Object System.Windows.Forms.OpenFileDialog
            $fileDialog.InitialDirectory = [Environment]::GetFolderPath('Desktop')
            $fileDialog.Filter = "All files (*.*)|*.*"
            if ($fileDialog.ShowDialog() -eq 'OK') { $file = $fileDialog.FileName } else { Write-Host "No file selected." -ForegroundColor Yellow; Start-Sleep -Milliseconds 700; continue }

            $alg = Select-AlgorithmMenu -Prompt "Choose hash algorithm for verification" -Default "SHA256"
            if (-not $alg) { Write-Host "Cancelled algorithm selection." -ForegroundColor DarkGray; Start-Sleep -Milliseconds 700; continue }

            $chk  = Read-Host "Enter expected checksum"
            $res = Test-FileChecksum -Path $file -ExpectedChecksum $chk -Algorithm $alg -ShowProgress
            if ($res.Match) { Write-Host "Match!" -ForegroundColor Green } else { Write-Host "Mismatch." -ForegroundColor Red }
            Read-Host "Press Enter to continue..."
        }

        '4' {
            Clear-Host
            Write-Host "Preferences" -ForegroundColor Cyan

            # prepare values for display (avoid inline if-expressions)
            if ($Global:Settings.AutoCopyToClipboard) { $prefAutoCopy = 'On' } else { $prefAutoCopy = 'Off' }
            $prefInterval = $Global:Settings.ProgressUpdateIntervalMs
            $prefMinDelta = $Global:Settings.ProgressMinDeltaPercent

            Write-Host ("1) AutoCopyToClipboard: {0}" -f $prefAutoCopy)
            Write-Host ("2) Progress update interval (ms): {0}" -f $prefInterval)
            Write-Host ("3) Progress minimum delta percent: {0}" -f $prefMinDelta)
            Write-Host "4) Save settings and Back"
            Write-Host "5) Back without saving"

            # Use the cross-host single-key reader to get a single keypress
            $prefKey = Read-SingleKey

            switch ($prefKey) {
                '1' {
                    $Global:Settings.AutoCopyToClipboard = -not $Global:Settings.AutoCopyToClipboard
                    if ($Global:Settings.AutoCopyToClipboard) { $toggle = 'On' } else { $toggle = 'Off' }
                    Write-Host ("AutoCopyToClipboard set to: {0}" -f $toggle) -ForegroundColor Yellow
                    Start-Sleep -Milliseconds 700
                }
                '2' {
                    $val = Read-Host ("Enter progress update interval in ms [Current: {0}]" -f $Global:Settings.ProgressUpdateIntervalMs)
                    if ($val) {
                        $tmp = 0
                        if ([int]::TryParse($val, [ref]$tmp)) {
                            $Global:Settings.ProgressUpdateIntervalMs = [int]$tmp
                            Write-Host ("Set ProgressUpdateIntervalMs to {0}" -f $Global:Settings.ProgressUpdateIntervalMs) -ForegroundColor Yellow
                        } else {
                            Write-Host "Invalid value; no change." -ForegroundColor Yellow
                        }
                    } else { Write-Host "No change." -ForegroundColor Yellow }
                    Start-Sleep -Milliseconds 700
                }
                '3' {
                    $val = Read-Host ("Enter progress minimum delta percent (e.g. 0.25) [Current: {0}]" -f $Global:Settings.ProgressMinDeltaPercent)
                    try {
                        $d = [double]$val
                        if ($d -ge 0) {
                            $Global:Settings.ProgressMinDeltaPercent = $d
                            Write-Host ("Set ProgressMinDeltaPercent to {0}" -f $Global:Settings.ProgressMinDeltaPercent) -ForegroundColor Yellow
                        } else { Write-Host "Must be >= 0" -ForegroundColor Yellow }
                    } catch { Write-Host "Invalid value; no change." -ForegroundColor Yellow }
                    Start-Sleep -Milliseconds 700
                }
                '4' {
                    if (Save-Settings -Settings $Global:Settings) {
                        Write-Host "Settings saved." -ForegroundColor Green
                    } else {
                        Write-Host "Failed to save settings (see verbose)." -ForegroundColor Red
                    }
                    Start-Sleep -Milliseconds 700
                }
                default { } # back
            }

            # small pause then continue main loop
        }

        '5' { 
            # Save settings on exit (best-effort)
            Save-Settings -Settings $Global:Settings | Out-Null
            exit 
        }

        default { Write-Host "Invalid option" -ForegroundColor Red; Start-Sleep -Milliseconds 700 }
    }
}

#endregion
