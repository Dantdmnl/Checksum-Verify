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
    - Support for both a file dialog and typed path
    - Log file for troubleshooting
    - Support for checksum files in various common formats

.NOTES
    - Author: Ruben Draaisma
    - Version: 1.2.1
    - Tested on: Windows 11 24H2
    - Tested with: PowerShell ISE, PowerShell 5.1 and PowerShell 7
#>

#region Version & helper: settings path
$ScriptVersion = '1.2.1'

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
    }
}
#endregion

#region Logging (rotating)
$Global:MaxLogSizeMB   = 5
$Global:MaxLogArchives = 5
$Global:MinLogLevel    = "INFO"
$Global:LogLevels      = @{ "DEBUG"=1; "INFO"=2; "WARN"=3; "ERROR"=4; "CRITICAL"=5 }

function Rotate-Logs {
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

function Log-Message {
    param([string] $Message, [ValidateSet("DEBUG","INFO","WARN","ERROR","CRITICAL")] [string] $Level = "INFO")
    try {
        if ($Global:LogLevels[$Level] -lt $Global:LogLevels[$Global:MinLogLevel]) { return }
    } catch {}

    try {
        if (-not $Global:LogFile) { return }
        Rotate-Logs
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
        Log-Message -Message ("Settings saved to {0}" -f $path) -Level INFO
        return $true
    } catch {
        Log-Message -Message ("Failed saving settings: {0}" -f $_.Exception.Message) -Level ERROR
        return $false
    }
}

function Normalize-SettingsObject {
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

    return $Obj
}

function Load-Settings {
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
        $o = Normalize-SettingsObject -Obj $o
        return $o
    } catch {
        Log-Message -Message ("Settings load failed, recreating defaults: {0}" -f $_.Exception.Message) -Level WARN
        $defaults = Get-DefaultSettings
        Save-Settings -Settings $defaults | Out-Null
        return [PSCustomObject]$defaults
    }
}

try {
    $loaded = Load-Settings
    if (-not $loaded) { $loaded = Get-DefaultSettings }
    $Global:Settings = Normalize-SettingsObject -Obj $loaded
} catch {
    Log-Message -Message ("Unexpected error loading settings: {0}" -f $_.Exception.Message) -Level ERROR
    $Global:Settings = Get-DefaultSettings
}

# Initialize log path globals using settings
$Global:LogDirectory = $Global:Settings.LogDirectory
if (-not (Test-Path -Path $Global:LogDirectory)) {
    try { New-Item -ItemType Directory -Path $Global:LogDirectory -Force | Out-Null } catch {}
}
$Global:LogFile = Join-Path -Path $Global:LogDirectory -ChildPath "checksum_tool.log"

Log-Message -Message ("Checksum tool starting (v{0})" -f $ScriptVersion) -Level INFO
Log-Message -Message ("LogDirectory set to {0}" -f $Global:LogDirectory) -Level INFO
#endregion

#region Utility: Clipboard (deferred Add-Type)
function Copy-ToClipboard {
    param([Parameter(Mandatory=$true)][string] $Text)
    if (Get-Command -Name Set-Clipboard -ErrorAction SilentlyContinue) {
        try { Set-Clipboard -Value $Text; return $true } catch { Log-Message -Message ("Set-Clipboard failed: {0}" -f $_.Exception.Message) -Level WARN }
    }
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
        [void][System.Windows.Forms.Clipboard]::SetText($Text)
        return $true
    } catch {
        Log-Message -Message ("Fallback clipboard failed: {0}" -f $_.Exception.Message) -Level WARN
        return $false
    }
}
#endregion

#region File selection helper (typed-path trims quotes)
function Select-File {
    param([string] $Prompt = "Select a file", [string] $InitialDirectory = $null)
    if (-not $InitialDirectory) { $InitialDirectory = [Environment]::GetFolderPath('Desktop') }

    if ($Global:Settings.UseFileDialog) {
        try {
            Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
            $fileDialog = New-Object System.Windows.Forms.OpenFileDialog
            $fileDialog.InitialDirectory = $InitialDirectory
            $fileDialog.Filter = "All files (*.*)|*.*"
            $fileDialog.Title = $Prompt
            if ($fileDialog.ShowDialog() -eq 'OK') { return $fileDialog.FileName } else { return $null }
        } catch {
            Log-Message -Message ("OpenFileDialog failed: {0}" -f $_.Exception.Message) -Level WARN
            return $null
        }
    } else {
        while ($true) {
            $input = Read-Host ("{0} - enter full path (leave blank to cancel)" -f $Prompt)
            if (-not $input) { return $null }
            $input = $input.Trim()
            $input = $input.Trim('"','''')
            try {
                $resolved = Resolve-Path -LiteralPath $input -ErrorAction Stop
                $first = $resolved | Select-Object -First 1
                if (Test-Path -LiteralPath $first.Path -PathType Leaf) { return $first.Path } else { Write-Host "Path is not a file. Try again or leave blank to cancel." -ForegroundColor Yellow }
            } catch { Write-Host "Path not found. Try again or leave blank to cancel." -ForegroundColor Yellow }
        }
    }
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
        Write-Host "  6) Cancel / Back"
        $choice = Read-Host ("Choose an option (1-6) [Default: {0}]" -f $Default)
        if ([string]::IsNullOrWhiteSpace($choice)) { return $Default }
        if ($map.ContainsKey($choice)) { return $map[$choice] }
        if ($choice -eq '6') { return $null }
        Write-Host "Invalid choice, try again." -ForegroundColor Yellow
    }
}
#endregion

#region Core checksum functions
function Get-FileChecksumEx {
    [CmdletBinding(DefaultParameterSetName='ByPath')]
    param(
        [Parameter(Mandatory=$true, Position=0)][ValidateNotNullOrEmpty()][string] $Path,
        [Parameter(Mandatory=$true)][ValidateSet('MD5','SHA1','SHA256','SHA384','SHA512')][string] $Algorithm = 'SHA256',
        [Parameter(Mandatory=$false)][int] $BufferSize = (4 * 1MB),
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
        try {
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

                        Write-Progress -Id $progressId -Activity ("Calculating {0}" -f $Algorithm) `
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

            Log-Message -Message ("Checksum calculated for {0} ({1})" -f $Path, $Algorithm) -Level INFO

            [PSCustomObject]@{
                Path      = (Get-Item -LiteralPath $Path).FullName
                Algorithm = $Algorithm
                Checksum  = $hex
                Length    = $length
                Elapsed   = $sw.Elapsed
            }

        } catch {
            Log-Message -Message ("Error computing checksum: {0}" -f $_.Exception.Message) -Level ERROR
            Throw "Error computing checksum: $($_.Exception.Message)"
        } finally {
            if ($fs) { try { $fs.Close(); $fs.Dispose() } catch {} }
            if ($hashAlgo) { $hashAlgo.Dispose() }
            if ($ShowProgress) { Write-Progress -Id $progressId -Activity ("Calculating {0}" -f $Algorithm) -Completed }
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

function Normalize-ChecksumString {
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

function Extract-ChecksumFromFile {
    param(
        [Parameter(Mandatory=$true)][string] $Path,
        [Parameter(Mandatory=$false)][string] $TargetFilename
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { Throw "Checksum file not found: $Path" }

    try {
        $lines = Get-Content -LiteralPath $Path -ErrorAction Stop
    } catch {
        Throw "Unable to read checksum file: $($_.Exception.Message)"
    }

    $candidates = @()
    $lineNum = 0
    $target = if ($TargetFilename) { [regex]::Escape($TargetFilename) } else { $null }

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
            if ($target -and ($line -match $target)) { $fileMention = $true }
            $candidates += [PSCustomObject]@{ Checksum = $hex; Algorithm = $alg; Line = $line; LineNumber = $lineNum; FilenameMatch = $fileMention; Preferred = $true }
            continue
        }

        # 2) Common unix "sha256sum" style: "<hex>  filename" or "<hex> *filename"
        if ($line -match '(?i)^\s*(?<hex>[0-9A-Fa-f]{32,128})\s+\*?(?<fname>.+?)\s*$') {
            $hex = $matches['hex'].ToLower()
            $fname = $matches['fname'].Trim("`"", "'")
            $alg = Get-ChecksumAlgorithmFromLength -Checksum $hex
            $fileMention = $false
            if ($target -and ($fname -match $target -or $line -match $target)) { $fileMention = $true }
            $candidates += [PSCustomObject]@{ Checksum = $hex; Algorithm = $alg; Line = $line; LineNumber = $lineNum; FilenameMatch = $fileMention; Preferred = $fileMention }
            continue
        }

        # 3) Labeled single-value lines: "Checksum: <hex>" or "checksum = <hex>"
        if ($line -match '(?i)^\s*Checksum\s*[:=]\s*(?<hex>[0-9A-Fa-f]{32,128})\b') {
            $hex = $matches['hex'].ToLower()
            $alg = Get-ChecksumAlgorithmFromLength -Checksum $hex
            $fileMention = ($target -and ($line -match $target))
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
                if ($target -and ($line -match $target)) { $fileMention = $true }
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
        [Parameter(Mandatory=$true)][string] $Path,
        [Parameter(Mandatory=$true)][string] $ExpectedChecksumOrFile,
        [Parameter(Mandatory=$false)][ValidateSet('MD5','SHA1','SHA256','SHA384','SHA512')][string] $Algorithm,
        [Parameter(Mandatory=$false)][switch] $AutoDetectAlgorithm,
        [Parameter(Mandatory=$false)][switch] $ShowProgress,
        [Parameter(Mandatory=$false)][switch] $SaveOnMismatch,
        [Parameter(Mandatory=$false)][string] $OutputPath
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { Throw "Target file not found: $Path" }

    $expectedChecksum = $null
    $derivedAlgorithm = $null

    # If the provided ExpectedChecksumOrFile is a path to a file, attempt to parse it; otherwise treat as literal/pasted
    if (Test-Path -LiteralPath $ExpectedChecksumOrFile -PathType Leaf) {
        Log-Message -Message ("Parsing checksum from file: {0}" -f $ExpectedChecksumOrFile) -Level INFO
        try {
            $parsed = Extract-ChecksumFromFile -Path $ExpectedChecksumOrFile -TargetFilename (Split-Path -Leaf $Path)
        } catch {
            Log-Message -Message ("Checksum file parse failed: {0}" -f $_.Exception.Message) -Level WARN
            Throw "Could not parse checksum file: $ExpectedChecksumOrFile"
        }

        if (-not $parsed) { Throw "Could not extract a checksum candidate from checksum file: $ExpectedChecksumOrFile" }
        if (-not $parsed.Checksum) {
            # If parser only returned algorithm hint, keep algorithm hint and let algorithm detection handle it
            $derivedAlgorithm = $parsed.Algorithm
        } else {
            $expectedChecksum = Normalize-ChecksumString -Raw $parsed.Checksum
            if (-not $expectedChecksum) { Throw "Extracted checksum is not valid hex." }
            $derivedAlgorithm = $parsed.Algorithm
        }
    } else {
        # Pasted value or user-typed value: normalize and treat as checksum
        $norm = Normalize-ChecksumString -Raw $ExpectedChecksumOrFile
        if (-not $norm) { Throw "Provided checksum string does not contain a valid hex checksum." }
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
        $calc = Get-FileChecksumEx -Path $Path -Algorithm $chosenAlgorithm -ShowProgress:$ShowProgress -ErrorAction Stop
    } catch {
        Log-Message -Message ("Checksum computation failed for {0} with algorithm {1}: {2}" -f $Path, $chosenAlgorithm, $_.Exception.Message) -Level ERROR
        Throw "Failed to compute checksum: $($_.Exception.Message)"
    }

    # Normalize both for reliable comparison
    if ($expectedChecksum) { $expectedChecksum = Normalize-ChecksumString -Raw $expectedChecksum }
    $calculatedChecksum = Normalize-ChecksumString -Raw $calc.Checksum

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
            $OutputPath = Join-Path -Path $dir -ChildPath ("{0}.{1}.{2}.checksum.txt" -f $base, $chosenAlgorithm, $env:USERNAME)
        }
        try {
            [System.IO.File]::WriteAllText($OutputPath, $calculatedChecksum, [System.Text.Encoding]::UTF8)
            $result | Add-Member -NotePropertyName SavedChecksumPath -NotePropertyValue $OutputPath -Force
            Log-Message -Message ("Saved checksum to {0} due to mismatch" -f $OutputPath) -Level INFO
        } catch {
            Log-Message -Message ("Failed to save checksum on mismatch: {0}" -f $_.Exception.Message) -Level WARN
        }
    }

    Log-Message -Message ("Verification for {0}: match={1} (alg={2})" -f $Path, $result.Match, $chosenAlgorithm) -Level INFO
    return $result
}

function Save-ChecksumQuick { param([string] $TargetPath,[string] $Checksum)
    try { [System.IO.File]::WriteAllText($TargetPath,$Checksum,[System.Text.Encoding]::UTF8); return $true } catch { Log-Message -Message ("Quick save failed for {0}: {1}" -f $TargetPath,$_.Exception.Message) -Level WARN; return $false }
}

function Save-ChecksumWithMetadata { param([string] $TargetPath,[string] $Checksum,[string] $Algorithm,[string] $FilePath)
    $now = (Get-Date).ToString("u"); $user = $env:USERNAME
    $content = @"
File:      $FilePath
Algorithm: $Algorithm
Checksum:  $Checksum

CreatedBy: $user
CreatedOn: $now
"@
    try { [System.IO.File]::WriteAllText($TargetPath,$content,[System.Text.Encoding]::UTF8); return $true } catch { Log-Message -Message ("Metadata save failed for {0}: {1}" -f $TargetPath,$_.Exception.Message) -Level WARN; return $false }
}
#endregion

#region Interactive single-key main menu (host-aware, concise)
function Read-SingleKey {
    param([string] $Prompt = $null)
    if ($Prompt) { Write-Host $Prompt }
    try { $ck = [Console]::ReadKey($true); return $ck.KeyChar } catch {
        try {
            while ($true) {
                $k = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                if ($k.Character -and ($k.Character -ne [char]0)) { return $k.Character }
            }
        } catch {
            # Final fallback: Read-Host with no explicit -Prompt (works in ISE)
            $input = Read-Host
            if ($input) { return $input[0] } else { return '' }
        }
    }
}

function Show-MainMenuAndReadKey {
    Clear-Host
    $userDisplay = if ($env:USERNAME) { $env:USERNAME } else { 'Unknown User' }
    $autoCopyStatus = if ($Global:Settings.AutoCopyToClipboard) { 'On' } else { 'Off' }
    $promptSuffix = if ($Host.Name -eq 'ConsoleHost') { 'no Enter required' } else { 'press number then Enter' }

    Write-Host ("Checksum Tool v{0} — User: {1}    AutoCopy: {2}" -f $ScriptVersion, $userDisplay, $autoCopyStatus) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1) Calculate checksum"
    Write-Host "2) Verify checksum (auto-detect algorithm, supports pasted value or checksum-file)"
    Write-Host "3) Verify checksum (specify algorithm, supports pasted value or checksum-file)"
    Write-Host "4) Preferences"
    Write-Host "5) Exit"
    Write-Host ""
    Write-Host ("Press the number key for your choice ({0})." -f $promptSuffix)
    $key = Read-SingleKey
    try { $key = [string]$key; $key = $key.Trim() } catch {}
    return $key
}
#endregion

#region Main loop (Preferences: LogDirectory is option 5, Back is 6)
while ($true) {
    $k = Show-MainMenuAndReadKey

    switch ($k) {
        '1' {
            $file = Select-File -Prompt "Choose file to calculate checksum"
            if (-not $file) { Write-Host "No file selected." -ForegroundColor Yellow; Start-Sleep -Milliseconds 700; continue }

            $alg = Select-AlgorithmMenu -Prompt "Choose hash algorithm" -Default "SHA256"
            if (-not $alg) { Write-Host "Cancelled algorithm selection." -ForegroundColor DarkGray; Start-Sleep -Milliseconds 700; continue }

            Log-Message -Message ("User requested checksum for {0} using {1}" -f $file, $alg) -Level INFO
            $res = Get-FileChecksumEx -Path $file -Algorithm $alg -ShowProgress
            Write-Host ("Checksum ({0}): {1}" -f $res.Algorithm, $res.Checksum) -ForegroundColor Green

            if ($Global:Settings.AutoCopyToClipboard) {
                if (Copy-ToClipboard -Text $res.Checksum) {
                    Write-Host "Checksum automatically copied to clipboard (preference enabled)." -ForegroundColor Yellow
                    Log-Message -Message "Checksum copied to clipboard automatically" -Level INFO
                } else {
                    Write-Host "Auto-copy failed (see verbose)." -ForegroundColor Red
                    Log-Message -Message "Auto-copy failed" -Level WARN
                }
            }

            Write-Host ""
            Write-Host "Actions: (C)opy to Clipboard  (F)ile quick-save  (M)etadata save  (N)one"
            $action = Read-Host "Choose an action (C/F/M/N) [N]"

            switch (($action).ToUpper()) {
                'C' {
                    if (Copy-ToClipboard -Text $res.Checksum) {
                        Write-Host "Checksum copied to clipboard." -ForegroundColor Yellow
                        Log-Message -Message "Checksum copied to clipboard by user" -Level INFO
                    } else {
                        Write-Host "Copy to clipboard failed (see verbose)." -ForegroundColor Red
                        Log-Message -Message "User copy to clipboard failed" -Level WARN
                    }
                }
                'F' {
                    $dir = Split-Path -Parent $file; $base = [IO.Path]::GetFileName($file)
                    $out = Join-Path -Path $dir -ChildPath ("{0}.{1}.{2}.checksum.txt" -f $base, $res.Algorithm, $env:USERNAME)
                    if (Save-ChecksumQuick -TargetPath $out -Checksum $res.Checksum) {
                        Write-Host "Quick-saved checksum to: $out" -ForegroundColor Yellow
                        Log-Message -Message ("Quick-saved checksum to {0}" -f $out) -Level INFO
                    } else { Write-Host "Quick-save failed." -ForegroundColor Red }
                }
                'M' {
                    $dir = Split-Path -Parent $file; $base = [IO.Path]::GetFileName($file)
                    $out = Join-Path -Path $dir -ChildPath ("{0}.{1}.{2}.checksum.txt" -f $base, $res.Algorithm, $env:USERNAME)
                    if (Save-ChecksumWithMetadata -TargetPath $out -Checksum $res.Checksum -Algorithm $res.Algorithm -FilePath $res.Path) {
                        Write-Host "Saved checksum with metadata to: $out" -ForegroundColor Yellow
                        Log-Message -Message ("Saved checksum with metadata to {0}" -f $out) -Level INFO
                    } else { Write-Host "Save with metadata failed." -ForegroundColor Red }
                }
                default { Write-Host "No action taken." -ForegroundColor DarkGray }
            }

            Read-Host "Press Enter to continue..."
        }

        '2' {
            # Verify checksum (auto-detect algorithm)
            $file = Select-File -Prompt "Choose file to verify checksum"
            if (-not $file) { Write-Host "No file selected." -ForegroundColor Yellow; Start-Sleep -Milliseconds 700; continue }

            if ($Global:Settings.UseFileDialog) {
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
                # Typed-path mode: single prompt — user may paste checksum OR type a checksum-file path
                $inputValue = Read-Host "Enter expected checksum or full path to a checksum file (leave blank to cancel)"
                if (-not $inputValue) { Write-Host "No checksum entered." -ForegroundColor Yellow; Start-Sleep -Milliseconds 700; continue }
            }

            Log-Message -Message ("User requested verify (auto-detect) for {0}" -f $file) -Level INFO
            try {
                $res = Test-FileChecksum -Path $file -ExpectedChecksumOrFile $inputValue -AutoDetectAlgorithm -ShowProgress
            } catch {
                Write-Host "Verification failed: $($_.Exception.Message)" -ForegroundColor Red
                Log-Message -Message ("Verification error: {0}" -f $_.Exception.Message) -Level ERROR
                Read-Host "Press Enter to continue..."
                continue
            }

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
                switch (($save).ToUpper()) {
                    'C' { if (Copy-ToClipboard -Text $res.Calculated) { Write-Host "Copied to clipboard." -ForegroundColor Yellow } else { Write-Host "Copy failed." -ForegroundColor Red } }
                    'F' {
                        $dir = Split-Path -Parent $file; $base = [IO.Path]::GetFileName($file)
                        $out = Join-Path -Path $dir -ChildPath ("{0}.{1}.{2}.checksum.txt" -f $base, $res.Algorithm, $env:USERNAME)
                        if (Save-ChecksumQuick -TargetPath $out -Checksum $res.Calculated) { Write-Host "Saved: $out" -ForegroundColor Yellow } else { Write-Host "Save failed." -ForegroundColor Red }
                    }
                    'M' {
                        $dir = Split-Path -Parent $file; $base = [IO.Path]::GetFileName($file)
                        $out = Join-Path -Path $dir -ChildPath ("{0}.{1}.{2}.checksum.txt" -f $base, $res.Algorithm, $env:USERNAME)
                        if (Save-ChecksumWithMetadata -TargetPath $out -Checksum $res.Calculated -Algorithm $res.Algorithm -FilePath $res.Path) { Write-Host "Saved: $out" -ForegroundColor Yellow } else { Write-Host "Save failed." -ForegroundColor Red }
                    }
                    default { Write-Host "Not saved." -ForegroundColor DarkGray }
                }
            }

            Read-Host "Press Enter to continue..."
        }

        '3' {
            # Verify checksum with explicit algorithm
            $file = Select-File -Prompt "Choose file to verify checksum (specify algorithm)"
            if (-not $file) { Write-Host "No file selected." -ForegroundColor Yellow; Start-Sleep -Milliseconds 700; continue }

            $alg = Select-AlgorithmMenu -Prompt "Choose hash algorithm for verification" -Default "SHA256"
            if (-not $alg) { Write-Host "Cancelled algorithm selection." -ForegroundColor DarkGray; Start-Sleep -Milliseconds 700; continue }

            if ($Global:Settings.UseFileDialog) {
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
                # Typed-path mode: single prompt (paste checksum or type path)
                $inputValue = Read-Host "Enter expected checksum or full path to a checksum file (leave blank to cancel)"
                if (-not $inputValue) { Write-Host "No checksum entered." -ForegroundColor Yellow; Start-Sleep -Milliseconds 700; continue }
            }

            Log-Message -Message ("User requested verify (explicit {0}) for {1}" -f $alg, $file) -Level INFO
            try {
                $res = Test-FileChecksum -Path $file -ExpectedChecksumOrFile $inputValue -Algorithm $alg -ShowProgress
            } catch {
                Write-Host "Verification failed: $($_.Exception.Message)" -ForegroundColor Red
                Log-Message -Message ("Verification error: {0}" -f $_.Exception.Message) -Level ERROR
                Read-Host "Press Enter to continue..."
                continue
            }

            if ($res.Match) { Write-Host "Match!" -ForegroundColor Green } else { Write-Host "Mismatch." -ForegroundColor Red }
            Read-Host "Press Enter to continue..."
        }

        '4' {
            $inPrefs = $true
            while ($inPrefs) {
                Clear-Host
                Write-Host "Preferences" -ForegroundColor Cyan
                $prefAutoCopy = if ($Global:Settings.AutoCopyToClipboard) { 'On' } else { 'Off' }
                $prefInterval = $Global:Settings.ProgressUpdateIntervalMs
                $prefMinDelta = $Global:Settings.ProgressMinDeltaPercent
                $prefFileDlg = if ($Global:Settings.UseFileDialog) { 'Explorer dialog' } else { 'Typed path' }
                $prefLogDir = $Global:Settings.LogDirectory

                Write-Host ("1) AutoCopyToClipboard: {0}" -f $prefAutoCopy)
                Write-Host ("2) Progress update interval (ms): {0}" -f $prefInterval)
                Write-Host ("3) Progress minimum delta percent: {0}" -f $prefMinDelta)
                Write-Host ("4) File selection method: {0}" -f $prefFileDlg)
                Write-Host ("5) Set log directory (current: {0})" -f $prefLogDir)
                Write-Host ("6) Back to main menu")
                Write-Host ""
                Write-Host "Press the number key to change that setting (host may require Enter). Changes are saved immediately."

                $prefKey = Read-SingleKey
                try { $prefKey = [string]$prefKey; $prefKey = $prefKey.Trim().ToUpper() } catch {}

                switch ($prefKey) {
                    '1' {
                        $Global:Settings.AutoCopyToClipboard = -not $Global:Settings.AutoCopyToClipboard
                        $state = if ($Global:Settings.AutoCopyToClipboard) { 'On' } else { 'Off' }
                        if (Save-Settings -Settings $Global:Settings) {
                            Write-Host ("AutoCopyToClipboard set to: {0}" -f $state) -ForegroundColor Yellow
                            Log-Message -Message ("AutoCopyToClipboard set to {0}" -f $state) -Level INFO
                        } else {
                            Write-Host "Failed to save settings." -ForegroundColor Red
                            Log-Message -Message "Failed to save AutoCopy change" -Level ERROR
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
                                    Log-Message -Message ("ProgressUpdateIntervalMs set to {0}" -f $tmp) -Level INFO
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
                                        Log-Message -Message ("ProgressMinDeltaPercent set to {0}" -f $d) -Level INFO
                                    } else { Write-Host "Failed to save settings." -ForegroundColor Red }
                                } else { Write-Host "Must be >= 0. No change." -ForegroundColor Yellow }
                            } catch { Write-Host "Invalid value; no change." -ForegroundColor Yellow }
                        } else { Write-Host "No change." -ForegroundColor Yellow }
                        Start-Sleep -Milliseconds 700
                    }
                    '4' {
                        $Global:Settings.UseFileDialog = -not $Global:Settings.UseFileDialog
                        $method = if ($Global:Settings.UseFileDialog) { 'Explorer dialog' } else { 'Typed path' }
                        if (Save-Settings -Settings $Global:Settings) {
                            Write-Host ("File selection method set to: {0}" -f $method) -ForegroundColor Yellow
                            Log-Message -Message ("File selection method set to {0}" -f $method) -Level INFO
                        } else { Write-Host "Failed to save settings." -ForegroundColor Red }
                        Start-Sleep -Milliseconds 700
                    }
                    '5' {
                        $new = $null
                        if ($Global:Settings.UseFileDialog) {
                            try {
                                Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
                                $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
                                $dlg.Description = "Select folder to store logs"
                                if (Test-Path $Global:Settings.LogDirectory) { $dlg.SelectedPath = $Global:Settings.LogDirectory }
                                if ($dlg.ShowDialog() -eq 'OK') { $new = $dlg.SelectedPath }
                            } catch {
                                Log-Message -Message ("Folder dialog failed: {0}" -f $_.Exception.Message) -Level WARN
                                $new = $null
                            }
                        } else {
                            $input = Read-Host ("Enter log directory full path (leave blank to cancel) [Current: {0}]" -f $Global:Settings.LogDirectory)
                            if ($input) { $new = $input.Trim().Trim('"','''') } else { $new = $null }
                        }

                        if ($new) {
                            try { if (-not (Test-Path -Path $new)) { New-Item -ItemType Directory -Path $new -Force | Out-Null } } catch {}
                            if (Test-Path -Path $new) {
                                $Global:Settings.LogDirectory = $new
                                $Global:LogDirectory = $new
                                $Global:LogFile = Join-Path -Path $Global:LogDirectory -ChildPath "checksum_tool.log"
                                if (Save-Settings -Settings $Global:Settings) {
                                    Write-Host ("LogDirectory set to: {0}" -f $new) -ForegroundColor Yellow
                                    Log-Message -Message ("LogDirectory set to {0}" -f $new) -Level INFO
                                } else { Write-Host "Failed to save settings." -ForegroundColor Red }
                            } else { Write-Host "Unable to set log directory." -ForegroundColor Red }
                        } else { Write-Host "No change." -ForegroundColor Yellow }
                        Start-Sleep -Milliseconds 700
                    }
                    '6' { $inPrefs = $false }
                    default { Write-Host "Invalid option" -ForegroundColor Red; Start-Sleep -Milliseconds 700 }
                }
            }
        }

        '5' {
            if (Save-Settings -Settings $Global:Settings) { Log-Message -Message "Settings saved on exit" -Level INFO }
            Log-Message -Message "Checksum tool exiting" -Level INFO
            exit
        }

        default { Write-Host "Invalid option" -ForegroundColor Red; Start-Sleep -Milliseconds 700 }
    }
}
#endregion
