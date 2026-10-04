#Requires -Version 5.1
param([string] $ScriptPath = "$PSScriptRoot\..\Checksum-Verify.ps1", [string] $Blake3Executable)

$ErrorActionPreference = 'Stop'
$failures = 0
$count = 0
$root = Join-Path ([IO.Path]::GetTempPath()) ('ChecksumTests_' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)

function Assert-Equal($Actual, $Expected) {
    if ($Actual -cne $Expected) { throw "Expected '$Expected', got '$Actual'." }
}
function Assert-Throws([scriptblock] $Action) {
    $threw = $false
    try { & $Action | Out-Null } catch { $threw = $true }
    if (-not $threw) { throw 'Expected a terminating error.' }
}
function Test-Case([string] $Name, [scriptblock] $Action) {
    $script:count++
    try { & $Action; Write-Host "[OK] $Name" }
    catch { $script:failures++; Write-Host "[FAIL] ${Name}: $($_.Exception.Message)" -ForegroundColor Red }
}

try {
    # Load actual function definitions without starting menus or touching user settings.
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $ScriptPath), [ref]$null, [ref]$errors)
    if ($errors) { throw ($errors.Message -join '; ') }
    $ast.FindAll({ $args[0] -is [Management.Automation.Language.FunctionDefinitionAst] }, $true) |
        ForEach-Object { . ([scriptblock]::Create($_.Extent.Text)) }
    $script:ApplicationPath = (Resolve-Path -LiteralPath $ScriptPath).ProviderPath
    function Get-SettingsFilePath { Join-Path $root 'settings.json' }
    if ($Blake3Executable) {
        $script:TestBlake3Path = (Resolve-Path -LiteralPath $Blake3Executable -ErrorAction Stop).ProviderPath
        function Get-Blake3Executable { $script:TestBlake3Path }
    }
    $Global:Settings = Get-DefaultSettings
    $Global:LogFile = Join-Path $root 'test.log'
    $Global:MaxLogSizeMB = 5
    $Global:MaxLogArchives = 5
    $Global:MinLogLevel = 'INFO'
    $Global:LogLevels = @{ DEBUG=1; INFO=2; WARN=3; ERROR=4; CRITICAL=5 }
    $target = Join-Path $root 'package.iso'
    $manifest = Join-Path $root 'SHA256SUMS'
    [IO.File]::WriteAllText($target, 'abc')
    $sha256 = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    $sha512 = (Get-FileHash -LiteralPath $target -Algorithm SHA512).Hash.ToLowerInvariant()

    Test-Case 'Known SHA256 vector' { Assert-Equal (Get-FileChecksumEx $target).Checksum $sha256 }
    Test-Case 'ALL includes each supported algorithm once' {
        $results = @(Get-FileChecksumEx $target -Algorithm ALL,SHA256)
        Assert-Equal $results.Count @(Get-SupportedChecksumAlgorithms).Count
        Assert-Equal @($results.Algorithm | Select-Object -Unique).Count $results.Count
        Assert-Equal ($results | Where-Object Algorithm -eq 'SHA256').Checksum $sha256
    }
    Test-Case 'Relative file paths follow the PowerShell location' {
        Push-Location -LiteralPath $root
        try {
            Assert-Equal (Get-FileChecksumEx '.\package.iso').Checksum $sha256
            Write-ChecksumFile '.\relative.sha256' $sha256
            Assert-Equal ([IO.File]::ReadAllText((Join-Path $root 'relative.sha256'))) $sha256
        }
        finally { Pop-Location }
    }
    Test-Case 'Duplicate algorithms and casing' {
        $results = @(Get-FileChecksumEx $target -Algorithm SHA256,sha256)
        Assert-Equal $results.Count 1
        Assert-Equal $results[0].Checksum $sha256
    }
    foreach ($size in @(0, 1, 4095, 4096, 4097, 16387)) {
        $data = Join-Path $root "data-$size.bin"
        $bytes = New-Object byte[] $size
        for ($i=0; $i -lt $size; $i++) { $bytes[$i] = $i % 251 }
        [IO.File]::WriteAllBytes($data, $bytes)
        foreach ($algorithm in @('MD5','SHA1','SHA256','SHA384','SHA512')) {
            Test-Case "$algorithm at $size bytes" {
                $expected = (Get-FileHash -LiteralPath $data -Algorithm $algorithm).Hash.ToLowerInvariant()
                Assert-Equal (Get-FileChecksumEx $data -Algorithm $algorithm -BufferSize 4096).Checksum $expected
            }
        }
        Test-Case "Single-pass multiple hashes at $size bytes" {
            foreach ($result in @(Get-FileChecksumEx $data -Algorithm MD5,SHA256,SHA512 -BufferSize 4096)) {
                Assert-Equal $result.Checksum (Get-FileHash -LiteralPath $data -Algorithm $result.Algorithm).Hash.ToLowerInvariant()
            }
        }
    }
    Test-Case 'Reject unrelated filename' {
        [IO.File]::WriteAllText($manifest, "$sha256  other.iso")
        Assert-Equal ([bool](Get-ChecksumFromFile $manifest -TargetFilename 'package.iso')) $false
        Assert-Throws { Test-FileChecksum $target $manifest }
    }
    Test-Case 'Reject conflicting entries' {
        [IO.File]::WriteAllText($manifest, "$sha256  package.iso`n$('a' * 64)  package.iso")
        Assert-Throws { Get-ChecksumFromFile $manifest -TargetFilename 'package.iso' }
    }
    Test-Case 'Named manifest punctuation is literal' {
        Assert-Equal ([bool](ConvertFrom-ChecksumText "$sha256  package.iso;" -TargetFilename 'package.iso')) $false
        Assert-Equal ([bool](ConvertFrom-ChecksumText "$sha256  package.iso.xz" -TargetFilename 'package.iso')) $false
    }
    Test-Case 'Unicode filenames and BSD filenames with parentheses' {
        $filename = 'package-' + [char]0x00E9 + '(1).iso'
        $parsed = ConvertFrom-ChecksumText "SHA256 ($filename) = $sha256" -TargetFilename $filename
        Assert-Equal $parsed.Checksum $sha256
        Assert-Equal $parsed.FilenameMatch $true
    }
    Test-Case 'Accept identical duplicate entries' {
        [IO.File]::WriteAllText($manifest, "$sha256  package.iso`n$sha256  package.iso")
        Assert-Equal (Test-FileChecksum $target $manifest).Match $true
    }
    Test-Case 'Chosen algorithm selects correct manifest entry' {
        [IO.File]::WriteAllText($manifest, "SHA512 (package.iso) = $sha512`nSHA256 (package.iso) = $sha256")
        Assert-Equal (Test-FileChecksum $target $manifest -Algorithm SHA256).Match $true
    }
    Test-Case 'Reject algorithm label and length disagreement' {
        [IO.File]::WriteAllText($manifest, "SHA512 (package.iso) = $sha256")
        Assert-Throws { Test-FileChecksum $target $manifest }
    }
    Test-Case 'Discovery reads past headers and excludes unrelated manifests' {
        [IO.File]::WriteAllText($manifest, ((('# header' + "`n") * 20) + "$sha256  package.iso"))
        Assert-Equal (@(Find-ChecksumFiles $target | Where-Object { $_.Path -eq $manifest }).Count) 1
        [IO.File]::WriteAllText($manifest, "$sha256  other.iso")
        Assert-Equal (@(Find-ChecksumFiles $target | Where-Object { $_.Path -eq $manifest }).Count) 0
    }
    Test-Case 'Explicit algorithm filters a mixed unlabeled manifest' {
        Assert-Equal (Test-FileChecksum $target "$sha512  package.iso`n$sha256  package.iso" -Algorithm SHA256).Match $true
    }
    Test-Case 'Pasted manifest selects target rather than longest digest' {
        Assert-Equal (Test-FileChecksum $target "$sha512  other.iso`n$sha256  package.iso").Match $true
    }
    Test-Case 'Reject normalization length bypass and junk' {
        Assert-Equal ([bool](ConvertTo-NormalizedChecksum (('aa:' * 31) + 'aa') -Algorithm SHA512)) $false
        Assert-Equal ([bool](ConvertTo-NormalizedChecksum ('a!' * 64))) $false
        Assert-Equal ([bool](ConvertTo-NormalizedChecksum ('a' * 65))) $false
    }
    Test-Case 'Reject unsupported labels rather than guessing by length' {
        Assert-Throws { ConvertFrom-ChecksumText "BLAKE2 (package.iso) = $sha256" -TargetFilename 'package.iso' }
        Assert-Throws { ConvertFrom-ChecksumText "Algorithm: SHA3-384`nChecksum: $sha512" }
    }
    Test-Case 'Save-on-mismatch preserves source manifest' {
        [IO.File]::WriteAllText($manifest, "$('a' * 64)  package.iso")
        $original = [IO.File]::ReadAllText($manifest)
        $result = Test-FileChecksum $target $manifest -SaveOnMismatch
        Assert-Equal $result.Match $false
        Assert-Equal ([IO.File]::ReadAllText($manifest)) $original
        Assert-Equal ([IO.File]::ReadAllText($result.SavedChecksumPath)) $sha256
        Assert-Throws { Test-FileChecksum $target $manifest -SaveOnMismatch -OutputPath $manifest }
        Assert-Throws { Test-FileChecksum $target $manifest -SaveOnMismatch -OutputPath $target }
        Assert-Equal ([IO.File]::ReadAllText($target)) 'abc'
    }
    Test-Case 'Quick and metadata save refuse overwrite' {
        Assert-Equal (Save-ChecksumQuick $target $sha256) $false
        Assert-Equal (Save-ChecksumWithMetadata $target $sha256 SHA256 $target) $false
        Assert-Equal ([IO.File]::ReadAllText($target)) 'abc'
    }
    Test-Case 'Structured logging round-trips quotes and newlines' {
        $Global:Settings.AnonymizeLogPaths = $false
        $message = "Quoted `"value`"; C:\test\file`nsecond line"
        Write-LogMessage $message
        $entry = Get-Content -LiteralPath $Global:LogFile -Tail 1 | ConvertFrom-Json
        Assert-Equal $entry.message $message
    }
    Test-Case 'Settings normalize booleans limits and nonfinite values' {
        $settings = ConvertTo-NormalizedSettings ([pscustomobject]@{
            IncludeUsernameInMetadata='false'; AnonymizeLogPaths='false'; MaxRecentFiles=-1
            ProgressMinDeltaPercent=[double]::NaN; LargeFileSizeWarningGB=[double]::PositiveInfinity
        })
        Assert-Equal $settings.IncludeUsernameInMetadata $false
        Assert-Equal $settings.AnonymizeLogPaths $false
        Assert-Equal $settings.MaxRecentFiles 10
        Assert-Equal $settings.ProgressMinDeltaPercent 0.25
        Assert-Equal $settings.LargeFileSizeWarningGB 1.0
    }
    Test-Case 'Settings save and replace round-trip without leftover files' {
        Assert-Equal (Save-Settings $Global:Settings) $true
        $Global:Settings.AutoCopyToClipboard = $true
        Assert-Equal (Save-Settings $Global:Settings) $true
        Assert-Equal (Import-Settings).AutoCopyToClipboard $true
    }
    Test-Case 'GNU export round-trip and overwrite protection' {
        $export = Join-Path $root 'export.sha256'
        Export-ChecksumManifest @(Get-FileChecksumEx $target) $export
        Assert-Equal ([IO.File]::ReadAllText($export)) "$sha256 *package.iso`n"
        Assert-Equal (Test-FileChecksum $target $export).Match $true
        Assert-Throws { Export-ChecksumManifest @(Get-FileChecksumEx $target) $export }
    }
    Test-Case 'Batch verification continues after a missing file' {
        [IO.File]::WriteAllText($manifest, "$sha256  package.iso")
        $results = @(Test-FileChecksums -Path @((Join-Path $root 'missing.iso'), $target) -ChecksumFile $manifest)
        Assert-Equal $results.Count 2
        Assert-Equal $results[0].Match $false
        Assert-Equal $results[1].Match $true
    }
    Test-Case 'CRC32 IEEE vectors and empty input' {
        $crcFile = Join-Path $root 'crc.bin'
        [IO.File]::WriteAllText($crcFile, '123456789')
        Assert-Equal (Get-FileChecksumEx $crcFile -Algorithm CRC32).Checksum 'cbf43926'
        [IO.File]::WriteAllBytes($crcFile, [byte[]]@())
        Assert-Equal (Get-FileChecksumEx $crcFile -Algorithm CRC32).Checksum '00000000'
        Assert-Equal (Get-FileChecksumEx $target -Algorithm CRC32).Checksum '352441c2'
    }
    Test-Case 'CRC32 is incremental across buffer boundaries' {
        $crcFile = Join-Path $root 'crc-large.bin'
        [IO.File]::WriteAllText($crcFile, ('123456789' * 10000))
        Assert-Equal (Get-FileChecksumEx $crcFile -Algorithm CRC32 -BufferSize 4096).Checksum (Get-FileChecksumEx $crcFile -Algorithm CRC32 -BufferSize 65536).Checksum
        $combined = @(Get-FileChecksumEx $crcFile -Algorithm CRC32,SHA256 -BufferSize 4096)
        Assert-Equal ($combined | Where-Object Algorithm -eq SHA256).Checksum (Get-FileHash $crcFile -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    Test-Case 'SFV filename-first parsing and manifest export' {
        $sfv = Join-Path $root 'test.sfv'
        [IO.File]::WriteAllText($sfv, "; comment`nother.iso DEADBEEF`npackage.iso 352441C2`n")
        Assert-Equal (Test-FileChecksum $target $sfv).Match $true
        Assert-Equal (ConvertFrom-ChecksumText 'file with spaces.iso 352441C2' -TargetFilename 'file with spaces.iso').FilenameMatch $true
        $export = Join-Path $root 'export.sfv'
        Export-ChecksumManifest @(Get-FileChecksumEx $target -Algorithm CRC32) $export
        Assert-Equal ([IO.File]::ReadAllText($export)) "package.iso 352441C2`n"
        Assert-Equal (Test-FileChecksum $target $export).Match $true
        Assert-Throws { Export-ChecksumManifest @(Get-FileChecksumEx $target) (Join-Path $root 'invalid.sfv') -Format SFV }
    }
    Test-Case 'Reject conflicting SFV entries and ignore generic 8-digit dates' {
        Assert-Throws { ConvertFrom-ChecksumText "package.iso 352441C2`npackage.iso DEADBEEF" -TargetFilename 'package.iso' }
        Assert-Equal ([bool](ConvertFrom-ChecksumText 'Build identifier: 20261004 in release notes')) $false
    }
    if (Get-Blake3Executable) {
        Test-Case 'BLAKE3 known vector and shared streaming read' {
            $expected = '6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85'
            Assert-Equal (Get-FileChecksumEx $target -Algorithm BLAKE3).Checksum $expected
            $combined = @(Get-FileChecksumEx $target -Algorithm BLAKE3,CRC32,SHA256 -BufferSize 4096)
            Assert-Equal ($combined | Where-Object Algorithm -eq BLAKE3).Checksum $expected
            Assert-Equal ($combined | Where-Object Algorithm -eq CRC32).Checksum '352441c2'
            Assert-Equal ($combined | Where-Object Algorithm -eq SHA256).Checksum $sha256
            Assert-Equal (Test-FileChecksum $target "BLAKE3 (package.iso) = $expected").Match $true
            Assert-Equal (Test-FileChecksum $target $expected -Algorithm BLAKE3).Match $true
            $sidecar = Join-Path $root 'package.iso.BLAKE3.txt'
            [IO.File]::WriteAllText($sidecar, $expected)
            Assert-Equal (Test-FileChecksum $target $sidecar).Match $true
            $export = Join-Path $root 'blake3-tagged.txt'
            Export-ChecksumManifest @($combined | Where-Object Algorithm -eq BLAKE3) $export
            Assert-Equal (Test-FileChecksum $target $export).Match $true
        }
        Test-Case 'BLAKE3 empty vector and binary streaming at boundaries' {
            $empty = Join-Path $root 'data-0.bin'
            Assert-Equal (Get-FileChecksumEx $empty -Algorithm BLAKE3).Checksum 'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262'
        }
        Test-Case 'BLAKE3 binary stdin matches official file hashing' {
            $binary = Join-Path $root 'data-16387.bin'
            $expected = (& (Get-Blake3Executable) --no-names --length 32 -- $binary).Trim()
            Assert-Equal (Get-FileChecksumEx $binary -Algorithm BLAKE3 -BufferSize 4096).Checksum $expected
        }
    } else {
        Test-Case 'Missing BLAKE3 dependency fails explicitly' { Assert-Throws { Get-FileChecksumEx $target -Algorithm BLAKE3 } }
    }

    Test-Case 'Updater validates stable tags digests sizes and download URLs' {
        $release = [pscustomobject]@{
            tag_name='v9.0.0'; draft=$false; prerelease=$false
            assets=@([pscustomobject]@{ name='Checksum-Verify.ps1'; state='uploaded'; digest=('sha256:' + $sha256); size=100; browser_download_url='https://github.com/Dantdmnl/Checksum-Verify/releases/download/v9.0.0/Checksum-Verify.ps1' })
        }
        Assert-Equal (ConvertTo-ChecksumReleaseInfo $release).Version '9.0.0'
        $release.prerelease=$true
        Assert-Throws { ConvertTo-ChecksumReleaseInfo $release }
        $release.prerelease=$false
        $release.assets[0].digest=$null
        Assert-Throws { ConvertTo-ChecksumReleaseInfo $release }
        $release.assets[0].digest='sha256:' + $sha256
        $release.assets[0].browser_download_url='https://example.org/untrusted.ps1'
        Assert-Throws { ConvertTo-ChecksumReleaseInfo $release }
    }
    Test-Case 'Updater stages verifies and backs up offline' {
        $script:DownloadFixture = Join-Path $root 'release.ps1'
        $current = Join-Path $root 'current.ps1'
        $source = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $ScriptPath))
        [IO.File]::WriteAllText($current, $source)
        [IO.File]::WriteAllText($script:DownloadFixture, $source.Replace("`$ScriptVersion = '1.7.0'", "`$ScriptVersion = '9.0.0'"))
        function Invoke-WebRequest { param($Uri,[switch]$UseBasicParsing,$TimeoutSec,$OutFile,$ErrorAction) [IO.File]::Copy($script:DownloadFixture, $OutFile) }
        $release = [pscustomobject]@{ Tag='v9.0.0'; Version='9.0.0'; Size=(Get-Item $script:DownloadFixture).Length; Digest=('sha256:' + (Get-FileHash $script:DownloadFixture -Algorithm SHA256).Hash); DownloadUrl='https://github.com/Dantdmnl/Checksum-Verify/releases/download/v9.0.0/Checksum-Verify.ps1' }
        $installed = Install-ChecksumUpdate $release $current
        Assert-Equal (Get-ChecksumScriptVersion $current).ToString() '9.0.0'
        Assert-Equal ([IO.File]::ReadAllText($installed.BackupPath)) $source
        Assert-Throws { Install-ChecksumUpdate $release $current }
        [IO.File]::WriteAllText($current, $source)
        $release.Digest='sha256:' + ('a' * 64)
        Assert-Throws { Install-ChecksumUpdate $release $current }
        Assert-Equal ([IO.File]::ReadAllText($current)) $source
        Assert-Equal @(Get-ChildItem -LiteralPath $root -Filter '*.update.ps1' -Force).Count 0
        $release.Digest='sha256:' + (Get-FileHash $script:DownloadFixture -Algorithm SHA256).Hash
        $release.Size++
        Assert-Throws { Install-ChecksumUpdate $release $current }
        Assert-Equal ([IO.File]::ReadAllText($current)) $source
        $release.Size--
        $downloadSource = [IO.File]::ReadAllText($script:DownloadFixture)
        [IO.File]::WriteAllText($script:DownloadFixture, $downloadSource.Replace("`$ScriptVersion = '9.0.0'", "`$ScriptVersion = '9.1.0'"))
        $release.Digest='sha256:' + (Get-FileHash $script:DownloadFixture -Algorithm SHA256).Hash
        Assert-Throws { Install-ChecksumUpdate $release $current }
        Assert-Equal ([IO.File]::ReadAllText($current)) $source
        [IO.File]::WriteAllText($script:DownloadFixture, '(')
        $release.Size=1
        $release.Digest='sha256:' + (Get-FileHash $script:DownloadFixture -Algorithm SHA256).Hash
        Assert-Throws { Install-ChecksumUpdate $release $current }
        Assert-Equal ([IO.File]::ReadAllText($current)) $source
        Assert-Equal @(Get-ChildItem -LiteralPath $root -Filter '*.update.ps1' -Force).Count 0
    }
    Test-Case 'Updater refuses a concurrently edited local script' {
        $script:ConcurrentCurrent = Join-Path $root 'concurrent.ps1'
        $source = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $ScriptPath))
        [IO.File]::WriteAllText($script:ConcurrentCurrent, $source)
        $script:DownloadFixture = Join-Path $root 'concurrent-release.ps1'
        [IO.File]::WriteAllText($script:DownloadFixture, $source.Replace("`$ScriptVersion = '1.7.0'", "`$ScriptVersion = '9.0.0'"))
        function Invoke-WebRequest {
            param($Uri,[switch]$UseBasicParsing,$TimeoutSec,$OutFile,$ErrorAction)
            [IO.File]::Copy($script:DownloadFixture, $OutFile)
            [IO.File]::AppendAllText($script:ConcurrentCurrent, "`n# Local edit")
        }
        $release = [pscustomobject]@{ Tag='v9.0.0'; Version='9.0.0'; Size=(Get-Item $script:DownloadFixture).Length; Digest=('sha256:' + (Get-FileHash $script:DownloadFixture -Algorithm SHA256).Hash); DownloadUrl='https://github.com/Dantdmnl/Checksum-Verify/releases/download/v9.0.0/Checksum-Verify.ps1' }
        Assert-Throws { Install-ChecksumUpdate $release $script:ConcurrentCurrent }
        Assert-Equal ([IO.File]::ReadAllText($script:ConcurrentCurrent)) ($source + "`n# Local edit")
        Assert-Equal @(Get-ChildItem -LiteralPath $root -Filter 'concurrent.ps1.*.bak').Count 0
    }
    Test-Case 'BLAKE3 setup validates downloads and never overwrites' {
        $directory = Join-Path $root 'backend'
        [void][IO.Directory]::CreateDirectory($directory)
        $script:BackendBytes = [byte[]]@(77,90,1,2,3,4)
        $fixture = Join-Path $root 'backend.bin'
        [IO.File]::WriteAllBytes($fixture, $script:BackendBytes)
        $script:BackendRelease = [pscustomobject]@{
            tag_name='1.8.7'; draft=$false; prerelease=$false
            assets=@([pscustomobject]@{ name='b3sum_windows_x64_bin.exe'; state='uploaded'; size=$script:BackendBytes.Length; digest=('sha256:' + (Get-FileHash $fixture -Algorithm SHA256).Hash); browser_download_url='https://github.com/BLAKE3-team/BLAKE3/releases/download/1.8.7/b3sum_windows_x64_bin.exe' })
        }
        function Invoke-RestMethod { param($Uri,$Headers,$TimeoutSec,$ErrorAction) $script:BackendRelease }
        function Invoke-WebRequest { param($Uri,[switch]$UseBasicParsing,$TimeoutSec,$OutFile,$ErrorAction) [IO.File]::WriteAllBytes($OutFile, $script:BackendBytes) }
        $installed = Install-Blake3Tool $directory
        Assert-Equal ([IO.File]::ReadAllBytes($installed.Path).Length) $script:BackendBytes.Length
        Assert-Throws { Install-Blake3Tool $directory }
        $script:BackendRelease.assets[0].digest='sha256:' + ('a' * 64)
        $badDirectory = Join-Path $root 'bad-backend'
        [void][IO.Directory]::CreateDirectory($badDirectory)
        Assert-Throws { Install-Blake3Tool $badDirectory }
        Assert-Equal @(Get-ChildItem -LiteralPath $badDirectory -Force).Count 0
        $script:BackendRelease.assets[0].browser_download_url='https://example.org/b3sum.exe'
        Assert-Throws { ConvertTo-Blake3ReleaseInfo $script:BackendRelease }
    }
    Test-Case 'BLAKE3 process errors and malformed output fail verification' {
        $script:FakeBlake3Arguments = '/c exit 9'
        function Start-Blake3Hasher {
            $start = New-Object Diagnostics.ProcessStartInfo
            $start.FileName = Join-Path $env:SystemRoot 'System32\cmd.exe'
            $start.Arguments = $script:FakeBlake3Arguments
            $start.UseShellExecute = $false
            $start.CreateNoWindow = $true
            $start.RedirectStandardInput = $true
            $start.RedirectStandardOutput = $true
            $start.RedirectStandardError = $true
            $process = New-Object Diagnostics.Process
            $process.StartInfo = $start
            [void]$process.Start()
            [pscustomobject]@{ Process=$process; Output=$process.StandardOutput.ReadToEndAsync(); Error=$process.StandardError.ReadToEndAsync() }
        }
        Assert-Throws { Get-FileChecksumEx $target -Algorithm BLAKE3 }
        $script:FakeBlake3Arguments = '/c echo invalid-digest'
        Assert-Throws { Get-FileChecksumEx $target -Algorithm BLAKE3 }
    }
    Test-Case 'Main menu accepts lowercase letter commands' {
        function Read-SingleKey { 'b' }
        function Write-Host { param($Object,$ForegroundColor,[switch]$NoNewline) }
        function Clear-Host { }
        Assert-Equal (Show-MainMenuAndReadKey) 'B'
    }
    Test-Case 'Algorithm menu accepts BLAKE3 and CRC32 keys' {
        function Get-Blake3Executable { 'fake-for-menu-only.exe' }
        function Read-SingleKey { 'b' }
        function Write-Host { param($Object,$ForegroundColor,[switch]$NoNewline) }
        Assert-Equal (Select-AlgorithmMenu) 'BLAKE3'
        function Read-SingleKey { '4' }
        Assert-Equal (Select-AlgorithmMenu) 'CRC32'
    }
    foreach ($algorithm in @(Get-SupportedChecksumAlgorithms)) {
        Test-Case "Menu selection and verification: $algorithm" {
            $ordered = @('SHA256','SHA384','SHA512','CRC32','MD5','SHA1','SHA3-256','SHA3-512') | Where-Object { $_ -in @(Get-SupportedChecksumAlgorithms) }
            $script:MenuKey = if ($algorithm -eq 'BLAKE3') { 'b' } else { [string]([array]::IndexOf($ordered, $algorithm) + 1) }
            function Read-SingleKey { $script:MenuKey }
            function Write-Host { param($Object,$ForegroundColor,[switch]$NoNewline) }
            $selected = Select-AlgorithmMenu
            Assert-Equal $selected $algorithm
            $result = Get-FileChecksumEx $target -Algorithm $selected
            Assert-Equal (Test-FileChecksum $target $result.Checksum -Algorithm $selected).Match $true
        }
    }
    foreach ($key in @('', '0', [string][char]27, 'a')) {
        Test-Case "Algorithm menu default/cancel/ALL key '$key'" {
            $script:MenuKey = $key
            function Read-SingleKey { $script:MenuKey }
            function Write-Host { param($Object,$ForegroundColor,[switch]$NoNewline) }
            $expected = if ($key.Length -eq 0) { 'SHA256' } elseif ($key -ceq 'a') { 'ALL' } else { $null }
            Assert-Equal (Select-AlgorithmMenu -AllowAll) $expected
        }
    }
    Test-Case 'Unavailable BLAKE3 and invalid choices retry safely' {
        function Get-Blake3Executable { $null }
        function Read-Host { param($Prompt) 'n' }
        $script:MenuKeys = [Collections.Generic.Queue[string]]::new()
        foreach ($key in @('B','invalid','A','0')) { $script:MenuKeys.Enqueue($key) }
        function Read-SingleKey { $script:MenuKeys.Dequeue() }
        function Write-Host { param($Object,$ForegroundColor,[switch]$NoNewline) }
        Assert-Equal (Select-AlgorithmMenu) $null
        Assert-Equal $script:MenuKeys.Count 0
    }
    foreach ($installOutcome in @('success', 'failure')) {
        Test-Case "Algorithm menu BLAKE3 install $installOutcome" {
            $script:MenuInstalled = $false
            function Get-Blake3Executable { if ($script:MenuInstalled) { 'menu-test.exe' } }
            function Install-Blake3Tool {
                param($Directory)
                if ($installOutcome -eq 'failure') { throw 'Simulated download failure' }
                $script:MenuInstalled = $true
                [pscustomobject]@{ Version='test'; Path='menu-test.exe' }
            }
            function Read-Host { param($Prompt) 'y' }
            $script:MenuKeys = [Collections.Generic.Queue[string]]::new()
            foreach ($key in @('B','0')) { $script:MenuKeys.Enqueue($key) }
            function Read-SingleKey { $script:MenuKeys.Dequeue() }
            function Write-Host { param($Object,$ForegroundColor,[switch]$NoNewline) }
            $expected = if ($installOutcome -eq 'success') { 'BLAKE3' } else { $null }
            Assert-Equal (Select-AlgorithmMenu) $expected
        }
    }
    foreach ($commandKey in @('C','F','M','E','N','', [string][char]27)) {
        Test-Case "Result action '$commandKey'" {
            $actionTarget = Join-Path $root ('action-' + [Guid]::NewGuid().ToString('N') + '.bin')
            [IO.File]::WriteAllText($actionTarget, 'abc')
            $result = Get-FileChecksumEx $actionTarget
            $script:MenuKey = $commandKey
            $script:CopiedText = $null
            function Read-SingleKey { $script:MenuKey }
            function Copy-ToClipboard { param($Text) $script:CopiedText = $Text; $true }
            function Write-Host { param($Object,$ForegroundColor,[switch]$NoNewline) }
            $Global:Settings.IncludeUsernameInMetadata = $false
            Invoke-ChecksumResultAction -Results @($result) -FilePath $actionTarget
            switch ($commandKey) {
                'C' { Assert-Equal $script:CopiedText $sha256 }
                'F' { Assert-Equal (Test-FileChecksum $actionTarget ($actionTarget + '.SHA256.txt')).Match $true }
                'M' { Assert-Equal (Test-FileChecksum $actionTarget ($actionTarget + '.SHA256.txt')).Match $true }
                'E' { Assert-Equal (Test-FileChecksum $actionTarget ($actionTarget + '.SHA256.sums.txt')).Match $true }
                default { Assert-Equal @(Get-ChildItem -LiteralPath $root -Filter ([IO.Path]::GetFileName($actionTarget) + '.*') | Where-Object FullName -ne $actionTarget).Count 0 }
            }
        }
    }
    Test-Case 'Declining an update never installs anything' {
        $ScriptVersion = '1.7.0'
        $script:AttemptedInstall = $false
        function Get-ChecksumRelease { [pscustomobject]@{ Version='9.0.0'; ReleaseUrl='https://github.com/Dantdmnl/Checksum-Verify/releases/tag/v9.0.0' } }
        function Read-Host { param($Prompt) 'n' }
        function Install-ChecksumUpdate { $script:AttemptedInstall=$true }
        function Write-Host { param($Object,$ForegroundColor,[switch]$NoNewline) }
        Update-ChecksumTool
        Assert-Equal $script:AttemptedInstall $false
    }
    foreach ($algorithm in @('SHA3-256','SHA3-512')) {
        if ($algorithm -in @(Get-SupportedChecksumAlgorithms)) {
            Test-Case "$algorithm known vector and labeled verification" {
                $expected = if ($algorithm -eq 'SHA3-256') {
                    '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532'
                } else {
                    'b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0'
                }
                Assert-Equal (Get-FileChecksumEx $target -Algorithm $algorithm).Checksum $expected
                Assert-Equal (Test-FileChecksum $target "$algorithm (package.iso) = $expected").Match $true
                $sidecar = Join-Path $root "package.iso.$algorithm.txt"
                Assert-Equal (Save-ChecksumQuick $sidecar $expected) $true
                Assert-Equal (Test-FileChecksum $target $sidecar).Match $true
                $metadata = Join-Path $root "$algorithm.metadata.txt"
                Assert-Equal (Save-ChecksumWithMetadata $metadata $expected $algorithm $target) $true
                Assert-Equal (Test-FileChecksum $target $metadata).Match $true
            }
        } else {
            Test-Case "$algorithm fails explicitly on unsupported runtime" { Assert-Throws { Get-FileChecksumEx $target -Algorithm $algorithm } }
        }
    }
} finally {
    $resolvedRoot = [IO.Path]::GetFullPath($root)
    if ($resolvedRoot.StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()), [StringComparison]::OrdinalIgnoreCase) -and [IO.Path]::GetFileName($resolvedRoot) -like 'ChecksumTests_*') {
        Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
    }
}
Write-Host "$count tests, $failures failures. PowerShell $($PSVersionTable.PSVersion)."
if ($failures -gt 0) { exit 1 }
exit 0
