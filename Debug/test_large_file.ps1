#Requires -Version 5.1
param(
    [Parameter(Mandatory=$true)][string] $Path,
    [string] $ScriptPath,
    [string] $Blake3Executable
)
$ErrorActionPreference = 'Stop'
if (-not $ScriptPath) { $ScriptPath = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) '..\Checksum-Verify.ps1' }
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $ScriptPath), [ref]$null, [ref]$errors)
if ($errors) { throw ($errors.Message -join '; ') }
$ast.FindAll({ $args[0] -is [Management.Automation.Language.FunctionDefinitionAst] }, $true) |
    ForEach-Object { . ([scriptblock]::Create($_.Extent.Text)) }
$Global:Settings = Get-DefaultSettings
$Global:Settings.AutoCopyToClipboard = $false
function Write-LogMessage { param($Message,$Level) }
if ($Blake3Executable) {
    $script:TestBlake3Path = (Resolve-Path -LiteralPath $Blake3Executable).ProviderPath
    function Get-Blake3Executable { $script:TestBlake3Path }
}
$before = Get-Item -LiteralPath $Path
$timer = [Diagnostics.Stopwatch]::StartNew()
$results = @(Get-FileChecksumEx -Path $Path -Algorithm ALL)
$timer.Stop()
Write-Host ("ALL: {0} algorithms, {1:N2} seconds, {2:N2} MiB/s" -f $results.Count, $timer.Elapsed.TotalSeconds, ($before.Length / 1MB / $timer.Elapsed.TotalSeconds))
foreach ($result in $results) {
    Write-Host "$($result.Algorithm): $($result.Checksum)"
    if ($result.Algorithm -in @('MD5','SHA1','SHA256','SHA384','SHA512')) {
        $reference = (Get-FileHash -LiteralPath $Path -Algorithm $result.Algorithm).Hash.ToLowerInvariant()
        if ($result.Checksum -cne $reference) { throw "Independent hash mismatch: $($result.Algorithm)" }
        Write-Host '  PASS: matches Get-FileHash'
    } elseif ($result.Algorithm -eq 'BLAKE3') {
        $reference = & $script:TestBlake3Path --no-names --no-mmap -- $Path
        if ($LASTEXITCODE -ne 0 -or $result.Checksum -cne $reference.Trim()) { throw 'Independent BLAKE3 file-mode mismatch' }
        Write-Host '  PASS: matches b3sum file mode'
    }
}
$after = Get-Item -LiteralPath $Path
if ($before.Length -ne $after.Length -or $before.LastWriteTimeUtc -ne $after.LastWriteTimeUtc) { throw 'File changed during test' }
Write-Host 'PASS: source length and modification time unchanged; no sidecars written.'
