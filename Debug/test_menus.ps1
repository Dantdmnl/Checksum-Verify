#Requires -Version 5.1
param([string] $ScriptPath = "$PSScriptRoot\..\Checksum-Verify.ps1")
$ErrorActionPreference = 'Stop'
$failures = 0
$count = 0
$root = Join-Path ([IO.Path]::GetTempPath()) ('ChecksumMenus_' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)
function Assert($Condition, $Message) { if (-not $Condition) { throw $Message } }
function Test-Case($Name, [scriptblock] $Test) {
    $script:count++
    try { & $Test; Microsoft.PowerShell.Utility\Write-Host "[OK] $Name" }
    catch { $script:failures++; Microsoft.PowerShell.Utility\Write-Host "[FAIL] ${Name}: $_" }
}
try {
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $ScriptPath), [ref]$null, [ref]$errors)
    if ($errors) { throw ($errors.Message -join '; ') }
    $ast.FindAll({ $args[0] -is [Management.Automation.Language.FunctionDefinitionAst] }, $true) |
        ForEach-Object { . ([scriptblock]::Create($_.Extent.Text)) }
    $script:ApplicationPath = (Resolve-Path -LiteralPath $ScriptPath).ProviderPath
    $ScriptVersion = '1.7.0'
    $main = @($ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.WhileStatementAst] })[-1]
    $script:MainLoop = [scriptblock]::Create($main.Extent.Text)
    $script:ExportData = (Get-Command Export-ChecksumData).ScriptBlock
    function Get-SettingsFilePath { Join-Path $script:CaseRoot 'settings.json' }
    function Export-ChecksumData { & $script:ExportData -OutputPath (Join-Path $script:CaseRoot 'export.json') }
    function Get-Blake3Executable { $null }
    function Get-ChecksumRelease { [pscustomobject]@{ Version='1.6.0'; ReleaseUrl='offline test' } }
    function Clear-Host { }
    function Start-Sleep { param($Milliseconds,$Seconds) }
    function Wait-ForUser { }
    function Write-Progress { param($Activity,$Status,$PercentComplete,[switch]$Completed,$Id) }
    function Write-Host {
        param($Object,$ForegroundColor,[switch]$NoNewline)
        if ($null -ne $Object) { [void]$script:Output.AppendLine([string]$Object) }
    }
    function Read-SingleKey {
        if ($script:Keys.Count -eq 0) { throw 'Unexpected key prompt' }
        $script:Keys.Dequeue()
    }
    function Read-Host {
        param($Prompt)
        if ($script:Answers.Count -eq 0) { throw "Unexpected prompt: $Prompt" }
        $script:Answers.Dequeue()
    }
    function Copy-ToClipboard { param($Text) $script:Copied = $Text; $true }
    function Get-ClipboardText { $script:Clipboard }
    function Reset-Case {
        $script:CaseRoot = Join-Path $root ([Guid]::NewGuid().ToString('N'))
        [void][IO.Directory]::CreateDirectory($script:CaseRoot)
        $script:Target = Join-Path $script:CaseRoot 'sample.bin'
        [IO.File]::WriteAllText($script:Target, 'abc')
        $script:Hash = (Get-FileHash -LiteralPath $script:Target -Algorithm SHA256).Hash.ToLowerInvariant()
        $Global:Settings = Get-DefaultSettings
        $Global:Settings.UseFileDialog = $false
        $Global:Settings.AutoCopyToClipboard = $false
        $Global:Settings.RecentFiles = @()
        $Global:LogDirectory = $script:CaseRoot
        $Global:Settings.LogDirectory = $script:CaseRoot
        $Global:LogFile = Join-Path $script:CaseRoot 'test.log'
        $Global:MaxLogSizeMB = 5
        $Global:MaxLogArchives = 5
        $Global:MinLogLevel = 'INFO'
        $Global:LogLevels = @{ DEBUG=1; INFO=2; WARN=3; ERROR=4; CRITICAL=5 }
        $script:Output = [Text.StringBuilder]::new()
        $script:Copied = $null
        $script:Clipboard = $script:Hash
    }
    function Run-Menu([string[]] $KeyInput, [string[]] $HostInput = @()) {
        $script:Keys = [Collections.Generic.Queue[string]]::new()
        $script:Answers = [Collections.Generic.Queue[string]]::new()
        foreach ($item in $KeyInput) { $script:Keys.Enqueue($item) }
        foreach ($item in $HostInput) { $script:Answers.Enqueue($item) }
        & $script:MainLoop
        Assert ($script:Keys.Count -eq 0 -and $script:Answers.Count -eq 0) 'Unused input: workflow did not complete as expected'
    }
    foreach ($menuKey in @('1','2','3')) {
        Test-Case "Main ${menuKey}: real calculation/verification" {
            Reset-Case
            if ($menuKey -eq '1') { Run-Menu @('1','1','N','Q') @($script:Target) }
            elseif ($menuKey -eq '2') { Run-Menu @('2','N','Q') @($script:Target,$script:Hash) }
            else { Run-Menu @('3','1','N','Q') @($script:Target,$script:Hash) }
            Assert ($script:Output.ToString().Contains($script:Hash)) 'Expected digest missing from results'
            Assert (-not $script:Output.ToString().Contains('Error:')) 'Unexpected workflow error'
        }
    }
    Test-Case 'Main 1: ALL auto-copy has algorithm labels' {
        Reset-Case
        $Global:Settings.AutoCopyToClipboard = $true
        Run-Menu @('1','A','N','Q') @($script:Target)
        Assert ($script:Copied.Contains('SHA256:') -and $script:Copied.Contains('CRC32:')) 'ALL clipboard text lacks labels'
    }
    Test-Case 'File and algorithm cancellation, invalid main key' {
        Reset-Case
        Run-Menu @('1','1','0','invalid','Q') @('',$script:Target)
        Assert ($script:Output.ToString().Contains('Cancelled algorithm')) 'Cancellation not reached'
    }
    foreach ($recentAction in @('0','1','2','3')) {
        Test-Case "Recent files action $recentAction" {
            Reset-Case
            $Global:Settings.EnableRecentFiles = $true
            Add-RecentFile -FilePath $script:Target
            if ($recentAction -eq '0') { Run-Menu @('4','1','0','Q') }
            elseif ($recentAction -eq '1') { Run-Menu @('4','1','1','1','N','Q') }
            elseif ($recentAction -eq '2') { Run-Menu @('4','1','2','N','Q') @($script:Hash) }
            else { Run-Menu @('4','1','3','1','N','Q') @($script:Hash) }
            if ($recentAction -ne '0') { Assert ($script:Output.ToString().Contains($script:Hash)) 'Recent-file result missing' }
        }
    }
    Test-Case 'Recent files disabled and empty' {
        Reset-Case
        $Global:Settings.EnableRecentFiles = $false
        Run-Menu @('4','Q')
        Assert ($script:Output.ToString().Contains('tracking is off')) 'Disabled message missing'
        $Global:Settings.EnableRecentFiles = $true
        Run-Menu @('4','Q')
        Assert ($script:Output.ToString().Contains('is empty')) 'Empty message missing'
    }
    Test-Case 'Every preference, including bracket-containing log directory' {
        Reset-Case
        $logDir = Join-Path $script:CaseRoot '[logs]'
        Run-Menu @('5','1','2','3','4','4','5','6','7','0','Q') @('50','0.5','1.5',$logDir)
        Assert $Global:Settings.AutoCopyToClipboard 'Auto-copy toggle failed'
        Assert ($Global:Settings.ProgressUpdateIntervalMs -eq 50) 'Interval failed'
        Assert ($Global:Settings.ProgressMinDeltaPercent -eq 0.5) 'Delta failed'
        Assert ($Global:Settings.LargeFileSizeWarningGB -eq 1.5) 'Threshold failed'
        Assert ($Global:Settings.LogDirectory -eq $logDir -and (Test-Path -LiteralPath $Global:LogFile)) 'Log directory failed'
    }
    Test-Case 'Preferences reject invalid, infinite, and out-of-range values' {
        Reset-Case
        $delta = $Global:Settings.ProgressMinDeltaPercent
        $threshold = $Global:Settings.LargeFileSizeWarningGB
        Run-Menu @('5','2','3','3','3','5','5','0','Q') @('49','Infinity','101','NaN','Infinity','-1')
        Assert ($Global:Settings.ProgressMinDeltaPercent -eq $delta) 'Invalid delta accepted'
        Assert ($Global:Settings.LargeFileSizeWarningGB -eq $threshold) 'Invalid threshold accepted'
    }
    Test-Case 'Every privacy option, with confirmed clears and declined deletion' {
        Reset-Case
        Run-Menu @('6','1','2','3','4','5','6','7','8','0','Q') @('y','y','n')
        $export = Join-Path $script:CaseRoot 'export.json'
        Assert (Test-Path -LiteralPath $export) 'Export missing'
        $data = [IO.File]::ReadAllText($export) | ConvertFrom-Json
        Assert ($data.ScriptVersion -eq '1.7.0') 'Wrong export version'
        $threw = $false
        try { Export-ChecksumData | Out-Null } catch { $threw = $true }
        Assert $threw 'Export overwrote an existing file'
    }
    Test-Case 'Privacy deletes only isolated settings/logs and returns' {
        Reset-Case
        Save-Settings -Settings $Global:Settings | Out-Null
        [IO.File]::WriteAllText($Global:LogFile, 'test')
        [IO.File]::WriteAllText("$Global:LogFile.1.log", 'test archive')
        Run-Menu @('6','8') @('DELETE')
        Assert (-not (Test-Path -LiteralPath (Get-SettingsFilePath))) 'Settings not deleted'
        Assert (-not (Test-Path -LiteralPath $Global:LogFile)) 'Log not deleted'
        Assert (Test-Path -LiteralPath $script:Target) 'Target file deleted'
    }
    Test-Case 'Batch manifest selection and multi-file verification' {
        Reset-Case
        $manifest = Join-Path $script:CaseRoot 'SHA256SUMS'
        [IO.File]::WriteAllText($manifest, "$script:Hash  sample.bin")
        Run-Menu @('B','Q') @($manifest,$script:Target,'')
        Assert ($script:Output.ToString().Contains('1 of 1 files verified')) 'Batch verification did not pass'
        Assert ($script:Output.ToString().Contains("Manifest: $manifest")) 'Batch manifest not displayed'
        Assert ($script:Output.ToString().Contains('[1/1] Verifying sample.bin')) 'Per-file start status missing'
        Assert ($script:Output.ToString().Contains('Algorithm: SHA256')) 'Detected algorithm not displayed'
        Assert ($script:Output.ToString().Contains('Mismatches: 0 | Errors: 0')) 'Batch counts missing'
    }
    Test-Case 'Batch streams results and distinguishes mismatch from error' {
        Reset-Case
        $bad = Join-Path $script:CaseRoot 'different.bin'
        $unknown = Join-Path $script:CaseRoot 'no-entry.bin'
        [IO.File]::WriteAllText($bad, 'xyz')
        [IO.File]::WriteAllText($unknown, 'abc')
        $manifest = Join-Path $script:CaseRoot 'SHA256SUMS'
        [IO.File]::WriteAllText($manifest, "$script:Hash  sample.bin`n$script:Hash  different.bin")
        Run-Menu @('B','Q') @($manifest,$script:Target,$bad,$unknown,'')
        $output = $script:Output.ToString()
        Assert ($output.Contains('1 of 3 files verified')) 'Wrong mixed batch result count'
        Assert ($output.Contains('Mismatches: 1 | Errors: 1')) 'Mismatch and error counts not separated'
        Assert ($output.Contains("Expected:  $script:Hash") -and $output.Contains('Calculated:')) 'Mismatch detail missing'
        Assert ($output.IndexOf('  OK  SHA256') -lt $output.IndexOf('[2/3] Verifying')) 'Results were delayed until end of batch'
        Assert ($output.Contains("Path:      $bad")) 'Full target path missing'
    }
    Test-Case 'Help, offline update check, and numeric exit' {
        Reset-Case
        Run-Menu @('H','0','U','7')
        Assert ($script:Output.ToString().Contains('BLAKE3 SETUP')) 'Help missing'
    }
    Test-Case 'Discovered source overflow is rejected without crashing' {
        Reset-Case
        [IO.File]::WriteAllText(($script:Target + '.sha256'), $script:Hash)
        $script:Answers = [Collections.Generic.Queue[string]]::new()
        $script:Answers.Enqueue('999999999999999999999999')
        Assert ($null -eq (Get-ExpectedChecksumInteractive -TargetFile $script:Target)) 'Overflow selection accepted'
    }
    foreach ($sourceKey in @('', '1', '0', 'P', 'C', 'F', 'direct')) {
        Test-Case "Discovered checksum source '$sourceKey'" {
            Reset-Case
            $manifest = $script:Target + '.sha256'
            [IO.File]::WriteAllText($manifest, $script:Hash)
            $script:Answers = [Collections.Generic.Queue[string]]::new()
            $script:Answers.Enqueue($(if ($sourceKey -eq 'direct') { $script:Hash } else { $sourceKey }))
            if ($sourceKey -eq 'P') { $script:Answers.Enqueue($script:Hash) }
            if ($sourceKey -eq 'C') { $script:Answers.Enqueue('y') }
            if ($sourceKey -eq 'F') { $script:Answers.Enqueue($manifest) }
            $value = Get-ExpectedChecksumInteractive -TargetFile $script:Target
            if ($sourceKey -eq '0') { Assert ($null -eq $value) 'Source cancel failed' }
            else { Assert (Test-FileChecksum $script:Target $value).Match 'Source did not verify' }
            Assert ($script:Answers.Count -eq 0) 'Source input not consumed'
        }
    }
    Test-Case 'Clipboard preview cancel and empty clipboard' {
        Reset-Case
        $script:Answers = [Collections.Generic.Queue[string]]::new()
        $script:Answers.Enqueue('n')
        Assert ($null -eq (Get-ConfirmedClipboardChecksumText $script:Target)) 'Clipboard cancel failed'
        $script:Clipboard = ''
        Assert ($null -eq (Get-ConfirmedClipboardChecksumText $script:Target)) 'Empty clipboard accepted'
    }
    foreach ($dialogOutcome in @('OK','Cancel','Throw')) {
        Test-Case "GUI file dialog $dialogOutcome disposes resources" {
            Reset-Case
            $Global:Settings.UseFileDialog = $true
            $script:DialogDisposed = $false
            function New-Object {
                param($TypeName)
                $dialog = [pscustomobject]@{ InitialDirectory=''; Filter=''; Title=''; FileName=$script:Target }
                $dialog | Add-Member ScriptMethod ShowDialog { if ($dialogOutcome -eq 'Throw') { throw 'Simulated dialog failure' }; $dialogOutcome }
                $dialog | Add-Member ScriptMethod Dispose { $script:DialogDisposed = $true }
                $dialog
            }
            $selected = Select-File
            if ($dialogOutcome -eq 'OK') { Assert ($selected -eq $script:Target) 'GUI selection failed' }
            else { Assert ($null -eq $selected) 'GUI cancel/error returned a file' }
            Assert $script:DialogDisposed 'GUI dialog not disposed'
        }
    }
    Test-Case 'GUI log folder picker disposes resources' {
        Reset-Case
        $Global:Settings.UseFileDialog = $true
        $script:DialogDisposed = $false
        $script:SelectedFolder = Join-Path $script:CaseRoot '[gui logs]'
        function New-Object {
            param($TypeName)
            $dialog = [pscustomobject]@{ Description=''; SelectedPath='' }
            $dialog | Add-Member ScriptMethod ShowDialog { $this.SelectedPath = $script:SelectedFolder; 'OK' }
            $dialog | Add-Member ScriptMethod Dispose { $script:DialogDisposed = $true }
            $dialog
        }
        Run-Menu @('5','6','0','Q')
        Assert ($Global:Settings.LogDirectory -eq $script:SelectedFolder) 'GUI log folder not saved'
        Assert $script:DialogDisposed 'Folder dialog not disposed'
    }
    Test-Case 'Recent-file ALL calculation matches main workflow' {
        Reset-Case
        $Global:Settings.EnableRecentFiles = $true
        $Global:Settings.AutoCopyToClipboard = $true
        Add-RecentFile -FilePath $script:Target
        Run-Menu @('4','1','1','A','N','Q')
        Assert ($script:Copied.Contains('SHA256:') -and $script:Copied.Contains('CRC32:')) 'Recent ALL clipboard text lacks labels'
    }
    Test-Case 'Bracket-containing log rotation, viewing, and clearing' {
        Reset-Case
        $Global:LogFile = Join-Path $script:CaseRoot '[test].log'
        $Global:MaxLogSizeMB = 0
        Write-LogMessage 'first'
        Write-LogMessage 'second'
        Assert (Test-Path -LiteralPath "$Global:LogFile.1.log") 'Literal log rotation failed'
        $Global:MaxLogSizeMB = 5
        Show-RecentLogEntries
        Assert ($script:Output.ToString().Contains('second')) 'Literal log viewing failed'
        Run-Menu @('6','6','0','Q') @('y')
        Assert (-not (Test-Path -LiteralPath "$Global:LogFile.1.log")) 'Literal archive clearing failed'
    }
    foreach ($sourceKey in @('', 'P', 'C', 'F', '0', 'direct', 'path')) {
        Test-Case "GUI checksum source without discovery '$sourceKey'" {
            Reset-Case
            $Global:Settings.UseFileDialog = $true
            function Find-ChecksumFiles { @() }
            function Select-File { $script:Manifest }
            $script:Manifest = Join-Path $script:CaseRoot 'reference.sha256'
            [IO.File]::WriteAllText($script:Manifest, $script:Hash)
            $script:Answers = [Collections.Generic.Queue[string]]::new()
            $script:Answers.Enqueue($(if ($sourceKey -eq 'direct') { $script:Hash } elseif ($sourceKey -eq 'path') { $script:Manifest } else { $sourceKey }))
            if ($sourceKey -in @('','P')) { $script:Answers.Enqueue($script:Hash) }
            if ($sourceKey -eq 'C') { $script:Answers.Enqueue('y') }
            $value = Get-ExpectedChecksumInteractive -TargetFile $script:Target
            if ($sourceKey -eq '0') { Assert ($null -eq $value) 'No-discovery source cancel failed' }
            else { Assert (Test-FileChecksum $script:Target $value).Match 'No-discovery source failed verification' }
        }
    }
    Test-Case 'GUI batch picker selects files and disposes both dialogs' {
        Reset-Case
        $Global:Settings.UseFileDialog = $true
        $script:Manifest = Join-Path $script:CaseRoot 'SHA256SUMS'
        [IO.File]::WriteAllText($script:Manifest, "$script:Hash  sample.bin")
        $script:DisposedDialogs = 0
        function New-Object {
            param($TypeName,$ArgumentList)
            if ($TypeName -notlike '*OpenFileDialog') { return ,(Microsoft.PowerShell.Utility\New-Object @PSBoundParameters) }
            $dialog = [pscustomobject]@{ InitialDirectory=''; Filter=''; Title=''; Multiselect=$false; FileName=$script:Manifest; FileNames=@($script:Target) }
            $dialog | Add-Member ScriptMethod ShowDialog { 'OK' }
            $dialog | Add-Member ScriptMethod Dispose { $script:DisposedDialogs++ }
            $dialog
        }
        Run-Menu @('B','Q')
        Assert ($script:DisposedDialogs -eq 2) 'Batch dialogs not disposed'
        Assert ($script:Output.ToString().Contains('1 of 1 files verified')) ("GUI batch did not verify: " + $script:Output.ToString())
    }
    Test-Case 'Large-file confirmation cancel and Enter default' {
        Reset-Case
        $Global:Settings.LargeFileSizeWarningGB = 1.0 / 1GB
        $script:Answers = [Collections.Generic.Queue[string]]::new()
        foreach ($answer in @($script:Target,'n',$script:Target,'')) { $script:Answers.Enqueue($answer) }
        Assert ($null -eq (Select-File -ShowFileInfo)) 'Large-file cancel failed'
        Assert ((Select-File -ShowFileInfo) -eq $script:Target) 'Large-file Enter default failed'
    }
} finally {
    $resolved = [IO.Path]::GetFullPath($root)
    if ($resolved.StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()), [StringComparison]::OrdinalIgnoreCase) -and [IO.Path]::GetFileName($resolved) -like 'ChecksumMenus_*') {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
Microsoft.PowerShell.Utility\Write-Host "$count menu tests, $failures failures. PowerShell $($PSVersionTable.PSVersion)."
if ($failures) { exit 1 }
