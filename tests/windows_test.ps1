#requires -Version 5.1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$ProgressPreference = 'SilentlyContinue'
$repo = Split-Path $PSScriptRoot -Parent
$scanner = Join-Path $repo 'Test-AgentFrameworkExposure.ps1'
$fixture = Join-Path ([System.IO.Path]::GetTempPath()) ('af-windows-test-' + [guid]::NewGuid().ToString('N'))
$sequence = 0
$assertions = 0
$cases = 0
Add-Type -AssemblyName System.IO.Compression
[void][System.IO.Directory]::CreateDirectory($fixture)

function Assert {
    param([bool] $Condition, [string] $Message)
    $script:assertions++
    if (-not $Condition) { throw $Message }
}

function Write-Fixture {
    param([string] $Path, [string] $Text = 'inert fixture; never execute')
    [void][System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName('\\?\' + $Path))
    [System.IO.File]::WriteAllText('\\?\' + $Path, $Text)
}

function New-Scope {
    $script:cases++
    $path = Join-Path $fixture "scope-$cases"
    [void][System.IO.Directory]::CreateDirectory($path)
    $path
}

function Scan {
    param([hashtable] $Parameters, [string] $Script = $scanner)
    $script:sequence++
    $path = Join-Path $fixture "report-$sequence.json"
    $Parameters.ReportPath = $path
    $result = & $Script @Parameters 6>$null
    $code = $LASTEXITCODE
    Assert ($code -eq $result.ExitCode) 'Returned object and process result differ.'
    $json = [System.IO.File]::ReadAllText($path) | ConvertFrom-Json
    Assert ($json.ExitCode -eq $code) 'Saved JSON exit code differs.'
    Assert ($json.CoverageStatus -eq $result.CoverageStatus) 'Saved coverage differs.'
    $htmlPath = [System.IO.Path]::ChangeExtension($path, '.html')
    Assert ([System.IO.File]::Exists($htmlPath)) 'HTML companion missing.'
    [pscustomobject]@{ Data = $json; Html = [System.IO.File]::ReadAllText($htmlPath); Path = $path }
}

function Write-Archive {
    param([string] $Path, [System.Collections.IDictionary] $Entries)
    $zip = [System.IO.Compression.ZipArchive]::new(
        [System.IO.File]::Create('\\?\' + $Path), [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($name in $Entries.Keys) {
            $writer = [System.IO.StreamWriter]::new($zip.CreateEntry($name).Open())
            try { $writer.Write([string]$Entries[$name]) }
            finally { $writer.Dispose() }
        }
    }
    finally { $zip.Dispose() }
}

function New-FaultScanner {
    param([string] $Body, [string] $Needle = '    $Directory.EnumerateFileSystemInfos()')
    $script:sequence++
    $path = Join-Path $fixture "fault-scanner-$sequence.ps1"
    $source = [System.IO.File]::ReadAllText($scanner)
    Assert ($source.Contains($Needle)) 'Fault-injection seam changed.'
    # Faults exist only in this private copy, never in the distributed scanner.
    [System.IO.File]::WriteAllText($path, $source.Replace($Needle, $Body))
    $path
}

function Remove-FixtureDirectory {
    param([string] $Path)
    foreach ($entry in [System.IO.DirectoryInfo]::new('\\?\' + $Path).EnumerateFileSystemInfos()) {
        $display = $entry.FullName.Replace('\\?\', '')
        if ($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            [System.IO.Directory]::Delete($display)
        }
        elseif ($entry -is [System.IO.DirectoryInfo]) { Remove-FixtureDirectory $display }
        else { [System.IO.File]::Delete($entry.FullName) }
    }
    [System.IO.Directory]::Delete('\\?\' + $Path)
}

try {
    $scope = New-Scope
    Write-Fixture "$scope\requirements.txt" 'agent-framework==1.26.2'
    Write-Fixture "$scope\agent_framework-1.26.1.dist-info\METADATA" "Name: agent-framework`nVersion: 1.26.1`n"
    $result = Scan @{ Roots = @($scope) }
    Assert ($result.Data.ExitCode -eq 0 -and $result.Data.CoverageStatus -eq 'Complete') 'Quick inspected metadata/dependency contents.'
    Assert ($result.Data.FindingStatus -eq 'NoIndicatorsFound' -and $result.Data.CandidateFilesExamined -eq 0) 'Quick candidate accounting failed.'
    Assert ($result.Data.AccessPreflight.Count -eq 1 -and $result.Data.AccessPreflight[0].Accessible) 'Enumeration preflight missing.'
    $result = Scan @{ Roots = @($scope); Mode = 'Deep' }
    Assert ($result.Data.ExitCode -eq 3 -and $result.Data.Findings.Count -eq 2) 'Deep affected package/dependency checks failed.'

    $scope = New-Scope
    $locks = [System.Collections.Generic.List[System.IO.FileStream]]::new()
    try {
        foreach ($name in @('.git\agent_framework_meta.pth', 'af_runtime_diag.pth', 'af_runtime_diag.py', 'agent_framework_meta\_telemetry.py')) {
            Write-Fixture "$scope\$name"
            $locks.Add([System.IO.File]::Open("$scope\$name", [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None))
        }
        Write-Fixture "$scope\_telemetry.py"
        $result = Scan @{ Roots = @($scope) }
        Assert ($result.Data.Findings.Count -eq 4 -and $result.Data.Errors.Count -eq 0) 'Quick read locked contents, missed .git, or flagged unrelated helper.'
        Assert ($result.Data.ScopePolicy.GitDirectoriesIncluded) '.git scope policy missing.'
    }
    finally { foreach ($lock in $locks) { $lock.Dispose() } }

    $scope = New-Scope
    $entries = [ordered]@{
        'agent_framework_meta.pth' = 'inert'
        'af_runtime_diag.pth' = 'inert'
        'af_runtime_diag.py' = 'inert'
        'agent_framework_meta/_telemetry.py' = 'inert'
        'agent_framework-1.26.2.dist-info/METADATA' = "Name: agent-framework`nVersion: 1.26.2`n"
    }
    Write-Archive "$scope\cached.body" $entries
    Write-Fixture "$scope\ordinary.body" 'not a ZIP'
    $unusual = 'nested/' + [char]0xe9 + '&/af_runtime_diag.py'
    if ($PSVersionTable.PSVersion.Major -ge 7) { $unusual = 'nested/' + [char]0xe9 + "`t`n<script>&/af_runtime_diag.py" }
    Write-Archive "$scope\unicode.whl" ([ordered]@{ $unusual = 'inert' })
    $result = Scan @{ Roots = @($scope); Mode = 'Deep' }
    Assert ($result.Data.ExitCode -eq 3 -and $result.Data.Findings.Count -eq 6) 'Archive indicator parity failed.'
    Assert (@($result.Data.Findings | Where-Object Kind -eq 'CachedHelperModule').Count -eq 3) 'Archive helpers not classified.'
    Assert (@($result.Data.Findings | Where-Object { $_.Path -eq "$scope\unicode.whl::$unusual" }).Count -eq 1) 'UTF-8/control-character archive path did not round-trip.'
    Assert ($result.Html -notmatch '<script(?:\s|>)') 'File-derived markup was not escaped.'
    $invalidRoot = "$scope\" + [char]0xe9 + "`t`n<script>&"
    $escaped = Scan @{ Roots = @($invalidRoot) }
    Assert ($escaped.Data.Errors[0].Path -eq $invalidRoot -and $escaped.Data.RequestedRoots[0] -eq $invalidRoot) 'UTF-8/control-character diagnostic path did not round-trip.'
    Assert ($escaped.Html.Contains('&lt;script&gt;&amp;') -and $escaped.Html -notmatch '<script(?:\s|>)') 'Diagnostic markup was not escaped.'

    $scope = New-Scope
    $outside = Join-Path $fixture 'outside'
    Write-Fixture "$outside\af_runtime_diag.py"
    foreach ($name in @('agent_framework_meta.pth', 'af_runtime_diag.pth', 'af_runtime_diag.py', 'agent_framework_meta\_telemetry.py')) {
        [void][System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName("$scope\$name"))
        New-Item -ItemType Junction -Path "$scope\$name" -Target $outside | Out-Null
    }
    $missingTarget = Join-Path $fixture 'missing-target'
    [void][System.IO.Directory]::CreateDirectory($missingTarget)
    New-Item -ItemType Junction -Path "$scope\broken" -Target $missingTarget | Out-Null
    [System.IO.Directory]::Delete($missingTarget)
    1..25 | ForEach-Object { New-Item -ItemType Junction -Path "$scope\alias-$_" -Target $outside | Out-Null }
    $result = Scan @{ Roots = @($scope) }
    Assert ($result.Data.ExitCode -eq 4 -and $result.Data.CoverageStatus -eq 'Incomplete') 'Findings hid link coverage gaps.'
    Assert ($result.Data.Findings.Count -eq 4 -and $result.Data.CandidateFilesExamined -eq 0) 'Link names were missed or targets followed.'
    Assert ($result.Data.ReparsePoints.Count -eq 30 -and $result.Data.SkippedReparsePoints.Count -eq 30) 'Full link evidence not retained.'
    Assert (@($result.Data.Findings | Where-Object { $_.Evidence -notmatch 'name only; target not inspected' }).Count -eq 0) 'Link-name evidence lacks qualification.'
    Assert ([regex]::Matches($result.Html, '<li>').Count -lt 40) 'HTML link examples are unbounded.'
    $result = Scan @{ Roots = @("$scope\agent_framework_meta.pth\") }
    Assert ($result.Data.Roots.Count -eq 0 -and $result.Data.Findings.Count -eq 1 -and $result.Data.ExitCode -eq 4) 'Root link was followed or indicator lost.'
    $result = Scan @{ Roots = @("$scope\agent_framework_meta.pth\child", $outside) }
    Assert ($result.Data.ExitCode -eq 4 -and $result.Data.Errors.Count -eq 1) 'Invalid root prevented remaining roots.'
    $result = Scan @{ Roots = @("$scope\agent_framework_meta.pth") ; DiscoverPython = $true; DiscoveryRoots = @("$scope\agent_framework_meta.pth") }
    Assert ($result.Data.PythonDiscovery.Environments.Count -eq 0 -and $result.Data.SkippedReparsePoints.Count -eq 1) 'Discovery followed or duplicated links.'

    $scope = New-Scope
    Write-Fixture "$scope\alias.exe"
    Write-Fixture "$scope\cloud.whl" 'PK invalid; must not read'
    $fake = New-FaultScanner @'
    foreach ($entry in $Directory.EnumerateFileSystemInfos()) {
        if ($entry.Name -eq 'alias.exe') { $entry | Add-Member NoteProperty Attributes ([System.IO.FileAttributes]::ReparsePoint) -Force }
        if ($entry.Name -eq 'cloud.whl') { $entry | Add-Member NoteProperty Attributes ([System.IO.FileAttributes]::Offline) -Force }
        $entry
    }
'@
    $result = Scan @{ Roots = @($scope); Mode = 'Deep' } $fake
    Assert ($result.Data.Errors.Count -eq 0 -and $result.Data.ReparsePoints.Count -eq 2) 'Cloud placeholder was read or evidence lost.'
    Assert (@($result.Data.ReparsePoints | Where-Object CoverageGap).Count -eq 1) 'Executable alias created a false coverage gap.'
    Assert ($result.Html -notmatch '<li>[^<]*alias\.exe</li>') 'Executable alias leaked into coverage examples.'
    [System.IO.File]::Delete("$scope\cloud.whl")
    $result = Scan @{ Roots = @($scope) } $fake
    Assert ($result.Data.ExitCode -eq 0 -and $result.Data.ReparsePoints.Count -eq 1) 'Executable alias alone makes coverage incomplete.'
    New-Item -ItemType Junction -Path "$scope\directory.exe" -Target $outside | Out-Null
    $result = Scan @{ Roots = @($scope) } $fake
    Assert ($result.Data.ExitCode -eq 2) 'Directory link named .exe was wrongly ignored.'

    $scope = New-Scope
    $metadata = "Name: agent-framework`nVersion: 1.26.0`n"
    Write-Fixture "$scope\agent_framework-1.26.0.dist-info\METADATA" ($metadata + '#' * (1MB - $metadata.Length))
    Write-Fixture "$scope\requirements-exact.txt" ('#' * 8MB)
    $result = Scan @{ Roots = @($scope); Mode = 'Deep' }
    Assert ($result.Data.Errors.Count -eq 0 -and $result.Data.PackageInventory.Count -eq 1) 'Exact read limits were incorrectly rejected.'
    Write-Fixture "$scope\agent_framework-1.26.0.dist-info\METADATA" ('#' * (1MB + 1))
    Write-Fixture "$scope\requirements-large.txt" ('#' * (8MB + 1))
    Write-Archive "$scope\large.whl" ([ordered]@{
        'agent_framework-1.26.2.dist-info/METADATA' = '#' * (1MB + 1)
        'af_runtime_diag.py' = 'inert'
    })
    $result = Scan @{ Roots = @($scope); Mode = 'Deep' }
    Assert ($result.Data.ExitCode -eq 4 -and $result.Data.Errors.Count -eq 3) 'Read limits hid findings or coverage gaps.'
    Assert (@($result.Data.Errors | Where-Object Category -eq 'InspectionLimit').Count -eq 3) 'Read limits misclassified.'
    Assert (@($result.Data.Errors | Where-Object { $_.Path -like '*::*METADATA' }).Count -eq 1) 'Archive limit lacks exact entry path.'

    $scope = New-Scope
    $faulted = Join-Path $scope 'faulted'
    Write-Fixture "$faulted\af_runtime_diag.py"
    foreach ($kind in @('Disappeared', 'Interrupted')) {
        $body = @'
    if ($Directory.Name -eq 'faulted') {
        if (-not (Get-Variable fixtureAttempt -Scope Script -ErrorAction SilentlyContinue)) { $script:fixtureAttempt = 0 }
        $script:fixtureAttempt++
        if ($script:fixtureAttempt -eq 1) {
            $Directory.GetFiles()[0]
            THROW_FIXTURE
        }
    }
    $Directory.EnumerateFileSystemInfos()
'@
        $failure = if ($kind -eq 'Disappeared') { "throw [System.IO.DirectoryNotFoundException]::new('Original disappeared fixture diagnostic.')" }
            else { "throw [System.IO.IOException]::new('Original interrupted fixture diagnostic.', -2147023901)" }
        $fake = New-FaultScanner ($body.Replace('THROW_FIXTURE', $failure))
        $result = Scan @{ Roots = @($scope) } $fake
        Assert ($result.Data.ExitCode -eq 3 -and $result.Data.Findings.Count -eq 1 -and $result.Data.FilesScanned -eq 1) 'Partial candidates lost or duplicated on retry.'
        Assert ($result.Data.Errors.Count -eq 1 -and $result.Data.Errors[0].Category -eq $kind) 'Original retry diagnostic not retained/classified.'
        Assert ($result.Data.Errors[0].Resolved -and $result.Data.Errors[0].RetryOutcome -eq 'DirectoryReenumerated') 'Recovery outcome not recorded.'
        Assert ($result.Data.UnresolvedErrorCount -eq 0 -and $result.Data.DirectorySearches.Count -eq 2) 'Recovered error counted as coverage gap or duplicate.'
    }
    $fake = New-FaultScanner @'
    if ($Directory.Name -eq 'faulted') {
        $Directory.GetFiles()[0]
        throw [System.IO.IOException]::new('Repeated interrupted fixture diagnostic.', -2147023901)
    }
    $Directory.EnumerateFileSystemInfos()
'@
    $result = Scan @{ Roots = @($scope) } $fake
    Assert ($result.Data.ExitCode -eq 4 -and $result.Data.UnresolvedErrorCount -eq 2) 'Repeated interruption was hidden.'
    Assert ($result.Data.DirectorySearches.Count -eq 2 -and $result.Data.Errors[1].RetryOutcome -eq 'RetryLimitReached') 'Directory retry was not bounded.'
    Assert ($result.Data.Findings.Count -eq 1) 'Repeated failure discarded partial findings.'

    $scope = New-Scope
    Write-Fixture "$scope\requirements.txt" 'agent-framework==1.26.2'
    $fake = New-FaultScanner -Needle '    $stream = [System.IO.File]::OpenRead($File.FullName)' -Body @'
    if (-not (Get-Variable fixtureReadAttempt -Scope Script -ErrorAction SilentlyContinue)) {
        $script:fixtureReadAttempt = 1
        throw [System.IO.FileNotFoundException]::new('Original candidate disappeared diagnostic.')
    }
    $stream = [System.IO.File]::OpenRead($File.FullName)
'@
    $result = Scan @{ Roots = @($scope); Mode = 'Deep' } $fake
    Assert ($result.Data.ExitCode -eq 3 -and $result.Data.CandidateFilesExamined -eq 1) 'Candidate retry lost finding or duplicated count.'
    Assert ($result.Data.Errors.Count -eq 1 -and $result.Data.Errors[0].Resolved -and $result.Data.Errors[0].RetryOutcome -eq 'EntryRescanned') 'Candidate recovery outcome missing.'
    $fake = New-FaultScanner -Needle '    $stream = [System.IO.File]::OpenRead($File.FullName)' -Body @'
    throw [System.IO.FileNotFoundException]::new('Repeated candidate disappearance.')
'@
    $result = Scan @{ Roots = @($scope); Mode = 'Deep' } $fake
    Assert ($result.Data.ExitCode -eq 2 -and $result.Data.Errors.Count -eq 2 -and $result.Data.UnresolvedErrorCount -eq 2) 'Repeated candidate failure was ignored.'
    Assert ($result.Data.Errors[1].RetryOutcome -eq 'RetryLimitReached') 'Candidate retry was not bounded.'
    [System.IO.File]::Delete("$scope\requirements.txt")
    Write-Fixture "$scope\Pipfile.lock" '{"never-report-this-fixture-secret": invalid'
    $result = Scan @{ Roots = @($scope); Mode = 'Deep' }
    Assert ($result.Data.ExitCode -eq 2 -and $result.Data.Errors.Count -eq 1) 'Malformed lockfile was silently accepted.'
    Assert (-not $result.Html.Contains('never-report-this-fixture-secret') -and
        -not [System.IO.File]::ReadAllText($result.Path).Contains('never-report-this-fixture-secret')) 'Inspection error leaked file contents.'

    $scope = New-Scope
    $faulted = Join-Path $scope 'faulted'
    [void][System.IO.Directory]::CreateDirectory($faulted)
    $fake = New-FaultScanner @'
    if ($Directory.Name -eq 'faulted') {
        if (-not (Get-Variable fixtureAttempt -Scope Script -ErrorAction SilentlyContinue)) {
            $script:fixtureAttempt = 1
            [System.IO.Directory]::Delete($Directory.FullName)
            throw [System.IO.DirectoryNotFoundException]::new('Entry disappeared during enumeration.')
        }
        throw 'Retry must not run while the entry is absent.'
    }
    $Directory.EnumerateFileSystemInfos()
'@
    $result = Scan @{ Roots = @($scope) } $fake
    Assert ($result.Data.ExitCode -eq 2 -and $result.Data.Errors[0].RetryOutcome -eq 'StillMissing') 'Missing directory incorrectly retried or ignored.'
    Assert ($result.Data.DirectorySearches.Count -eq 1) 'Still-missing entry caused another search.'

    [void][System.IO.Directory]::CreateDirectory($faulted)
    $targetLiteral = $outside.Replace("'", "''")
    $fake = New-FaultScanner (@'
    if ($Directory.Name -eq 'faulted') {
        [System.IO.Directory]::Delete($Directory.FullName)
        New-Item -ItemType Junction -Path (Get-DisplayPath $Directory.FullName) -Target 'TARGET_LITERAL' | Out-Null
        throw [System.IO.DirectoryNotFoundException]::new('Entry replaced with an out-of-scope junction.')
    }
    $Directory.EnumerateFileSystemInfos()
'@).Replace('TARGET_LITERAL', $targetLiteral)
    $result = Scan @{ Roots = @($scope) } $fake
    Assert ($result.Data.ExitCode -eq 2 -and $result.Data.Findings.Count -eq 0) 'Retry crossed a physical scope/mount boundary.'
    Assert ($result.Data.Errors[0].RetryOutcome -eq 'OutsideScopeOrUnverifiable' -and $result.Data.DirectorySearches.Count -eq 1) 'Changed boundary did not stop retry.'
    Write-Fixture "$outside\subdirectory\af_runtime_diag.py"
    $result = Scan @{ Roots = @("$faulted\subdirectory") }
    Assert ($result.Data.ExitCode -eq 2 -and $result.Data.Roots.Count -eq 0) 'Root with junction ancestor was traversed.'

    $scope = New-Scope
    $acl = Get-Acl -LiteralPath $scope
    $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $deny = [System.Security.AccessControl.FileSystemAccessRule]::new(
        $sid, [System.Security.AccessControl.FileSystemRights]::ListDirectory, [System.Security.AccessControl.AccessControlType]::Deny)
    $acl.AddAccessRule($deny)
    Set-Acl -LiteralPath $scope -AclObject $acl
    try {
        $result = Scan @{ Roots = @($scope) }
        Assert ($result.Data.ExitCode -eq 2 -and $result.Data.Errors.Count -eq 1) 'Access denial was hidden or duplicated.'
        Assert ($result.Data.Errors[0].Category -eq 'AccessDenied' -and $result.Data.Errors[0].Path -eq $scope) 'Access denial has wrong path/cause.'
        Assert (-not $result.Data.AccessPreflight[0].Accessible) 'Access preflight did not report blocked root.'
        Assert ($result.Data.Errors[0].Error -ne 'MethodInvocationException') 'Underlying filesystem error was hidden.'
    }
    finally { [void]$acl.RemoveAccessRuleSpecific($deny); Set-Acl -LiteralPath $scope -AclObject $acl }

    $scope = New-Scope
    $long = "$scope\$([string]::new('a', 100))\$([string]::new('b', 100))\environment"
    Write-Fixture "$long\Lib\site-packages\af_runtime_diag.pth"
    Write-Fixture "$long\Lib\site-packages\agent_framework-1.26.2.dist-info\METADATA" "Name: agent-framework`nVersion: 1.26.2`n"
    Write-Fixture "$long\Scripts\python.exe"
    Write-Fixture "$long\pyvenv.cfg"
    Write-Archive "$long\cached.body" ([ordered]@{ 'af_runtime_diag.py' = 'inert' })
    $result = Scan @{ Roots = @($scope); Mode = 'Deep'; DiscoverPython = $true; DiscoveryRoots = @($scope) }
    Assert ($result.Data.Errors.Count -eq 0 -and $result.Data.Findings.Count -eq 3) 'Long-path traversal/discovery/archive inspection regressed.'
    Assert ($result.Data.PythonDiscovery.Environments.Count -eq 1 -and $result.Data.PythonDiscovery.Environments[0].Type -eq 'VirtualEnvironment') 'Long-path venv classification failed.'
    Assert (@($result.Data.Findings | Where-Object { $_.Path.StartsWith('\\?\') }).Count -eq 0) 'Internal path prefix leaked into findings.'

    $original = [System.IO.File]::ReadAllText($result.Path)
    $refused = $false
    try { & $scanner -Roots $scope -ReportPath $result.Path 6>$null | Out-Null }
    catch { $refused = $true }
    Assert ($refused -and [System.IO.File]::ReadAllText($result.Path) -eq $original) 'Existing report overwritten.'
    $collision = Join-Path $fixture 'html-only.html'
    Write-Fixture $collision 'preserve HTML'
    $refused = $false
    try { & $scanner -Roots $scope -ReportPath ([System.IO.Path]::ChangeExtension($collision, '.json')) 6>$null | Out-Null }
    catch { $refused = $true }
    Assert ($refused -and [System.IO.File]::ReadAllText($collision) -eq 'preserve HTML') 'HTML-only collision not preserved.'
    Assert (-not [System.IO.File]::Exists([System.IO.Path]::ChangeExtension($collision, '.json'))) 'JSON created despite HTML collision.'
    $scope = New-Scope
    Write-Fixture "$scope\truncated.zip" 'PK'
    $result = Scan @{ Roots = @($scope); Mode = 'Deep' }
    Assert ($result.Data.ExitCode -eq 2 -and $result.Data.Errors.Count -eq 1) 'Corrupt archive was accepted or diagnostics duplicated.'
    Assert ($result.Data.Errors[0].Error -ne 'MethodInvocationException') 'Archive error hid its underlying cause.'
    $scope = New-Scope
    $caseEntries = [System.Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
    $caseEntries.Add('Case/af_runtime_diag.py', 'inert')
    $caseEntries.Add('case/af_runtime_diag.py', 'inert')
    Write-Archive "$scope\case-sensitive.zip" $caseEntries
    $result = Scan @{ Roots = @($scope); Mode = 'Deep' }
    Assert ($result.Data.ExitCode -eq 3 -and $result.Data.Findings.Count -eq 2) 'Distinct archive paths were collapsed by case-insensitive deduplication.'

    $scope = New-Scope
    $tools = Join-Path $fixture 'Tools & checks!'
    $profile = Join-Path $fixture 'User & checks!'
    [void][System.IO.Directory]::CreateDirectory($tools)
    [void][System.IO.Directory]::CreateDirectory($profile)
    $oldProfile = $env:USERPROFILE
    try {
        $env:USERPROFILE = $profile
        foreach ($launcher in @('Run-QuickScan.cmd', 'Run-FullScan.cmd')) {
            Copy-Item -LiteralPath (Join-Path $repo $launcher) -Destination $tools
            foreach ($code in @(0, 1, 2, 3, 4, 7)) {
                Write-Fixture "$tools\Test-AgentFrameworkExposure.ps1" (
                    'param($Mode,$Scope,$ReportPath)' + "`r`n" +
                    '$PSBoundParameters | ConvertTo-Json | Set-Content -LiteralPath ($ReportPath + ".args")' + "`r`nexit $code")
                $inputFile = Join-Path $fixture 'input.txt'
                Write-Fixture $inputFile "Y`r`n`r`n"
                $output = & $env:ComSpec /d /v:off /c ('call "' + "$tools\$launcher" + '" < "' + $inputFile + '"') 2>&1
                $actual = $LASTEXITCODE
                $output = $output -join "`n"
                Assert ($actual -eq $code) "Launcher $launcher changed exit code $code : $output"
                $label = switch ($code) { 0 { 'Open this report' }; 2 { 'WARNING:' }; 3 { 'ALERT:' }; 4 { 'ALERT:' }; default { 'ERROR:' } }
                Assert ($output.Contains($label)) "Launcher $launcher mislabeled $code : $output"
                if ($code -in @(0, 2, 3, 4)) { Assert (-not $output.Contains('ERROR:')) 'Usable report mislabeled as fatal failure.' }
            }
        }
        $arguments = @(Get-ChildItem -LiteralPath $profile -Filter '*.args' | ForEach-Object {
            Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json
        })
        Assert (@($arguments | Where-Object { $_.Mode -eq 'Quick' -and $_.Scope -eq 'UserProfile' }).Count -eq 6) 'Quick launcher scope changed.'
        Assert (@($arguments | Where-Object { $_.Mode -eq 'Deep' -and $_.Scope -eq 'FixedDrives' }).Count -eq 6) 'Full launcher scope changed.'
        $before = @(Get-ChildItem -LiteralPath $profile).Count
        Write-Fixture $inputFile "N`r`n`r`n"
        $output = & $env:ComSpec /d /v:off /c ('call "' + "$tools\Run-FullScan.cmd" + '" < "' + $inputFile + '"') 2>&1
        Assert ($LASTEXITCODE -eq 0 -and ($output -join "`n").Contains('Cancelled')) 'Full scan cancellation failed.'
        Assert (@(Get-ChildItem -LiteralPath $profile).Count -eq $before) 'Cancellation launched a scanner.'

        $childHome = & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -Command '$HOME'
        Assert ($childHome -eq $profile) 'Refusing real Quick launcher test outside the isolated profile.'
        Copy-Item -LiteralPath $scanner -Destination "$tools\Test-AgentFrameworkExposure.ps1" -Force
        Write-Fixture "$profile\af_runtime_diag.py"
        Write-Fixture $inputFile "`r`n"
        $output = & $env:ComSpec /d /v:off /c ('call "' + "$tools\Run-QuickScan.cmd" + '" < "' + $inputFile + '"') 2>&1
        Assert ($LASTEXITCODE -eq 3 -and ($output -join "`n").Contains('ALERT:')) 'Real Quick launcher lost incident exit code.'
        $reports = @(Get-ChildItem -LiteralPath $profile -Filter '*.json')
        Assert ($reports.Count -eq 1 -and [System.IO.File]::Exists([System.IO.Path]::ChangeExtension($reports[0].FullName, '.html'))) 'Real Quick launcher report pair missing.'
    }
    finally { $env:USERPROFILE = $oldProfile }

    "PASS: $cases Windows fixture groups; $assertions assertions; PowerShell $($PSVersionTable.PSVersion). No Python or real full-drive scan started."
}
catch { Write-Host "FAIL: $_`n$($_.ScriptStackTrace)"; throw }
finally { Remove-FixtureDirectory $fixture }
exit 0
