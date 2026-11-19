#requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('Quick', 'Deep')]
    [string] $Mode = 'Quick',
    [ValidateSet('UserProfile', 'FixedDrives')]
    [string] $Scope = 'UserProfile',
    [string[]] $Roots,
    [switch] $DiscoverPython,
    [ValidateSet('UserProfile', 'FixedDrives')]
    [string] $DiscoveryScope = 'UserProfile',
    [string[]] $DiscoveryRoots,
    [string] $ReportPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$startedUtc = [DateTime]::UtcNow
if ($ReportPath) {
    $fullReportPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ReportPath)
    if ([System.IO.Path]::GetExtension($fullReportPath) -ne '.json') {
        throw 'ReportPath must end in .json; a matching .html report is generated alongside it.'
    }
    $htmlReportPath = [System.IO.Path]::ChangeExtension($fullReportPath, '.html')
    if (Test-Path -LiteralPath $fullReportPath) { throw 'Report already exists; choose a new ReportPath to preserve evidence.' }
    if (Test-Path -LiteralPath $htmlReportPath) { throw 'HTML report already exists; choose a new ReportPath to preserve evidence.' }
    if (-not (Test-Path -LiteralPath ([System.IO.Path]::GetDirectoryName($fullReportPath)) -PathType Container)) {
        throw 'Report parent directory does not exist.'
    }
}
if (-not $DiscoverPython -and ($PSBoundParameters.ContainsKey('DiscoveryScope') -or $DiscoveryRoots)) {
    throw 'Use -DiscoverPython with -DiscoveryScope or -DiscoveryRoots.'
}
$findings = [System.Collections.Generic.List[object]]::new()
$packages = [System.Collections.Generic.List[object]]::new()
$scanErrors = [System.Collections.Generic.List[object]]::new()
$skippedLinks = [System.Collections.Generic.List[string]]::new()
$discoveryLocations = [System.Collections.Generic.List[string]]::new()
$environments = [System.Collections.Generic.List[object]]::new()
$environmentRoots = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$hashes = @{
    'd27fa34414e6201d5e03e559ef634f020057554d7b3f4898dd5d7cd3e989e110' = '1.26.1'
    '3d20a8bc91351a9a16b6db243b848ceca0206b7a8623b02d2af553a9c9f7e0a9' = '1.26.2'
}
$hookNames = @('agent_framework_meta.pth', 'af_runtime_diag.pth')
$filesScanned = 0

function ConvertTo-ReportTable {
    param([object[]] $Rows, [string[]] $Columns)
    if (-not $Rows.Count) { return '<p>None recorded.</p>' }
    $html = [System.Text.StringBuilder]::new()
    [void]$html.Append('<div class="scroll"><table><thead><tr>')
    foreach ($column in $Columns) {
        [void]$html.Append('<th>' + [System.Net.WebUtility]::HtmlEncode($column) + '</th>')
    }
    [void]$html.Append('</tr></thead><tbody>')
    foreach ($row in $Rows) {
        [void]$html.Append('<tr>')
        foreach ($column in $Columns) {
            [void]$html.Append('<td>' + [System.Net.WebUtility]::HtmlEncode([string]$row.$column) + '</td>')
        }
        [void]$html.Append('</tr>')
    }
    [void]$html.Append('</tbody></table></div>')
    $html.ToString()
}

function ConvertTo-ReportList {
    param([object[]] $Items)
    if (-not $Items.Count) { return '<p>None recorded.</p>' }
    '<ul>' + (($Items | ForEach-Object {
        '<li>' + [System.Net.WebUtility]::HtmlEncode([string]$_) + '</li>'
    }) -join '') + '</ul>'
}

function ConvertTo-ExposureHtml {
    param([object] $Report)
    $computer = [System.Net.WebUtility]::HtmlEncode([string]$Report.ComputerName)
    $modeText = [System.Net.WebUtility]::HtmlEncode([string]$Report.Mode)
    $scopeText = [System.Net.WebUtility]::HtmlEncode([string]$Report.Scope)
    $time = [System.Net.WebUtility]::HtmlEncode([string]$Report.ScanTimeUtc)
    $statusText = [System.Net.WebUtility]::HtmlEncode([string]$Report.Status)
    $findingsTable = ConvertTo-ReportTable $Report.Findings @('Kind', 'LocationType', 'Path', 'Evidence')
    $packagesTable = ConvertTo-ReportTable $Report.PackageInventory @('Version', 'Kind', 'Path')
    $errorsTable = ConvertTo-ReportTable $Report.Errors @('Operation', 'Path', 'Error')
    $rootsList = ConvertTo-ReportList $Report.Roots
    $skippedList = ConvertTo-ReportList $Report.SkippedReparsePoints
    $limitationsList = ConvertTo-ReportList $Report.Limitations
    $discoveryTable = ConvertTo-ReportTable $Report.PythonDiscovery.Environments @('Type', 'Root', 'DiscoveredBy')
    $message = switch ($Report.Status) {
        'IndicatorsFound' { 'Indicators need security-team review. Preserve evidence and avoid starting suspect Python environments.' }
        'Incomplete' { 'No indicators found, but coverage gaps prevent a complete inspection.' }
        default { 'No matching indicators found in the inspected scope. This is not proof that the machine is safe.' }
    }
    @"
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Agent Framework exposure report</title>
<style>
body{font:16px/1.5 system-ui,sans-serif;color:#17233b;background:#f3f5f9;margin:0}
main{max-width:1200px;margin:32px auto;padding:28px;background:white;border-radius:12px}
h1,h2{line-height:1.2}h2{margin-top:32px}.notice{padding:18px;border-left:5px solid #a85800;background:#fff3dc}
.summary{display:flex;flex-wrap:wrap;gap:24px;padding:18px 0}.scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;vertical-align:top;padding:10px;border:1px solid #d5dce7}
th{background:#edf1f7}td,li{overflow-wrap:anywhere;white-space:pre-wrap}small{color:#48566d}
@media(max-width:700px){main{margin:0;padding:16px}}
</style></head><body><main>
<h1>Agent Framework exposure report</h1>
<p><strong>Computer:</strong> $computer<br><strong>Mode:</strong> $modeText |
<strong>Scope:</strong> $scopeText | <strong>Completed (UTC):</strong> $time</p>
<div class="notice"><strong>$statusText</strong><p>$message</p>
<p>Completion does not establish safety. Errors and skipped locations remain important even when indicators are found.
This tool does not verify execution, prove credential theft, or remediate anything.</p></div>
<div class="summary"><span><strong>Findings:</strong> $($Report.Findings.Count)</span>
<span><strong>Errors:</strong> $($Report.Errors.Count)</span><span><strong>Skipped links:</strong> $($Report.SkippedReparsePoints.Count)</span>
<span><strong>Files enumerated:</strong> $($Report.FilesScanned)</span><span><strong>Seconds:</strong> $($Report.DurationSeconds)</span></div>
<h2>Findings</h2>$findingsTable
<p>SitePackages is a path-based triage aid, not proof of installation or execution. Archives may never have been installed.</p>
<h2>Inspection roots</h2>$rootsList
<h2>Coverage errors</h2>$errorsTable
<h2>Skipped links and junctions</h2>$skippedList
<h2>Package inventory (Deep mode only)</h2>$packagesTable
<h2>Optional environment discovery</h2>$discoveryTable
<h2>Limitations</h2>$limitationsList
<p><small>Share this report and its JSON companion only through your approved security/IT process.
Reports can contain internal paths and computer names. No external resources or scripts are loaded by this page.</small></p>
</main></body></html>
"@
}

function Add-Finding {
    param([string] $Kind, [string] $Path, [string] $Evidence)
    $locationType = if ($Kind -in @('CachedPackage', 'CachedStartupHook', 'KnownMaliciousWheelHash')) { 'Archive' }
        elseif ($Path -match '(?i)[\\/]site-packages[\\/]') { 'SitePackages' }
        else { 'OtherOnDisk' }
    $findings.Add([pscustomobject]@{
        Kind = $Kind; Path = $Path; LocationType = $locationType; Evidence = $Evidence
    })
}

function Read-PackageMetadata {
    param([string] $Text, [string] $Path, [string] $Kind)
    if ($Text -match '(?im)^Name:\s*agent[-_.]framework\s*$' -and
        $Text -match '(?im)^Version:\s*(\S+)\s*$') {
        $version = $Matches[1]
        $packages.Add([pscustomobject]@{ Version = $version; Path = $Path; Kind = $Kind })
        if ($version -in @('1.26.1', '1.26.2')) {
            Add-Finding $Kind $Path "agent-framework==$version"
        }
    }
}

function Read-DependencyFile {
    param([System.IO.FileInfo] $File)
    $text = [System.IO.File]::ReadAllText($File.FullName)
    if ($File.Name -eq 'Pipfile.lock') {
        $lock = $text | ConvertFrom-Json
        foreach ($group in $lock.PSObject.Properties) {
            if ($null -eq $group.Value) { continue }
            foreach ($package in $group.Value.PSObject.Properties) {
                if ($package.Name -match '^agent[-_.]framework$' -and
                    $package.Value.version -match '^==1\.26\.[12]$') {
                    Add-Finding 'DependencyReference' $File.FullName "agent-framework$($package.Value.version)"
                }
            }
        }
        return
    }
    if ($File.Extension -eq '.lock') {
        foreach ($block in [regex]::Split($text, '(?m)^\s*\[\[package\]\]\s*$')) {
            if ($block -match '(?im)^\s*name\s*=\s*["'']agent[-_.]framework["'']\s*$' -and
                $block -match '(?im)^\s*version\s*=\s*["''](1\.26\.[12])["'']\s*$') {
                Add-Finding 'DependencyReference' $File.FullName "agent-framework==$($Matches[1])"
            }
        }
    }
    # Emit only the package/version, never full lines that might contain credentials.
    foreach ($match in [regex]::Matches($text, '(?im)(?<![\w.-])agent[-_.]framework(?:\[[^\]\r\n]*\])?\s*(?:===|==|@|=)\s*["'']?(1\.26\.[12])(?![\w.])')) {
        Add-Finding 'DependencyReference' $File.FullName "agent-framework==$($match.Groups[1].Value)"
    }
    foreach ($match in [regex]::Matches($text, '(?i)agent[-_]framework-(1\.26\.[12])(?![\w.])')) {
        Add-Finding 'DependencyReference' $File.FullName "artifact reference: agent-framework $($match.Groups[1].Value)"
    }
}

function Read-CachedArchive {
    param([System.IO.FileInfo] $File)
    $hash = (Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hashes.ContainsKey($hash)) {
        Add-Finding 'KnownMaliciousWheelHash' $File.FullName "agent-framework==$($hashes[$hash]); SHA256=$hash"
    }
    $stream = [System.IO.File]::OpenRead($File.FullName)
    try {
        # pip HTTP bodies are not necessarily ZIP files.
        if ($stream.ReadByte() -ne 0x50 -or $stream.ReadByte() -ne 0x4b) { return }
        $stream.Position = 0
        $archive = [System.IO.Compression.ZipArchive]::new(
            $stream, [System.IO.Compression.ZipArchiveMode]::Read, $true)
        try {
            foreach ($entry in $archive.Entries) {
                $leaf = ($entry.FullName -split '/')[-1]
                if ($leaf -in $hookNames) {
                    Add-Finding 'CachedStartupHook' "$($File.FullName)::$($entry.FullName)" $leaf
                }
                if ($entry.FullName -match '(?i)(^|/)agent[-_.]framework-[^/]+\.dist-info/METADATA$') {
                    if ($entry.Length -gt 1MB) { throw 'Package METADATA exceeds the 1 MiB inspection limit.' }
                    $reader = [System.IO.StreamReader]::new($entry.Open())
                    try {
                        Read-PackageMetadata $reader.ReadToEnd() "$($File.FullName)::$($entry.FullName)" 'CachedPackage'
                    }
                    finally { $reader.Dispose() }
                }
            }
        }
        finally { $archive.Dispose() }
    }
    finally { $stream.Dispose() }
}

function Add-DiscoveredEnvironment {
    param([System.IO.FileInfo] $File)
    $environmentRoot = $File.Directory.FullName
    if ($File.Name -eq 'python.exe' -and $File.Directory.Name -eq 'Scripts') {
        $environmentRoot = $File.Directory.Parent.FullName
    }
    $type = 'InterpreterDirectory'
    if (Test-Path -LiteralPath (Join-Path $environmentRoot 'pyvenv.cfg') -PathType Leaf) {
        $type = 'VirtualEnvironment'
    }
    elseif (Test-Path -LiteralPath (Join-Path $environmentRoot 'conda-meta') -PathType Container) {
        $type = 'CondaEnvironment'
    }
    if ($environmentRoots.Add($environmentRoot)) {
        $environments.Add([pscustomobject]@{
            Root = $environmentRoot
            Type = $type
            DiscoveredBy = $File.FullName
        })
    }
}

function Find-PythonEnvironments {
    param([string[]] $SearchRoots)
    $directories = [System.Collections.Generic.Stack[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($searchRoot in $SearchRoots) {
        try {
            $item = Get-Item -LiteralPath $searchRoot -Force
            if (-not $item.PSIsContainer) { throw 'Discovery root is not a directory.' }
            $discoveryLocations.Add($item.FullName)
            $directories.Push($item.FullName)
            Write-Verbose "Python discovery root: $($item.FullName)"
        }
        catch {
            $scanErrors.Add([pscustomobject]@{ Path = $searchRoot; Operation = 'ResolveDiscoveryRoot'; Error = $_.Exception.GetType().Name })
        }
    }
    while ($directories.Count -gt 0) {
        $directory = $directories.Pop()
        if (-not $seen.Add($directory)) { continue }
        try {
            $info = [System.IO.DirectoryInfo]::new($directory)
            if ($info.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                $skippedLinks.Add($directory)
                continue
            }
            if ($seen.Count % 200 -eq 0) {
                Write-Progress -Activity 'Discovering Python environments (no executables are run)' `
                    -Status "$($seen.Count) directories; $($environments.Count) environments found" -CurrentOperation $directory
            }
            foreach ($entry in $info.EnumerateFileSystemInfos()) {
                if ($entry -is [System.IO.FileInfo] -and $entry.Name -in @('python.exe', 'pyvenv.cfg')) {
                    Add-DiscoveredEnvironment $entry
                }
                if ($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                    $skippedLinks.Add($entry.FullName)
                    continue
                }
                if ($entry -is [System.IO.DirectoryInfo] -and $entry.Name -ne '.git') {
                    $directories.Push($entry.FullName)
                }
            }
        }
        catch {
            $scanErrors.Add([pscustomobject]@{ Path = $directory; Operation = 'Discover'; Error = $_.Exception.GetType().Name })
        }
    }
    Write-Progress -Activity 'Discovering Python environments (no executables are run)' -Completed
}

if (-not $Roots) {
    if ($Scope -eq 'FixedDrives') {
        $Roots = @([System.IO.DriveInfo]::GetDrives() |
            Where-Object { $_.DriveType -eq [System.IO.DriveType]::Fixed -and $_.IsReady } |
            ForEach-Object { $_.RootDirectory.FullName })
    }
    else {
        $Roots = @($HOME)
    }
}

Write-Host "Agent Framework exposure check: $Mode mode. No Python or pip will be run."
if ($DiscoverPython) {
    if (-not $DiscoveryRoots) {
        if ($DiscoveryScope -eq 'FixedDrives') {
            $DiscoveryRoots = @([System.IO.DriveInfo]::GetDrives() |
                Where-Object { $_.DriveType -eq [System.IO.DriveType]::Fixed -and $_.IsReady } |
                ForEach-Object { $_.RootDirectory.FullName })
        }
        else {
            $DiscoveryRoots = @($HOME)
        }
    }
    Find-PythonEnvironments $DiscoveryRoots
    $Roots = @($Roots) + @($environments | ForEach-Object { $_.Root })
    $Roots = @($Roots | Sort-Object -Unique)
}

if ($Mode -eq 'Deep') { Add-Type -AssemblyName System.IO.Compression }
$pending = [System.Collections.Generic.Stack[string]]::new()
$visited = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$resolvedRoots = [System.Collections.Generic.List[string]]::new()
foreach ($root in $Roots) {
    try {
        $item = Get-Item -LiteralPath $root -Force
        if (-not $item.PSIsContainer) { throw 'Scan root is not a directory.' }
        $resolvedRoots.Add($item.FullName)
        $pending.Push($item.FullName)
        Write-Host "Inspection root: $($item.FullName)"
    }
    catch {
        $scanErrors.Add([pscustomobject]@{ Path = $root; Operation = 'ResolveRoot'; Error = $_.Exception.GetType().Name })
    }
}

while ($pending.Count -gt 0) {
    $directory = $pending.Pop()
    if (-not $visited.Add($directory)) { continue }
    if ($visited.Count % 200 -eq 0) {
        Write-Progress -Activity "Inspecting Agent Framework exposure ($Mode)" `
            -Status "$filesScanned files; $($visited.Count) directories; $($findings.Count) indicators" -CurrentOperation $directory
    }
    try {
        $directoryInfo = [System.IO.DirectoryInfo]::new($directory)
        if ($directoryInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            $skippedLinks.Add($directory)
            continue
        }
        foreach ($file in $directoryInfo.EnumerateFileSystemInfos()) {
            if ($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                $skippedLinks.Add($file.FullName)
                continue
            }
            if ($file -is [System.IO.DirectoryInfo]) {
                if ($file.Name -ne '.git') { $pending.Push($file.FullName) }
                continue
            }
            $filesScanned++
            try {
                if ($file.Name -in $hookNames) {
                    Add-Finding 'StartupHookOnDisk' $file.FullName $file.Name
                }
                if ($file.Name -eq '_telemetry.py' -and $file.Directory.Name -eq 'agent_framework_meta') {
                    Add-Finding 'HelperModuleOnDisk' $file.FullName 'agent_framework_meta\_telemetry.py'
                }
                if ($file.Name -eq 'af_runtime_diag.py') {
                    Add-Finding 'HelperModuleOnDisk' $file.FullName 'af_runtime_diag.py'
                }
                if ($Mode -eq 'Quick') { continue }
                if ($file.Name -eq 'METADATA' -and $file.Directory.Name -match '^agent[-_.]framework-[^\\]+\.dist-info$') {
                    Read-PackageMetadata ([System.IO.File]::ReadAllText($file.FullName)) $file.FullName 'PackageOnDisk'
                }
                if ($file.Extension -in @('.whl', '.zip', '.body')) { Read-CachedArchive $file }
                if ($file.Name -match '^(requirements.*\.(txt|in)|constraints.*\.txt|uv\.lock|poetry\.lock|pdm\.lock|pylock.*\.toml|Pipfile(\.lock)?|pyproject\.toml|setup\.(cfg|py))$') {
                    Read-DependencyFile $file
                }
            }
            catch {
                $scanErrors.Add([pscustomobject]@{ Path = $file.FullName; Operation = 'Inspect'; Error = $_.Exception.GetType().Name })
            }
        }
    }
    catch {
        $scanErrors.Add([pscustomobject]@{ Path = $directory; Operation = 'Traverse'; Error = $_.Exception.GetType().Name })
    }
}
Write-Progress -Activity "Inspecting Agent Framework exposure ($Mode)" -Completed

$uniqueFindings = @($findings | Sort-Object Kind, Path, Evidence -Unique)
$status = if ($uniqueFindings.Count) { 'IndicatorsFound' }
    elseif ($scanErrors.Count -or $skippedLinks.Count -or -not $resolvedRoots.Count -or
        ($DiscoverPython -and -not $discoveryLocations.Count)) { 'Incomplete' }
    else { 'NoIndicatorsInScannedScope' }
$report = [pscustomobject]@{
    Advisory = 'https://github.com/advisories/GHSA-764m-3ppc-5m73'
    ComputerName = $env:COMPUTERNAME
    Mode = $Mode
    Scope = if ($PSBoundParameters.ContainsKey('Roots')) { 'Custom' } else { $Scope }
    StartedUtc = $startedUtc.ToString('o')
    ScanTimeUtc = [DateTime]::UtcNow.ToString('o')
    DurationSeconds = [Math]::Round(([DateTime]::UtcNow - $startedUtc).TotalSeconds, 1)
    Status = $status
    Roots = @($resolvedRoots.ToArray())
    PythonDiscovery = [pscustomobject]@{
        Enabled = [bool]$DiscoverPython
        Scope = if (-not $DiscoverPython) { 'Disabled' }
            elseif ($PSBoundParameters.ContainsKey('DiscoveryRoots')) { 'Custom' }
            else { $DiscoveryScope }
        Roots = @($discoveryLocations.ToArray())
        Environments = @($environments.ToArray())
    }
    FilesScanned = $filesScanned
    Findings = $uniqueFindings
    PackageInventory = @($packages.ToArray())
    Errors = @($scanErrors.ToArray())
    SkippedReparsePoints = @($skippedLinks.ToArray())
    Limitations = @(
        'Point-in-time file inspection only; no proof of historical absence or successful exfiltration.',
        'The default scope is the current user profile only. Other locations need FixedDrives or explicit Roots.',
        'Quick mode matches hook/helper filenames only; it does not read package metadata, dependency files, or archives, or compute hashes.',
        'Optional discovery searches filenames python.exe and pyvenv.cfg, not archives or other interpreter names; python.exe alone does not prove a virtual environment.',
        'Reparse points and .git directories are not traversed. Supply physical target roots separately.',
        'Only wheel/ZIP/pip .body archives are inspected; other archive formats and container layers require separate inspection.',
        'Dependency references show possible acquisition, not execution. Unpinned installs require CI/install-log review.',
        'No Python, pip, package imports, malware, or credential files are executed/read.'
    )
}
if ($ReportPath) {
    $report | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $fullReportPath -Encoding utf8 -NoClobber
    ConvertTo-ExposureHtml $report | Out-File -LiteralPath $htmlReportPath -Encoding utf8 -NoClobber
    Write-Host "HTML report: $htmlReportPath"
    Write-Host "JSON report: $fullReportPath"
}
Write-Host "Result: $status; $filesScanned files; $($uniqueFindings.Count) findings; $($scanErrors.Count) errors; $($skippedLinks.Count) skipped links."
if ($uniqueFindings.Count) {
    Write-Host 'Preserve findings and contact your security team. Filename matches alone do not prove execution or credential theft.'
}
else {
    Write-Host 'No matching indicators were found in the inspected locations. This does not establish that the machine is safe.'
}
$report
