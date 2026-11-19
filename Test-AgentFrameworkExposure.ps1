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
$reparsePoints = [System.Collections.Generic.List[object]]::new()
$linkPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$accessPreflight = [System.Collections.Generic.List[object]]::new()
$preflightPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$directorySearches = [System.Collections.Generic.List[object]]::new()
$discoveryLocations = [System.Collections.Generic.List[string]]::new()
$environments = [System.Collections.Generic.List[object]]::new()
$environmentRoots = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$hashes = @{
    'd27fa34414e6201d5e03e559ef634f020057554d7b3f4898dd5d7cd3e989e110' = '1.26.1'
    '3d20a8bc91351a9a16b6db243b848ceca0206b7a8623b02d2af553a9c9f7e0a9' = '1.26.2'
}
$filesScanned = 0
$candidateFilesExamined = 0
$directoryEnumerationCount = 0

function Get-ExtendedPath {
    param([string] $Path)
    if ($Path.StartsWith('\\?\')) { return $Path }
    $resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    if ($resolved.StartsWith('\\')) { return '\\?\UNC\' + $resolved.Substring(2) }
    '\\?\' + $resolved
}

function Get-DisplayPath {
    param([string] $Path)
    if ($Path.StartsWith('\\?\UNC\', [StringComparison]::OrdinalIgnoreCase)) { return '\\' + $Path.Substring(8) }
    if ($Path.StartsWith('\\?\')) { return $Path.Substring(4) }
    $Path
}

function Add-ScanError {
    param(
        [string] $Path, [string] $Operation, [System.Management.Automation.ErrorRecord] $Record,
        [string] $Category, [string] $Detail, [switch] $PassThru
    )
    $errorName = $Category
    if ($Record) {
        $cause = $Record.Exception.GetBaseException()
        $errorName = $cause.GetType().Name
        $Detail = $cause.Message
        if (-not $Category) {
            $Category = if ($cause -is [System.UnauthorizedAccessException] -or $cause -is [System.Security.SecurityException]) { 'AccessDenied' }
                elseif ($cause -is [System.IO.FileNotFoundException] -or $cause -is [System.IO.DirectoryNotFoundException]) { 'Disappeared' }
                elseif ($cause -is [System.Threading.ThreadInterruptedException] -or
                    ($cause -is [System.IO.IOException] -and ($cause.HResult -band 0xffff) -in @(995, 1235, 10004))) { 'Interrupted' }
                elseif ($cause -is [System.IO.IOException]) { 'IOFailure' }
                elseif ($Operation -in @('Traverse', 'Discover')) { 'TraversalFailure' }
                else { 'ToolFailure' }
        }
        if ($Operation -eq 'Inspect' -and $cause -isnot [System.IO.IOException] -and
            $cause -isnot [System.UnauthorizedAccessException] -and $cause -isnot [System.Security.SecurityException]) {
            $Detail = 'Details omitted to avoid including file contents in the report.'
        }
    }
    $diagnostic = [pscustomobject]@{
        Path = Get-DisplayPath $Path
        Operation = $Operation
        Error = $errorName
        Detail = $Detail
        Category = $Category
        RetryOutcome = 'NotAttempted'
        Resolved = $false
    }
    $scanErrors.Add($diagnostic)
    if ($PassThru) { $diagnostic }
}

function Test-WithinRoot {
    param([string] $Path, [string] $Root)
    $Path.Equals($Root, [StringComparison]::OrdinalIgnoreCase) -or
        $Path.StartsWith($Root.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Get-BoundaryFailure {
    param([string] $Path, [string] $Root)
    if (-not (Test-WithinRoot $Path $Root)) { return 'OutsideScopeOrUnverifiable' }
    $anchor = [System.IO.Path]::GetPathRoot($Path)
    $current = $anchor
    # Mount points, cloud placeholders and junctions are never crossed, including in ancestors.
    foreach ($part in @('') + @($Path.Substring($anchor.Length).Split('\') | Where-Object { $_ })) {
        if ($part) { $current = [System.IO.Path]::Combine($current, $part) }
        try {
            $attributes = [System.IO.File]::GetAttributes((Get-ExtendedPath $current))
            if ([int]$attributes -band (0x400 -bor 0x1000 -bor 0x40000 -bor 0x400000)) {
                return 'OutsideScopeOrUnverifiable'
            }
        }
        catch {
            $cause = $_.Exception.GetBaseException()
            if ($cause -is [System.IO.FileNotFoundException] -or $cause -is [System.IO.DirectoryNotFoundException]) {
                return 'StillMissing'
            }
            return 'OutsideScopeOrUnverifiable'
        }
    }
}

function Get-DirectoryEntries {
    param([System.IO.DirectoryInfo] $Directory)
    $Directory.EnumerateFileSystemInfos()
}

function Invoke-AccessPreflight {
    param([string] $Root)
    $paths = @($Root)
    if ($HOME) {
        $paths += @('Desktop', 'Documents', 'Downloads', 'AppData') | ForEach-Object { Join-Path $HOME $_ }
    }
    foreach ($path in $paths) {
        if (-not (Test-WithinRoot $path $Root) -or -not $preflightPaths.Add($path)) { continue }
        try {
            if (Get-BoundaryFailure $path $Root) { continue }
            $info = [System.IO.DirectoryInfo]::new((Get-ExtendedPath $path))
            if (-not $info.Exists) { continue }
            $accessible = $true
            $detail = ''
            try { $info.EnumerateFileSystemInfos() | Out-Null }
            catch {
                $accessible = $false
                $detail = $_.Exception.GetBaseException().Message
                Write-Warning "Cannot enumerate $path. Ask IT to review access; no permissions are changed."
            }
            $accessPreflight.Add([pscustomobject]@{ Path = $path; Accessible = $accessible; Detail = $detail })
        }
        catch { Write-Verbose "Optional access probe unavailable: $path" }
    }
}

function Add-NameIndicators {
    param([string] $Path, [string] $DisplayedPath, [switch] $Archive, [switch] $Link)
    $parts = $Path -split '[\\/]'
    $leaf = $parts[-1]
    $parent = if ($parts.Count -gt 1) { $parts[-2] } else { '' }
    $note = if ($Link) { ' (reparse/link name only; target not inspected)' } else { '' }
    $hook = if ($Archive) { 'CachedStartupHook' } else { 'StartupHookOnDisk' }
    $helper = if ($Archive) { 'CachedHelperModule' } else { 'HelperModuleOnDisk' }
    if ($leaf -in @('agent_framework_meta.pth', 'af_runtime_diag.pth')) {
        Add-Finding $hook $DisplayedPath "$leaf$note"
    }
    elseif ($leaf -eq 'af_runtime_diag.py' -or ($leaf -eq '_telemetry.py' -and $parent -eq 'agent_framework_meta')) {
        Add-Finding $helper $DisplayedPath "$leaf$note"
    }
}

function Add-SkippedEntry {
    param([System.IO.FileSystemInfo] $Entry)
    $path = (Get-DisplayPath $Entry.FullName).TrimEnd('\')
    if (-not $linkPaths.Add($path)) { return }
    Add-NameIndicators $path $path -Link
    $directory = [bool]($Entry.Attributes -band [System.IO.FileAttributes]::Directory)
    $excludedExecutable = -not $directory -and $Entry.Extension -eq '.exe'
    $skippedLinks.Add($path)
    $reparsePoints.Add([pscustomobject]@{
        Path = $path
        EntryType = if ($directory) { 'Directory' } else { 'FileOrUnavailable' }
        Disposition = if ($excludedExecutable) { 'ExecutableContentsOutsideScope' } else { 'NotFollowed' }
        CoverageGap = -not $excludedExecutable
    })
}

function Read-BoundedText {
    param([System.IO.Stream] $Stream, [int] $Limit, [string] $Path)
    $buffer = [byte[]]::new(81920)
    $bounded = [System.IO.MemoryStream]::new()
    try {
        do {
            $read = $Stream.Read($buffer, 0, [Math]::Min($buffer.Length, $Limit + 1 - [int]$bounded.Length))
            $bounded.Write($buffer, 0, $read)
        } while ($read -gt 0 -and $bounded.Length -le $Limit)
        if ($bounded.Length -gt $Limit) {
            Add-ScanError $Path 'Inspect' -Category 'InspectionLimit' -Detail "File exceeds the $($Limit / 1MB) MiB inspection limit."
            return
        }
        $bounded.Position = 0
        $reader = [System.IO.StreamReader]::new($bounded)
        try { $reader.ReadToEnd() }
        finally { $reader.Dispose() }
    }
    finally { $bounded.Dispose() }
}

function Read-BoundedFile {
    param([System.IO.FileInfo] $File, [int] $Limit)
    $stream = [System.IO.File]::OpenRead($File.FullName)
    try { Read-BoundedText $stream $Limit (Get-DisplayPath $File.FullName) }
    finally { $stream.Dispose() }
}

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
    $errorGroups = @($Report.Errors | Group-Object Category | ForEach-Object {
        [pscustomobject]@{ Category = $_.Name; Count = $_.Count }
    })
    $errorSummary = ConvertTo-ReportTable $errorGroups @('Category', 'Count')
    $errorsTable = ConvertTo-ReportTable @($Report.Errors | Select-Object -First 100) @('Category', 'Operation', 'Path', 'Error', 'RetryOutcome', 'Resolved', 'Detail')
    $rootsList = ConvertTo-ReportList $Report.Roots
    $coverageLinks = @($Report.ReparsePoints | Where-Object CoverageGap)
    $linkGroups = @($Report.ReparsePoints | Group-Object EntryType, Disposition | ForEach-Object {
        [pscustomobject]@{ Group = $_.Name; Count = $_.Count }
    })
    $linksSummary = ConvertTo-ReportTable $linkGroups @('Group', 'Count')
    $skippedList = ConvertTo-ReportList @($coverageLinks | Select-Object -First 20 -ExpandProperty Path)
    $preflightTable = ConvertTo-ReportTable $Report.AccessPreflight @('Path', 'Accessible', 'Detail')
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
<p><strong>Findings status:</strong> $($Report.FindingStatus) | <strong>Coverage:</strong> $($Report.CoverageStatus)</p>
<div class="notice"><strong>$statusText</strong><p>$message</p>
<p>Completion does not establish safety. Errors and skipped locations remain important even when indicators are found.
This tool does not verify execution, prove credential theft, or remediate anything.</p></div>
<div class="summary"><span><strong>Findings:</strong> $($Report.Findings.Count)</span>
<span><strong>Diagnostics:</strong> $($Report.Errors.Count) ($($Report.UnresolvedErrorCount) unresolved)</span><span><strong>Skipped links (coverage gaps):</strong> $($coverageLinks.Count)</span>
<span><strong>Files enumerated:</strong> $($Report.FilesScanned)</span><span><strong>Seconds:</strong> $($Report.DurationSeconds)</span></div>
<h2>Findings</h2>$findingsTable
<p>SitePackages is a path-based triage aid, not proof of installation or execution. Archives may never have been installed.</p>
<h2>Inspection roots</h2>$rootsList
<h2>Access preflight</h2>
<p>Enumeration probes do not certify complete access. Ask IT to review denied folders, cloud availability and endpoint controls, then rerun after approved changes. No permissions are changed; do not bypass security controls or elevate without approval.</p>$preflightTable
<h2>Coverage diagnostics</h2>$errorSummary
<details><summary>Show up to 100 diagnostics; every diagnostic is retained in JSON</summary>$errorsTable</details>
<h2>Skipped links and junctions</h2>$linksSummary
<p>Link targets, mounted folders and cloud placeholders are not followed. Each non-executable-file gap remains incomplete coverage.
Executable file contents are outside the inspection scope; executable aliases alone do not create a coverage gap. Directory links named .exe still do.</p>
<details><summary>Show up to 20 coverage-gap examples; every skipped path is retained in JSON</summary>$skippedList</details>
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
    $Path = Get-DisplayPath $Path
    $locationType = if ($Kind -in @('CachedPackage', 'CachedStartupHook', 'CachedHelperModule', 'KnownMaliciousWheelHash')) { 'Archive' }
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
        $packages.Add([pscustomobject]@{ Version = $version; Path = Get-DisplayPath $Path; Kind = $Kind })
        if ($version -in @('1.26.1', '1.26.2')) {
            Add-Finding $Kind $Path "agent-framework==$version"
        }
    }
}

function Read-DependencyFile {
    param([System.IO.FileInfo] $File)
    $text = Read-BoundedFile $File 8MB
    if ($null -eq $text) { return }
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
                Add-NameIndicators $entry.FullName "$($File.FullName)::$($entry.FullName)" -Archive
                if ($entry.FullName -match '(?i)(^|/)agent[-_.]framework-[^/]+\.dist-info/METADATA$') {
                    $entryStream = $entry.Open()
                    try {
                        $text = Read-BoundedText $entryStream 1MB "$($File.FullName)::$($entry.FullName)"
                        if ($null -ne $text) {
                            Read-PackageMetadata $text "$($File.FullName)::$($entry.FullName)" 'CachedPackage'
                        }
                    }
                    finally { $entryStream.Dispose() }
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
    $environmentRoot = Get-DisplayPath $environmentRoot
    $type = 'InterpreterDirectory'
    if (Test-Path -LiteralPath (Get-ExtendedPath (Join-Path $environmentRoot 'pyvenv.cfg')) -PathType Leaf) {
        $type = 'VirtualEnvironment'
    }
    elseif (Test-Path -LiteralPath (Get-ExtendedPath (Join-Path $environmentRoot 'conda-meta')) -PathType Container) {
        $type = 'CondaEnvironment'
    }
    if ($environmentRoots.Add($environmentRoot)) {
        $environments.Add([pscustomobject]@{
            Root = $environmentRoot
            Type = $type
            DiscoveredBy = Get-DisplayPath $File.FullName
        })
    }
}

function Invoke-EntryInspection {
    param([System.IO.FileSystemInfo] $Entry, [string] $Root, [object] $Pending, [switch] $Discovery, [switch] $Count)
    $path = Get-DisplayPath $Entry.FullName
    $attributes = $Entry.Attributes
    if ([int]$attributes -eq -1) { $attributes = [System.IO.File]::GetAttributes($Entry.FullName) }
    if ([int]$attributes -band (0x400 -bor 0x1000 -bor 0x40000 -bor 0x400000)) {
        Add-SkippedEntry $Entry
        return
    }
    if ($attributes -band [System.IO.FileAttributes]::Directory) {
        $Pending.Push([pscustomobject]@{ Path = $path; Root = $Root })
        return
    }
    if ($Discovery) {
        if ($Entry.Name -in @('python.exe', 'pyvenv.cfg')) { Add-DiscoveredEnvironment $Entry }
        return
    }
    if ($Count) { $script:filesScanned++ }
    $candidate = $Entry.Name -in @('agent_framework_meta.pth', 'af_runtime_diag.pth', 'af_runtime_diag.py', '_telemetry.py')
    if ($Mode -eq 'Deep' -and ($Entry.Extension -in @('.whl', '.zip', '.body') -or
        $Entry.Name -match '^(METADATA|requirements.*\.(txt|in)|constraints.*\.txt|uv\.lock|poetry\.lock|pdm\.lock|pylock.*\.toml|Pipfile(\.lock)?|pyproject\.toml|setup\.(cfg|py))$')) {
        $candidate = $true
    }
    if (-not $candidate) { return }
    if ($Count) { $script:candidateFilesExamined++ }
    Add-NameIndicators $path $path
    if ($Mode -eq 'Quick') { return }
    $boundary = Get-BoundaryFailure $path $Root
    if ($boundary) {
        if ($boundary -eq 'StillMissing') { throw [System.IO.FileNotFoundException]::new('Candidate disappeared before inspection.', $path) }
        Add-ScanError $path 'Inspect' -Category 'ScopeBoundary' -Detail "Candidate is no longer verifiably inside the original physical scope: $boundary."
        return
    }
    if ($Entry.Name -eq 'METADATA' -and $Entry.Directory.Name -match '^agent[-_.]framework-[^\\]+\.dist-info$') {
        $text = Read-BoundedFile $Entry 1MB
        if ($null -ne $text) { Read-PackageMetadata $text $path 'PackageOnDisk' }
    }
    if ($Entry.Extension -in @('.whl', '.zip', '.body')) { Read-CachedArchive $Entry }
    if ($Entry.Name -match '^(requirements.*\.(txt|in)|constraints.*\.txt|uv\.lock|poetry\.lock|pdm\.lock|pylock.*\.toml|Pipfile(\.lock)?|pyproject\.toml|setup\.(cfg|py))$') {
        Read-DependencyFile $Entry
    }
}

function Invoke-WalkEntry {
    param([System.IO.FileSystemInfo] $Entry, [string] $Root, [object] $Pending, [switch] $Discovery)
    $retryDiagnostic = $null
    for ($attempt = 0; $attempt -lt 2; $attempt++) {
        try {
            Invoke-EntryInspection $Entry $Root $Pending -Discovery:$Discovery -Count:($attempt -eq 0)
            if ($retryDiagnostic) {
                $retryDiagnostic.RetryOutcome = 'EntryRescanned'
                $retryDiagnostic.Resolved = $true
            }
            return
        }
        catch {
            $diagnostic = Add-ScanError $Entry.FullName 'Inspect' $_ -PassThru
            if ($retryDiagnostic) {
                $retryDiagnostic.RetryOutcome = 'RetryFailed'
                $diagnostic.RetryOutcome = 'RetryLimitReached'
                return
            }
            if ($diagnostic.Category -notin @('Disappeared', 'Interrupted')) { return }
            $boundary = Get-BoundaryFailure (Get-DisplayPath $Entry.FullName) $Root
            if ($boundary) { $diagnostic.RetryOutcome = $boundary; return }
            $retryDiagnostic = $diagnostic
            $Entry.Refresh()
        }
    }
}

function Invoke-DirectoryWalk {
    param([string[]] $SearchRoots, [object] $ResolvedRoots, [switch] $Discovery)
    $pendingDirectories = [System.Collections.Generic.Stack[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $seenEntries = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $operation = if ($Discovery) { 'Discover' } else { 'Traverse' }
    foreach ($searchRoot in $SearchRoots) {
        try {
            $extended = Get-ExtendedPath $searchRoot
            $attributes = [System.IO.File]::GetAttributes($extended)
            $info = if ($attributes -band [System.IO.FileAttributes]::Directory) {
                [System.IO.DirectoryInfo]::new($extended)
            } else { [System.IO.FileInfo]::new($extended) }
            if ([int]$attributes -band (0x400 -bor 0x1000 -bor 0x40000 -bor 0x400000)) {
                Add-SkippedEntry $info
                continue
            }
            if ($info -isnot [System.IO.DirectoryInfo]) {
                Add-ScanError $searchRoot 'ResolveRoot' -Category 'InvalidRoot' -Detail 'Root is not a directory.'
                continue
            }
            $displayPath = Get-DisplayPath $info.FullName
            $anchor = [System.IO.Path]::GetPathRoot($displayPath)
            $path = $displayPath.TrimEnd('\')
            if ($path -eq $anchor.TrimEnd('\')) { $path = $anchor }
            $boundary = Get-BoundaryFailure $path $path
            if ($boundary) {
                Add-ScanError $path 'ResolveRoot' -Category 'ScopeBoundary' -Detail "Root has an excluded or unverifiable ancestor: $boundary. Supply an authorized physical root."
                continue
            }
            $ResolvedRoots.Add($path)
            Write-Host "$operation root: $path"
            Invoke-AccessPreflight $path
            $pendingDirectories.Push([pscustomobject]@{ Path = $path; Root = $path })
        }
        catch {
            $resolveOperation = if ($Discovery) { 'ResolveDiscoveryRoot' } else { 'ResolveRoot' }
            $diagnostic = Add-ScanError $searchRoot $resolveOperation $_ -PassThru
            if ($diagnostic.Category -eq 'Disappeared') { $diagnostic.Category = 'InvalidRoot' }
        }
    }
    while ($pendingDirectories.Count) {
        $context = $pendingDirectories.Pop()
        $directory = $context.Path
        if (-not $seen.Add($directory)) { continue }
        if ($seen.Count % 200 -eq 0) {
            Write-Progress -Activity "$operation Agent Framework exposure ($Mode)" `
                -Status "$filesScanned files; $($seen.Count) directories; $($findings.Count) indicators" -CurrentOperation $directory
        }
        $retryDiagnostic = $null
        for ($attempt = 0; $attempt -lt 2; $attempt++) {
            try {
                $info = [System.IO.DirectoryInfo]::new((Get-ExtendedPath $directory))
                $attributes = [System.IO.File]::GetAttributes($info.FullName)
                if ([int]$attributes -band (0x400 -bor 0x1000 -bor 0x40000 -bor 0x400000)) {
                    Add-SkippedEntry $info
                    if ($retryDiagnostic) { $retryDiagnostic.RetryOutcome = 'OutsideScopeOrUnverifiable' }
                    break
                }
                $boundary = Get-BoundaryFailure $directory $context.Root
                if ($boundary) {
                    Add-ScanError $directory $operation -Category 'ScopeBoundary' -Detail "Directory is no longer verifiably inside the original physical scope: $boundary."
                    if ($retryDiagnostic) { $retryDiagnostic.RetryOutcome = $boundary }
                    break
                }
                $script:directoryEnumerationCount++
                # Consume the pipeline incrementally so an interrupted enumerator cannot discard earlier entries.
                Get-DirectoryEntries $info | ForEach-Object {
                    if ($seenEntries.Add((Get-DisplayPath $_.FullName))) {
                        Invoke-WalkEntry $_ $context.Root $pendingDirectories -Discovery:$Discovery
                    }
                }
                if ($retryDiagnostic) {
                    $retryDiagnostic.RetryOutcome = 'DirectoryReenumerated'
                    $retryDiagnostic.Resolved = $true
                    $directorySearches.Add([pscustomobject]@{ Path = $directory; Operation = $operation; Retry = $true; Succeeded = $true })
                }
                break
            }
            catch {
                $diagnostic = Add-ScanError $directory $operation $_ -PassThru
                $directorySearches.Add([pscustomobject]@{ Path = $directory; Operation = $operation; Retry = ($attempt -gt 0); Succeeded = $false })
                if ($retryDiagnostic) {
                    $retryDiagnostic.RetryOutcome = 'RetryFailed'
                    $diagnostic.RetryOutcome = 'RetryLimitReached'
                    break
                }
                if ($diagnostic.Category -notin @('Disappeared', 'Interrupted')) { break }
                $boundary = Get-BoundaryFailure $directory $context.Root
                if ($boundary) { $diagnostic.RetryOutcome = $boundary; break }
                $retryDiagnostic = $diagnostic
            }
        }
    }
    Write-Progress -Activity "$operation Agent Framework exposure ($Mode)" -Completed
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
$requestedRoots = @($Roots)
Write-Host 'Access preflight checks enumeration only; it cannot certify complete access.'
Write-Host 'Ask IT to review access warnings, cloud availability and endpoint controls, then rerun after approved changes.'
Write-Host 'No permissions are changed. Do not elevate or bypass security controls without IT approval.'
Write-Host 'Hidden folders and .git are included. Reparse targets and mounted folders are not followed.'
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
    Invoke-DirectoryWalk $DiscoveryRoots $discoveryLocations -Discovery
    $Roots = @($Roots) + @($environments | ForEach-Object { $_.Root })
    $Roots = @($Roots | Sort-Object -Unique)
}

if ($Mode -eq 'Deep') { Add-Type -AssemblyName System.IO.Compression }
$resolvedRoots = [System.Collections.Generic.List[string]]::new()
Invoke-DirectoryWalk $Roots $resolvedRoots

$uniqueFindings = @($findings | Sort-Object Kind, Path, Evidence -CaseSensitive -Unique)
$unresolvedErrors = @($scanErrors | Where-Object { -not $_.Resolved })
$coverageLinks = @($reparsePoints | Where-Object CoverageGap)
$coverageStatus = if ($unresolvedErrors.Count -or $coverageLinks.Count -or -not $resolvedRoots.Count -or
    ($DiscoverPython -and -not $discoveryLocations.Count)) { 'Incomplete' } else { 'Complete' }
$findingStatus = if ($uniqueFindings.Count) { 'IndicatorsFound' } else { 'NoIndicatorsFound' }
$status = if ($uniqueFindings.Count) { 'IndicatorsFound' }
    elseif ($coverageStatus -eq 'Incomplete') { 'Incomplete' }
    else { 'NoIndicatorsInScannedScope' }
$exitCode = if ($uniqueFindings.Count) {
    if ($coverageStatus -eq 'Incomplete') { 4 } else { 3 }
} elseif ($coverageStatus -eq 'Incomplete') { 2 } else { 0 }
$report = [pscustomobject]@{
    Advisory = 'https://github.com/advisories/GHSA-764m-3ppc-5m73'
    ComputerName = $env:COMPUTERNAME
    Mode = $Mode
    Scope = if ($PSBoundParameters.ContainsKey('Roots')) { 'Custom' } else { $Scope }
    StartedUtc = $startedUtc.ToString('o')
    ScanTimeUtc = [DateTime]::UtcNow.ToString('o')
    DurationSeconds = [Math]::Round(([DateTime]::UtcNow - $startedUtc).TotalSeconds, 1)
    Status = $status
    FindingStatus = $findingStatus
    CoverageStatus = $coverageStatus
    ExitCode = $exitCode
    UnresolvedErrorCount = $unresolvedErrors.Count
    RequestedRoots = $requestedRoots
    Roots = @($resolvedRoots | Sort-Object -Unique)
    ScopePolicy = [pscustomobject]@{ GitDirectoriesIncluded = $true; FollowReparsePoints = $false; CrossFilesystems = $false }
    AccessPreflight = @($accessPreflight.ToArray())
    DirectoryEnumerationCount = $directoryEnumerationCount
    DirectorySearches = @($directorySearches.ToArray())
    PythonDiscovery = [pscustomobject]@{
        Enabled = [bool]$DiscoverPython
        Scope = if (-not $DiscoverPython) { 'Disabled' }
            elseif ($PSBoundParameters.ContainsKey('DiscoveryRoots')) { 'Custom' }
            else { $DiscoveryScope }
        Roots = @($discoveryLocations.ToArray())
        Environments = @($environments.ToArray())
    }
    FilesScanned = $filesScanned
    CandidateFilesExamined = $candidateFilesExamined
    Findings = $uniqueFindings
    PackageInventory = @($packages | Sort-Object Version, Kind, Path -CaseSensitive -Unique)
    Errors = @($scanErrors.ToArray())
    SkippedReparsePoints = @($skippedLinks.ToArray())
    ReparsePoints = @($reparsePoints.ToArray())
    Limitations = @(
        'Point-in-time file inspection only; no proof of historical absence or successful exfiltration.',
        'The default scope is the current user profile only. Other locations need FixedDrives or explicit Roots.',
        'Quick mode matches hook/helper filenames only; it does not read package metadata, dependency files, or archives, or compute hashes.',
        'Optional discovery searches filenames python.exe and pyvenv.cfg, not archives or other interpreter names; python.exe alone does not prove a virtual environment.',
        '.git directories are included. Reparse targets, mounted folders and cloud/offline placeholders are not followed. Supply authorized physical target roots separately.',
        'Executable contents are outside scope. Non-directory .exe reparse entries are retained in JSON but do not alone create coverage gaps.',
        'Access preflight only probes directory enumeration and does not certify complete access. No permissions or endpoint settings are changed.',
        'Each interrupted/disappeared directory or candidate is retried at most once, only while verifiably inside the original physical root and without crossing reparse/mount boundaries. Concurrent filesystem changes cannot be ruled out.',
        'Metadata reads are bounded to 1 MiB and dependency reads to 8 MiB; exceeding a limit is an unresolved coverage diagnostic.',
        'DirectorySearches records failed/retried directory enumerations only; DirectoryEnumerationCount counts all enumeration attempts, excluding access probes.',
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
Write-Host "Result: $status; coverage: $coverageStatus; $filesScanned files; $($uniqueFindings.Count) findings; $($scanErrors.Count) diagnostics ($($unresolvedErrors.Count) unresolved); $($coverageLinks.Count) skipped-link coverage gaps."
if ($uniqueFindings.Count) {
    Write-Host 'Preserve findings and contact your security team. Filename matches alone do not prove execution or credential theft.'
}
else {
    Write-Host 'No matching indicators were found in the inspected locations. This does not establish that the machine is safe.'
}
$report
exit $exitCode
