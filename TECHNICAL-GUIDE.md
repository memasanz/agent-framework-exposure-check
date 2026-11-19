# Agent Framework exposure check: technical guide

For the short, double-click instructions, see [README.md](README.md).
This reference covers advanced options, scan limitations, and investigation.

Read-only inspection for [GHSA-764m-3ppc-5m73](https://github.com/advisories/GHSA-764m-3ppc-5m73).
The advisory identifies `agent-framework` versions **1.26.1 and 1.26.2** as
malicious and 1.26.0 as the last clean release. It does not identify
`agent-framework-core==1.26.0` as affected.

**Do not run Python, pip, uv sync/run, notebooks, or applications that start
the suspect interpreter to check its version.** Startup hooks can execute
before an import. Do not download the malicious releases for testing.

## Easiest way to run

1. Save and extract `AgentFramework-QuickScan.zip` (Windows: **Extract All**;
   macOS: double-click the ZIP).
2. Open the extracted folder. On **Windows**, double-click
   **`Run-QuickScan.cmd`**. On **macOS**, double-click
   **`Run-QuickScan.command`**.
3. Leave the window open until the result appears. Open the
   **`AgentFramework-QuickReport-*.html`** file in a browser to read the
   results. It and a matching **`.json`** file are saved in your
   user-profile/home folder; the window shows their locations.
   Send both files to your security/IT contact.

**No commands to type, no Python installation, and no administrator access
are required for the packaged launchers**, subject to your organization's
script permissions/security controls. Keep the launcher and matching scanner
together (`.cmd` with `.ps1` on Windows, `.command` with `.sh` on macOS).
Extract the ZIP before running; do not launch from inside the ZIP. The folder
where you extract it does not determine the scan scope.

The launcher performs a **Quick filename scan of the current user's profile
only**. It does not scan every drive, launch Python, delete anything, or upload
results. It keeps the result window open. The report receives a new name each
run; no previous report is overwritten. A completed scan does not mean the
machine is safe: review findings and coverage gaps with your security team.

### Double-click Full scans (optional)

Use **Quick first**. For broader Deep checks, use the separate Full launcher:

| Platform | Double-click | Scope and confirmation |
| --- | --- | --- |
| Windows | `Run-FullScan.cmd` | All accessible local fixed drives. Press **Y** to start or **N** to cancel. |
| macOS | `Run-FullScan.command` | Main data volume (`/System/Volumes/Data` on modern macOS; `/` on older versions). Type **FULL** and press Return to start; anything else cancels. Other mounted volumes are not included. |

Both explain their scope before asking for confirmation. Cancelling starts
no scanner and creates no report. A started scan saves a uniquely named
`AgentFramework-FullReport-*.html` plus a matching `.json` file in the user's
profile/home folder, displays their locations, and keeps the window open.
Open the HTML file in a browser. Review errors/skipped locations;
"Full" describes the requested scope and Deep mode, not guaranteed coverage.
These scans can take much longer than Quick scans, do not start Python or
remediate anything, and do not automatically elevate privileges. Obtain IT
authorization before scanning broadly.

Run under your normal account, not another user's account or "Run as
administrator". If Windows or organizational policy blocks `.cmd`/PowerShell
scripts, use your approved IT distribution process; **do not bypass execution
policy or disable security controls**. On macOS, the packaged shell files
carry executable permissions. Source downloads or other extraction tools may
not preserve those permissions; have IT approve/restore them as appropriate.
If Gatekeeper, privacy permissions, or endpoint controls block access or
execution, use your approved IT process rather than disabling protections.
Have IT review/approve the files before broad distribution.

**Validation:** Windows behavior is tested on PowerShell 5.1 and 7.
The shell scanner and launcher logic have native macOS Bash 3.2 regression
fixtures (`/usr/bin/ruby tests/macos_test.rb`, using Ruby's standard library
and bundled Minitest; no package installation or Python).
Finder double-click launching still needs an IT smoke test before broad
distribution.

## Windows command-line options (advanced)

Save `Test-AgentFrameworkExposure.ps1` in any folder. **It does not need to
be inside the user's profile, a Python environment, or a project folder.**
The script's location does not determine what gets scanned.

Open a trusted PowerShell session under the account you want to check, then
change to the folder containing the script:

```powershell
Set-Location 'C:\path\to\folder-containing-script'
```

Run one of the following commands. The first command performs a Quick scan
of that account's user-profile folder (`$HOME`), regardless of where the
script is stored. Relative report paths such as `.\exposure-report.json`
save the report in the current PowerShell working folder, not necessarily
the scanned folder.

```powershell
# Quick scan of the current user's profile (default):
.\Test-AgentFrameworkExposure.ps1 -ReportPath .\exposure-report.json

# Quick scan of all ready local fixed drives (requires authorization):
.\Test-AgentFrameworkExposure.ps1 -Scope FixedDrives `
    -ReportPath .\fixed-drives-quick-report.json

# Deep scan: also inspect versions, dependency files, and cached archives:
.\Test-AgentFrameworkExposure.ps1 -Mode Deep `
    -ReportPath .\deep-report.json

# Equivalent to the Full launcher, without its interactive confirmation:
.\Test-AgentFrameworkExposure.ps1 -Mode Deep -Scope FixedDrives `
    -ReportPath .\full-report.json

# Either mode accepts explicit roots instead of the selected scope:
.\Test-AgentFrameworkExposure.ps1 `
    -Roots 'C:\work', 'D:\venvs', 'D:\package-cache' `
    -ReportPath .\custom-scope-report.json
```

| Mode | Checks |
| --- | --- |
| `Quick` (default) | Filename matches for `agent_framework_meta.pth`, `af_runtime_diag.pth`, `af_runtime_diag.py`, and `_telemetry.py` inside `agent_framework_meta`. No file-content reads, hashes, or archive inspection. |
| `Deep` | All Quick checks, plus package metadata, supported dependency files, wheel/ZIP/pip-cache inspection and archive SHA-256 checks. |

Quick mode goes directly to filename checking; it needs no preliminary
`python.exe` discovery. It still enumerates the selected directory trees,
so large trees can take time. Names alone are suspicious indicators, not
proof that the files contain malware.

`-Scope UserProfile` is the default: only the current user's `$HOME` tree,
including hidden folders, is inspected. No username or project-folder name
is hardcoded. This **does not include** system-wide Python installations
outside the profile or environments/caches on other drives.
`-Scope FixedDrives` selects all ready local fixed-drive roots instead.
Both modes accept either scope. `-Roots` overrides the scope entirely.
Use explicit roots for custom or authorized network/removable locations.
Neither predefined scope inspects WSL/container filesystems or remote hosts.
Obtain authorization before checking other users'/system folders; do not
elevate privileges without IT approval.

The script prints the selected inspection roots before inspection, shows
interactive progress, and returns a report object plus a readable summary.
Supply `-ReportPath` ending in `.json` to save both JSON and a matching `.html`
report. If either destination already exists, scanning is refused before it
begins. The reports record mode, scope, actual roots, duration, findings, and
coverage gaps. A report destination must have an existing parent directory.

### Optional Python environment discovery

For targeted Deep investigations, optional discovery can first
locate `python.exe` and `pyvenv.cfg` by directory enumeration, then add the
identified environment directories to the package inspection roots.
**It never launches the executables.** This is an extra pass and normally
unnecessary when the inspection scope already covers the same locations.

```powershell
# Discover environments under this user's profile, then perform Deep checks:
.\Test-AgentFrameworkExposure.ps1 -Mode Deep -DiscoverPython `
    -DiscoveryScope UserProfile -Verbose `
    -ReportPath .\profile-discovery-report.json

# Discover environments on fixed drives; add them to profile inspection roots:
.\Test-AgentFrameworkExposure.ps1 -Mode Deep -DiscoverPython `
    -DiscoveryScope FixedDrives -Verbose `
    -ReportPath .\fixed-drives-discovery-report.json

# Alternatively, restrict discovery to specific authorized folders.
.\Test-AgentFrameworkExposure.ps1 -Mode Deep -DiscoverPython `
    -DiscoveryRoots 'C:\work', 'D:\environments' -Verbose `
    -ReportPath .\custom-discovery-report.json
```

`UserProfile` is the discovery default when `-DiscoverPython` is specified.
Without that switch, no discovery pass is performed. `-DiscoveryScope` and
`-DiscoveryRoots` control discovery only, not the inspection scope.
`-DiscoveryRoots` overrides `-DiscoveryScope`. Discovered environment roots
are added to the roots selected with `-Scope` or `-Roots`, and may therefore
expand inspection beyond that original scope. The JSON records the final
inspection roots.

`python.exe` alone means an interpreter directory, **not necessarily a virtual
environment**. A neighboring `pyvenv.cfg` identifies a virtual-environment
layout; `conda-meta` identifies a Conda layout. An interpreter in `Scripts`
maps to its parent environment folder. `pyvenv.cfg` also allows discovery of
an environment whose interpreter is missing. Markers do not establish that
an environment is functional or trusted.

The JSON `PythonDiscovery` section lists the actual discovery roots,
environment roots, classifications, and discovery filenames. `Roots` lists
the subsequent package-inspection roots. `-Verbose` prints selected roots,
and interactive progress shows discovery/inspection activity.

Discovery only lists filesystem entries and checks marker paths; it does not
inspect every file's contents on a drive. Package inspection then reads the
supported files under its roots. Reparse-point directories and `.git` are
not traversed. Access-denied locations and skipped links are reported;
do not interpret incomplete coverage as safety. Fixed-drive mode excludes
network/removable drives, WSL/container filesystems, and drives that are not
ready. It can reach other user profiles only to the extent current access
permissions allow. Do not elevate privileges without your IT team's approval.

The scanner does not start Python, import packages, install/uninstall anything,
make network requests, read standalone credential files, or delete evidence.
In Deep mode it reads package/dependency files and hashes/inspects archives
without extracting them. Its report outputs are the optional JSON and HTML
files; existing reports are never overwritten. Paths can contain user/project names,
so handle reports as internal incident evidence.

## macOS command-line options (advanced)

The packaged ZIP marks the `.command` launchers executable, but source
downloads or some extraction tools may lose those permissions. For approved
scripts, run this once from the extracted folder if needed:

```shell
chmod u+x ./Run-QuickScan.command ./Run-FullScan.command
```

This sets the normal executable permission; it does not remove quarantine or
override Gatekeeper/organizational policy. Contact IT if those controls block
execution. The `.sh` scanner does not need its own executable bit when invoked
through `/bin/bash`, as the launchers do.

From Terminal in the extracted folder:

```shell
# Quick scan of your home folder; report is saved there automatically:
/bin/bash ./Test-AgentFrameworkExposure.sh

# Deep checks using only built-in macOS utilities, never Python:
/bin/bash ./Test-AgentFrameworkExposure.sh --mode Deep

# Explicit authorized roots instead of your home folder; repeat --root:
/bin/bash ./Test-AgentFrameworkExposure.sh --mode Quick \
    --root "/Users/your-account/work" --root "/opt/homebrew"

# Optional JSON destination; a matching HTML report is also created:
/bin/bash ./Test-AgentFrameworkExposure.sh --report "$HOME/my-scan-report.json"
```

The scanner targets the Bash 3.2 and standard tools supplied with macOS.
It does not need PowerShell, Python, jq, Homebrew, or package installation.
The default is only `$HOME`; it does not include system-wide Python packages
outside that folder. There is no automatic fixed-drive selector on macOS:
use explicit, authorized `--root` locations for broader coverage, such as
`/Library`, `/usr/local`, `/opt/homebrew`, or a specific `/Volumes/...` mount.
These are examples, not mandatory roots. Do not run with `sudo` or grant
additional filesystem permissions without IT approval.

macOS directory searches include hidden folders and `.git`, but do not follow
symlinks or cross into nested filesystem mounts. Pass authorized physical
targets and volume mount paths as separate `--root` arguments to inspect them.
`RequestedRoots`, canonical `Roots`, and `ScopePolicy` make the requested roots
and these boundaries explicit; the Full launcher is still main-data-volume
only, not every mounted volume or container.

An enumeration-only access preflight probes each valid root and selected
protected home folders that fall within that root. `AccessPreflight` records
the results. A successful probe is not proof of Full Disk Access or of access
to every descendant. On an authorized machine, IT can review **System Settings >
Privacy & Security > Files & Folders / Full Disk Access** for the launching
terminal app and approve access before a rerun. The scanner neither changes
permissions nor elevates. Do not exclude protected folders to obtain a
successful status.

`Errors` retains diagnostics with the affected `Path`, `Category`, original
diagnostic in `Detail`, `RetryOutcome`, and `Resolved`. Categories distinguish
`AccessDenied`, `Disappeared`, `Interrupted`, `IOFailure`, `TraversalFailure`, `InvalidRoot`,
`InspectionLimit`, and other tool failures. A disappeared entry is rechecked
once: a rediscovered directory is rescanned once, a rediscovered file/link is
selected again using the original mode's rules, and a still-missing path remains
an unresolved gap. Retries must resolve within the original root and filesystem;
outside-scope or unverifiable paths are not rescanned.
If BSD `find` aborts with `fts_read: Interrupted system call`, its unread
subtree is unknown, so the original root is re-enumerated once. Partial
candidates are retained; repeated interruption remains an unresolved gap.
This retry does not change permissions or retry access denials individually.
Retry failures retain their diagnostics too. Search process exit codes live
in `DirectorySearches`, rather than adding a duplicate root-level error.
`UnresolvedErrorCount` excludes diagnostics resolved by a successful retry.
Identical diagnostic records are deduplicated across attempts.

Symlinks appear in `SkippedSymlinks` and the structured `Symlinks` array
(the Windows field is `SkippedReparsePoints`). Target-type classification
uses filesystem metadata only; it does not read target contents, establish
target coverage, or authorize following a link. Indicator names are checked
on the link itself before it is skipped, including broken links. All skipped
links conservatively remain coverage gaps. HTML groups file, directory,
and unavailable/other target counts and shows at most 20 examples; JSON
retains every skipped path. No blanket `find -L` traversal is used.
`CandidateFilesExamined` counts examinations of regular files selected by
filename, not every file traversed or symlink name checked. Re-enumeration
or overlapping roots can examine the same path more than once; findings,
package inventory, and skipped-link records are deduplicated.

Quick mode opens no inspected file contents and checks the same four
hook/helper names as Windows. Deep mode adds package `METADATA`, common exact
pins, TOML package records, conventional Pipfile.lock objects, and cached
wheel/ZIP/pip bodies with advisory hash checks. All four hook/helper indicator
names are checked inside ZIP/wheel entries as well as on disk. It is not a
dependency resolver.
Dependency files over 8 MiB and archived metadata over 1 MiB are reported as
coverage errors rather than read without limits. Archive entries with unusual
embedded newlines may not be parsed reliably by the system ZIP listing tool.

Search progress is printed every ten seconds while directory enumeration is
active, then periodically during Deep candidate inspection. Both HTML and JSON
reports are created with owner-only permissions; existing reports are never
overwritten. An explicit `--report` must end in `.json`.
Temporary inspection files are private and removed on normal exit/interruption.
Nothing is uploaded and no remediation is performed.

macOS reports keep the legacy `Status` and add independent `FindingStatus`
(`NoIndicatorsFound` or `IndicatorsFound`) and `CoverageStatus` (`Complete` or
`Incomplete`). `Complete` applies only to the requested filesystem scope and
documented inspection rules, not historical absence or whole-machine safety.
Coverage remains visible even when indicators are found.

The macOS scanner and launchers return these process exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Reports saved, no indicators, requested inspection complete within documented limits. |
| `1` | Fatal setup/tool/report-writing failure; a report pair may be absent or partial. |
| `2` | Reports saved, no indicators, coverage incomplete. |
| `3` | Reports saved with indicators, requested inspection complete within documented limits. |
| `4` | Reports saved with indicators and incomplete coverage. |

Signal interruption can return the usual `130`/`143` without reports.
The launchers distinguish incomplete reports and indicators from a fatal
scanner failure. Automation must not treat a nonzero code as proof that no
reports exist, nor code `0` as proof that the machine is safe. Windows exit
behavior is unchanged.

## Reading and sharing reports

**Open the `.html` file in your browser.** It contains the status, counts,
findings with exact paths, inspection roots, coverage errors, skipped
locations, and Deep-mode package inventory. No application or web server is
needed. HTML reports are self-contained, load no external assets, contain no
JavaScript, and escape file-derived text instead of treating it as markup.

The matching `.json` file retains structured results for security/IT analysis.
An example pair is `AgentFramework-QuickReport-123-456.html` and
`AgentFramework-QuickReport-123-456.json`. Both files can contain internal
paths and computer names; share them only through your approved process,
not in a public repository. `.gitignore` excludes standard report filenames,
the `reports` folder, local secrets and the generated ZIP package. For custom
report names, use a `reports` folder that you create first.

Neither file is a certificate that the machine is safe. Review all coverage
warnings even when findings are present.

## Interpret results

| Result or finding | Meaning |
| --- | --- |
| `IndicatorsFound` | At least one indicator/reference needs investigation. Not proof of execution or exfiltration. |
| `NoIndicatorsInScannedScope` | Nothing matched in the selected locations. **Not a clean bill of health.** |
| `Incomplete` | No indicators found, but errors, skipped links, or empty scope prevent complete inspection. |
| `PackageOnDisk` | Affected package metadata exists on disk. Check whether its path is an installed environment, staging directory, or extracted cache. |
| `StartupHookOnDisk` / `HelperModuleOnDisk` | Advisory-listed filenames exist. Preserve and investigate; names alone are not cryptographic proof. A hook in active `site-packages` is urgent. |
| `KnownMaliciousWheelHash` | File bytes match a wheel SHA-256 from the advisory. A cached wheel alone does not establish execution. |
| `CachedPackage` / `CachedStartupHook` / `CachedHelperModule` | Affected metadata, startup-hook, or helper filename exists inside a wheel/ZIP/pip HTTP cache body. The helper kind is emitted by the macOS scanner. |
| `DependencyReference` | An exact bad version appears in a supported dependency declaration/artifact reference. Establish whether it was installed. |

Every finding has `LocationType`: `SitePackages`, `Archive`, or `OtherOnDisk`.
This is a path-based triage aid, not proof of installation or execution.
`OtherOnDisk` can include source copies or extracted caches. For Quick-mode
matches in `site-packages`, avoid launching that environment and contact your
security team for verification/containment. Do not automatically delete files.

Always inspect `Errors` and `SkippedReparsePoints` (macOS: `SkippedSymlinks` and
`CoverageStatus`), even with
`IndicatorsFound`. Symlinks/junctions are not followed; pass their physical
targets as additional roots. Windows excludes `.git`; macOS includes it. ZIP inspection
does not cover tarballs, nested archives, encrypted archives, or container
layers. Dependency parsing covers common requirements/constraints, uv/Poetry/PDM
package records, Pipfile.lock, and direct exact pins; it is not a universal
dependency resolver or log scanner. The Windows script returns a report
object, not an incident-status process exit code. Fleet automation should
evaluate `Status`, `Findings`, and coverage fields; macOS also has the exit
codes described above.

Deep-mode package inventory includes unaffected versions too; Quick mode does
not inventory package versions. Finding only 1.26.0 now
does not exclude a previous malicious installation. Deleted environments and
ephemeral CI runners require historical evidence.

## Fleet investigation

1. Distribute this script through your existing approved endpoint-management
   system. Collect JSON reports centrally through that system, not through
   a new public upload service. Include developer machines, build agents,
   deployment hosts, scheduled jobs, and service-account environments.
2. Search historical lockfiles, install/build logs, internal mirrors and
   artifact repositories for `agent-framework` 1.26.1/1.26.2. Review unpinned
   installs during the reported November 17 window (approximately
   **20:35-21:30 UTC**), but do not limit investigation to that hour:
   caches/mirrors could supply a malicious copy later.
3. Inspect container filesystems and all image layers without starting their
   Python entrypoints. Include stopped containers, image registries, build
   caches and ephemeral-runner logs. These filesystem scanners do
   not perform that work automatically.
4. Hunt for the network indicators below. Missing telemetry is not proof of
   safety; blocked requests or platform-specific failures also require triage.

### Microsoft Defender for Endpoint examples

Requires available Defender Advanced Hunting telemetry. These queries are
independent of the filesystem scanner.

```kusto
DeviceFileEvents
| where Timestamp >= datetime(2026-11-17T00:00:00Z)
| where FileName in~ (
    "agent_framework_meta.pth", "af_runtime_diag.pth", "af_runtime_diag.py")
    or (FileName =~ "_telemetry.py" and FolderPath contains "agent_framework_meta")
    or (FileName =~ "METADATA" and
        (FolderPath contains "agent_framework-1.26.1.dist-info"
         or FolderPath contains "agent_framework-1.26.2.dist-info"))
| project Timestamp, DeviceName, ActionType, FileName, FolderPath,
          InitiatingProcessFileName, SHA256
```

```kusto
DeviceNetworkEvents
| where Timestamp >= datetime(2026-11-17T00:00:00Z)
| where RemoteUrl contains "webhook.site"
| project Timestamp, DeviceName, ActionType, RemoteUrl, RemoteIP,
          InitiatingProcessFileName, InitiatingProcessId
```

`webhook.site` is also a legitimate service; correlate with package evidence,
Python processes, and the exact advisory endpoint. DNS generally shows only
the domain, and HTTPS telemetry may not expose URL paths or User-Agent.
File-event retention may not include old or unchanged files.

Advisory network indicators (do not visit the collection endpoint):

```text
Domain: webhook.site
URL: https://webhook.site/d381fd80-ec62-42ad-8f5c-d1b15103c9bb
User-Agent: af-runtime-diagnostics/1
User-Agent: runtime-diagnostics/1
```

Advisory wheel SHA-256 values:

```text
1.26.1 d27fa34414e6201d5e03e559ef634f020057554d7b3f4898dd5d7cd3e989e110
1.26.2 3d20a8bc91351a9a16b6db243b848ceca0206b7a8623b02d2af553a9c9f7e0a9
```

## If affected

Treat an environment with an affected installation as exposed. Isolate it
through approved incident-response controls and preserve relevant files,
hashes, timestamps and logs. Do not launch its interpreter to investigate.
The scanner deliberately performs no remediation.

Coordinate shell-based disabling/removal of the startup hooks with your
response team **before** any Python/pip execution. Removing hooks is not a
complete cleanup: processes may already be running, and the 1.26.1 helper can
also run through an import. Rebuild from trusted sources rather than repairing
in place.

From a separate clean system, rotate reachable credentials and investigate
identity access, including Entra user/service-principal/managed-identity
sign-ins, Azure activity and resource data-plane audit logs, Azure DevOps,
and GitHub Actions. Consider tokens already issued and access to mint new
ones; rotating stored secrets alone is insufficient. Determine appropriate
revocation/access restrictions with the identity/security team.

For unaffected environments, pin `agent-framework==1.26.0` using your normal
requirements/constraints and trusted artifact controls. Validate provenance
and apply the pin to CI/build paths as well; do not rely on "upgrade latest".
This does not remediate an environment that already executed malicious code.
