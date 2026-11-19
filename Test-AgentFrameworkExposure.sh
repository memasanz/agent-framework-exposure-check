#!/bin/bash
# Compatible with the Bash 3.2 shipped with macOS. Never starts Python.
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
export LC_ALL=C
umask 077
shopt -s nocasematch

mode=Quick
roots=()
root_arguments=0
report=
work=
find_pid=
files_examined=0
started=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

usage() {
    printf '%s\n' \
        'Usage: /bin/bash Test-AgentFrameworkExposure.sh [options]' \
        '  --mode Quick|Deep   Quick filename checks (default), or Deep inspection' \
        '  --root DIRECTORY    Scan this directory instead of HOME; repeat as needed' \
        '  --report FILE       JSON report destination (must not already exist)' \
        '  --help              Show this help' \
        'Default: Quick scan of HOME, report saved in HOME. Never executes Python.'
}

while (( $# )); do
    case "$1" in
        --mode|--root|--report)
            if (( $# < 2 )); then usage >&2; exit 1; fi
            case "$1" in
                --mode) mode=$2 ;;
                --root) roots[$root_arguments]=$2; root_arguments=$((root_arguments+1)) ;;
                --report) report=$2 ;;
            esac
            shift 2
            ;;
        --help|-h) usage; exit 0 ;;
        *) printf 'Unknown option: %s\n' "$1" >&2; usage >&2; exit 1 ;;
    esac
done
case "$mode" in
    Quick) mode=Quick ;;
    Deep) mode=Deep ;;
    *) printf 'Mode must be Quick or Deep.\n' >&2; exit 1 ;;
esac
if [[ -z ${HOME:-} ]]; then printf 'HOME is not set.\n' >&2; exit 1; fi
scope=Custom
if (( root_arguments == 0 )); then roots=("$HOME"); scope=UserProfile; fi
if [[ -z "$report" ]]; then
    report="$HOME/AgentFramework-${mode}Report-$(date -u '+%Y%m%dT%H%M%SZ')-$$.json"
fi
if [[ -e "$report" || -L "$report" ]]; then
    printf 'Report already exists; choose a new destination: %s\n' "$report" >&2
    exit 1
fi
if [[ ! -d "$(dirname "$report")" ]]; then printf 'Report parent directory does not exist.\n' >&2; exit 1; fi

hash_tool=
if [[ "$mode" == Deep ]]; then
    for tool in awk unzip head od tr wc; do
        if ! command -v "$tool" >/dev/null 2>&1; then printf 'Deep mode needs %s.\n' "$tool" >&2; exit 1; fi
    done
    if command -v shasum >/dev/null 2>&1; then hash_tool=shasum
    elif command -v sha256sum >/dev/null 2>&1; then hash_tool=sha256sum
    else printf 'Deep mode needs shasum or sha256sum.\n' >&2; exit 1
    fi
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/af-exposure.XXXXXXXX")
cleanup() {
    if [[ -n "$find_pid" ]]; then
        kill "$find_pid" 2>/dev/null || :
        wait "$find_pid" 2>/dev/null || :
    fi
    rm -f -- "$work/findings" "$work/errors" "$work/skipped" "$work/inventory" \
        "$work/roots" "$work/candidates" "$work/find-errors" "$work/zip-entries" \
        "$work/metadata" "$work/tool-errors"
    rmdir -- "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
for name in findings errors skipped inventory roots; do : > "$work/$name"; done

json_string() {
    local value=$1 character code i
    printf '"'
    for (( i=0; i<${#value}; i++ )); do
        character=${value:i:1}
        case "$character" in
            '"') printf '\\"' ;;
            '\') printf '\\\\' ;;
            $'\n') printf '\\n' ;;
            $'\r') printf '\\r' ;;
            $'\t') printf '\\t' ;;
            *)
                printf -v code '%d' "'$character"
                if (( code < 32 )); then printf '\\u%04x' "$code"
                else printf '%s' "$character"
                fi
                ;;
        esac
    done
    printf '"'
}

add_error() {
    {
        printf '{"Path":'; json_string "$1"
        printf ',"Operation":'; json_string "$2"
        printf ',"Detail":'; json_string "$3"
        printf '}\n'
    } >> "$work/errors"
}

add_finding() {
    local kind=$1 path=$2 evidence=$3 location=OtherOnDisk
    case "$kind" in
        CachedPackage|CachedStartupHook|KnownMaliciousWheelHash) location=Archive ;;
        *) case "$path" in */site-packages/*) location=SitePackages ;; esac ;;
    esac
    {
        printf '{"Kind":'; json_string "$kind"
        printf ',"Path":'; json_string "$path"
        printf ',"LocationType":'; json_string "$location"
        printf ',"Evidence":'; json_string "$evidence"
        printf '}\n'
    } >> "$work/findings"
    printf 'Indicator (%s): %q\n' "$kind" "$path"
}

read_metadata() {
    local file=$1 displayed_path=$2 kind=$3 version
    if ! version=$(awk '
        /^Name:[[:space:]]*/ { name=$0; sub(/^Name:[[:space:]]*/, "", name); sub(/\r$/, "", name) }
        /^Version:[[:space:]]*/ { version=$0; sub(/^Version:[[:space:]]*/, "", version); sub(/[[:space:]]+$/, "", version) }
        END { if (tolower(name) ~ /^agent[-_.]framework$/) print version }
    ' "$file" 2>"$work/tool-errors"); then
        add_error "$displayed_path" Metadata 'Could not read package metadata.'
        return
    fi
    if [[ -z "$version" ]]; then return; fi
    {
        printf '{"Version":'; json_string "$version"
        printf ',"Path":'; json_string "$displayed_path"
        printf ',"Kind":'; json_string "$kind"
        printf '}\n'
    } >> "$work/inventory"
    case "$version" in
        1.26.1|1.26.2) add_finding "$kind" "$displayed_path" "agent-framework==$version" ;;
    esac
}

read_dependencies() {
    local file=$1 version versions
    if (( $(wc -c < "$file") > 8388608 )); then
        add_error "$file" DependencyFile 'Dependency file exceeds the 8 MiB inspection limit.'
        return
    fi
    if ! versions=$(awk '
        function affected(v) { return v == "1.26.1" || v == "1.26.2" }
        function flush() { if (name ~ /^agent[-_.]framework$/ && affected(version)) print version }
        {
            if (FILENAME ~ /Pipfile.lock$/) { json=json $0 "\n"; next }
            if ($0 ~ /^[[:space:]]*\[\[packages?\]\]/) { flush(); name=""; version="" }
            if ($0 ~ /^[[:space:]]*name[[:space:]]*=/) {
                name=$0; sub(/^[^=]*=[[:space:]]*["\047]/, "", name); sub(/["\047].*$/, "", name)
            }
            if ($0 ~ /^[[:space:]]*version[[:space:]]*=/) {
                version=$0; sub(/^[^=]*=[[:space:]]*["\047]/, "", version); sub(/["\047].*$/, "", version)
            }
            line=$0
            while (match(line, /(^|[^[:alnum:]_.-])agent[-_.]framework(\[[^]]*\])?[[:space:]]*(===|==|@|=)[[:space:]]*["\047]?1\.26\.[12]([^[:alnum:]_.]|$)|agent[-_]framework-1\.26\.[12]([^[:alnum:]_.]|$)/)) {
                pin=substr(line, RSTART, RLENGTH); line=substr(line, RSTART+RLENGTH)
                match(pin, /1\.26\.[12]/); print substr(pin, RSTART, RLENGTH)
            }
        }
        END {
            flush()
            while (match(json, /"agent[-_.]framework"[[:space:]]*:[[:space:]]*\{/)) {
                start=RSTART+RLENGTH-1; depth=0; quoted=0; escaped=0
                for (i=start; i<=length(json); i++) {
                    c=substr(json,i,1)
                    if (quoted) {
                        if (escaped) escaped=0
                        else if (c=="\\") escaped=1
                        else if (c=="\"") quoted=0
                    } else {
                        if (c=="\"") quoted=1
                        else if (c=="{") depth++
                        else if (c=="}" && --depth==0) break
                    }
                }
                object=substr(json,start,i-start+1)
                if (match(object, /"version"[[:space:]]*:[[:space:]]*"==1\.26\.[12]"/)) {
                    pin=substr(object,RSTART,RLENGTH)
                    match(pin,/1\.26\.[12]/); print substr(pin,RSTART,RLENGTH)
                }
                json=substr(json,i+1)
            }
        }
    ' "$file" 2>"$work/tool-errors"); then
        add_error "$file" DependencyFile 'Could not inspect dependency file.'
        return
    fi
    while IFS= read -r version; do
        if [[ -n "$version" ]]; then add_finding DependencyReference "$file" "agent-framework==$version"; fi
    done <<< "$versions"
}

read_archive() {
    local file=$1 hash_output hash signature entry leaf size
    if [[ "$hash_tool" == shasum ]]; then
        if ! hash_output=$(shasum -a 256 "$file" 2>"$work/tool-errors"); then
            add_error "$file" Hash 'Could not hash archive.'; return
        fi
    else
        if ! hash_output=$(sha256sum "$file" 2>"$work/tool-errors"); then
            add_error "$file" Hash 'Could not hash archive.'; return
        fi
    fi
    hash=${hash_output%% *}
    hash=${hash#\\}
    case "$hash" in
        d27fa34414e6201d5e03e559ef634f020057554d7b3f4898dd5d7cd3e989e110)
            add_finding KnownMaliciousWheelHash "$file" "agent-framework==1.26.1; SHA256=$hash" ;;
        3d20a8bc91351a9a16b6db243b848ceca0206b7a8623b02d2af553a9c9f7e0a9)
            add_finding KnownMaliciousWheelHash "$file" "agent-framework==1.26.2; SHA256=$hash" ;;
    esac
    if ! signature=$(od -An -tx1 -N2 "$file" 2>"$work/tool-errors" | tr -d ' \n'); then
        add_error "$file" Archive 'Could not read archive signature.'; return
    fi
    if [[ "$signature" != 504b ]]; then return; fi
    if ! unzip -Z1 "$file" > "$work/zip-entries" 2>"$work/tool-errors"; then
        add_error "$file" Archive 'Could not list ZIP entries.'; return
    fi
    while IFS= read -r entry; do
        leaf=${entry##*/}
        case "$leaf" in
            agent_framework_meta.pth|af_runtime_diag.pth)
                add_finding CachedStartupHook "$file::$entry" "$leaf" ;;
        esac
        if [[ "$entry" =~ (^|/)agent[-_.]framework-[^/]+\.dist-info/METADATA$ ]]; then
            if ! unzip -p "$file" "$entry" 2>"$work/tool-errors" | head -c 1048577 > "$work/metadata"; then
                add_error "$file::$entry" ArchiveMetadata 'Could not read bounded archive metadata.'
                continue
            fi
            size=$(wc -c < "$work/metadata")
            if (( size > 1048576 )); then
                add_error "$file::$entry" ArchiveMetadata 'Metadata exceeds the 1 MiB inspection limit.'
                continue
            fi
            read_metadata "$work/metadata" "$file::$entry" CachedPackage
        fi
    done < "$work/zip-entries"
}

printf 'Agent Framework exposure check: %s mode. No Python will be run.\n' "$mode"
for root in "${roots[@]}"; do
    if [[ -L "$root" ]]; then
        { json_string "$root"; printf '\n'; } >> "$work/skipped"
        continue
    fi
    if [[ ! -d "$root" ]]; then add_error "$root" ResolveRoot 'Root is missing or is not a directory.'; continue; fi
    root=$(cd -P -- "$root" && pwd -P)
    { json_string "$root"; printf '\n'; } >> "$work/roots"
    printf 'Searching root: %q\n' "$root"
    if [[ "$mode" == Quick ]]; then
        find "$root" -xdev \( -type d -name .git -prune \) -o \
            \( -type l -o \( -type f \( -iname agent_framework_meta.pth -o -iname af_runtime_diag.pth \
            -o -iname af_runtime_diag.py -o -iname _telemetry.py \) \) \) -print0 \
            > "$work/candidates" 2> "$work/find-errors" &
    else
        find "$root" -xdev \( -type d -name .git -prune \) -o \
            \( -type l -o \( -type f \( -iname agent_framework_meta.pth -o -iname af_runtime_diag.pth \
            -o -iname af_runtime_diag.py -o -iname _telemetry.py -o -iname METADATA \
            -o -iname '*.whl' -o -iname '*.zip' -o -iname '*.body' \
            -o -iname 'requirements*.txt' -o -iname 'requirements*.in' -o -iname 'constraints*.txt' \
            -o -iname uv.lock -o -iname poetry.lock -o -iname pdm.lock -o -iname 'pylock*.toml' \
            -o -iname Pipfile -o -iname Pipfile.lock -o -iname pyproject.toml -o -iname setup.cfg -o -iname setup.py \) \) \) -print0 \
            > "$work/candidates" 2> "$work/find-errors" &
    fi
    find_pid=$!
    seconds=0
    while kill -0 "$find_pid" 2>/dev/null; do
        sleep 1
        seconds=$((seconds+1))
        if (( seconds % 10 == 0 )); then printf 'Still searching this root (%s seconds)...\n' "$seconds"; fi
    done
    if ! wait "$find_pid"; then add_error "$root" Find 'Directory search did not complete successfully; see FindDiagnostic entries.'; fi
    find_pid=
    while IFS= read -r diagnostic; do
        add_error "$root" FindDiagnostic "$diagnostic"
    done < "$work/find-errors"
    while IFS= read -r -d '' file; do
        if [[ -L "$file" ]]; then
            { json_string "$file"; printf '\n'; } >> "$work/skipped"
            continue
        fi
        files_examined=$((files_examined+1))
        leaf=${file##*/}
        parent=${file%/*}
        case "$leaf" in
            agent_framework_meta.pth|af_runtime_diag.pth) add_finding StartupHookOnDisk "$file" "$leaf" ;;
            af_runtime_diag.py) add_finding HelperModuleOnDisk "$file" "$leaf" ;;
            _telemetry.py)
                if [[ ${parent##*/} == agent_framework_meta ]]; then add_finding HelperModuleOnDisk "$file" 'agent_framework_meta/_telemetry.py'; fi ;;
        esac
        if [[ "$mode" == Quick ]]; then continue; fi
        if (( files_examined % 200 == 0 )); then printf 'Deep inspection: %s candidate files processed...\n' "$files_examined"; fi
        if [[ "$leaf" == METADATA && ${parent##*/} =~ ^agent[-_.]framework-[^/]+\.dist-info$ ]]; then
            read_metadata "$file" "$file" PackageOnDisk
        fi
        case "$leaf" in
            *.whl|*.zip|*.body) read_archive "$file" ;;
            requirements*.txt|requirements*.in|constraints*.txt|uv.lock|poetry.lock|pdm.lock|pylock*.toml|Pipfile|Pipfile.lock|pyproject.toml|setup.cfg|setup.py)
                read_dependencies "$file" ;;
        esac
    done < "$work/candidates"
done

for name in findings inventory roots skipped; do sort -u -o "$work/$name" "$work/$name"; done
finding_count=$(wc -l < "$work/findings")
error_count=$(wc -l < "$work/errors")
skipped_count=$(wc -l < "$work/skipped")
root_count=$(wc -l < "$work/roots")
status=NoIndicatorsInScannedScope
if (( finding_count > 0 )); then status=IndicatorsFound
elif (( error_count > 0 || skipped_count > 0 || root_count == 0 )); then status=Incomplete
fi

json_array() {
    local separator= item
    printf '['
    while IFS= read -r item; do printf '%s%s' "$separator" "$item"; separator=,; done < "$1"
    printf ']'
}

# Noclobber makes report creation exclusive, including if another run used the same name.
if ! (
    set -o noclobber
    {
        printf '{"Advisory":"https://github.com/advisories/GHSA-764m-3ppc-5m73","Platform":"macOS-compatible shell","Mode":'
        json_string "$mode"
        printf ',"ComputerName":'; json_string "${HOSTNAME:-unknown}"
        printf ',"Scope":'; json_string "$scope"
        printf ',"StartedUtc":'; json_string "$started"
        printf ',"ScanTimeUtc":'; json_string "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf ',"Status":'; json_string "$status"
        printf ',"CandidateFilesExamined":%s,"Roots":' "$files_examined"; json_array "$work/roots"
        printf ',"Findings":'; json_array "$work/findings"
        printf ',"PackageInventory":'; json_array "$work/inventory"
        printf ',"Errors":'; json_array "$work/errors"
        printf ',"SkippedSymlinks":'; json_array "$work/skipped"
        printf ',"Limitations":['
        json_string 'Point-in-time file inspection only; no proof of historical absence, execution, or exfiltration.'
        printf ','; json_string 'Quick checks filenames only. Deep inspects selected metadata, dependency files, ZIP/wheels and pip bodies, not other archive formats or nested/container layers.'
        printf ','; json_string 'Symlinks, .git directories and nested filesystem mounts are not followed. Inspect authorized physical targets/volumes as explicit roots.'
        printf ','; json_string 'Dependency parsing covers common exact pins, conventional Pipfile.lock objects, and TOML package records, not arbitrary build code or a universal dependency resolver.'
        printf ','; json_string 'CandidateFilesExamined counts files selected by filename, not every file traversed. No Python, package imports, or credential files are executed/read.'
        printf ']}\n'
    } > "$report"
); then printf 'ERROR: Could not save report: %q\n' "$report" >&2; exit 1
fi
printf '\nResult: %s; %s findings; %s errors; %s skipped symlinks.\n' "$status" "$finding_count" "$error_count" "$skipped_count"
printf 'Report saved to: %q\n' "$report"
printf 'Send this report to your security/IT contact. A completed scan does NOT establish that the machine is safe.\n'
