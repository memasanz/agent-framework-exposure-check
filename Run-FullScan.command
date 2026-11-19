#!/bin/bash
set -uo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
script_directory=$(cd -P -- "$(dirname -- "$0")" && pwd -P) || exit 1
scan_root=/
if [[ -d /System/Volumes/Data ]]; then scan_root=/System/Volumes/Data; fi

printf 'Agent Framework - Full Exposure Check (macOS)\n\n'
printf 'This performs DEEP checks across the main data volume: %s\n' "$scan_root"
printf 'It checks filenames, package metadata, dependency files, and archives.\n'
printf 'Other mounted volumes are excluded. Protected folders may be inaccessible.\n'
printf 'This can take much longer than Quick scanning. Obtain authorization first.\n'
printf 'Do NOT run with sudo or grant extra access without IT approval.\n'
printf 'Python is never started. Files are not deleted and results are not uploaded.\n\n'

result=0
if [[ -z ${HOME:-} ]]; then
    printf 'ERROR: Your home folder could not be determined.\n' >&2
    result=1
elif [[ ! -f "$script_directory/Test-AgentFrameworkExposure.sh" ]]; then
    printf 'ERROR: Scanner missing. Extract all files from the ZIP into the same folder.\n' >&2
    result=1
else
    printf 'Type FULL and press Return to start; anything else cancels: '
    confirmation=
    IFS= read -r confirmation || confirmation=
    if [[ "$confirmation" == FULL ]]; then
        report="$HOME/AgentFramework-FullReport-$(date -u '+%Y%m%dT%H%M%SZ')-$$.json"
        /bin/bash "$script_directory/Test-AgentFrameworkExposure.sh" \
            --mode Deep --root "$scan_root" --report "$report" || result=$?
    else
        printf '\nCancelled. No scan was started and no report was created.\n'
    fi
fi
if (( result != 0 )); then
    printf '\nERROR: The scan could not finish. Contact IT; do not bypass security controls.\n' >&2
fi
printf '\nPress Return to close this window.'
IFS= read -r _ || :
exit "$result"
