#!/bin/bash
set -uo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
script_directory=$(cd -P -- "$(dirname -- "$0")" && pwd -P) || exit 1
printf 'Agent Framework - Quick Exposure Check (macOS)\n\n'
printf 'This checks your home folder only. It never runs Python, deletes files, or uploads results.\n\n'
result=0
if [[ ! -f "$script_directory/Test-AgentFrameworkExposure.sh" ]]; then
    printf 'ERROR: Scanner missing. Extract all files from the ZIP into the same folder.\n' >&2
    result=1
else
    /bin/bash "$script_directory/Test-AgentFrameworkExposure.sh" --mode Quick || result=$?
fi
case "$result" in
    0) ;;
    2) printf '\nWARNING: Reports saved, but coverage is incomplete. Ask IT to review access restrictions and skipped links.\n' >&2 ;;
    3) printf '\nALERT: Reports saved with indicators. Avoid suspect Python environments and contact IT.\n' >&2 ;;
    4) printf '\nALERT: Reports saved with indicators AND incomplete coverage. Contact IT.\n' >&2 ;;
    *) printf '\nERROR: The scanner failed. A report pair may be missing or partial. Contact IT; do not bypass security controls.\n' >&2 ;;
esac
printf '\nPress Return to close this window.'
IFS= read -r _ || :
exit "$result"
