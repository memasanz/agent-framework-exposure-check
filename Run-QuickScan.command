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
if (( result != 0 )); then
    printf '\nERROR: The scan could not finish. Contact IT; do not bypass security controls.\n' >&2
fi
printf '\nPress Return to close this window.'
IFS= read -r _ || :
exit "$result"
