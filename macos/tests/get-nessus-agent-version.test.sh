# Unit tests for get-nessus-agent-version.sh helpers.
# Run: bash macos/tests/get-nessus-agent-version.test.sh
#
# Covers CSPRIM-08 (2026-09-25): plugin 326953 reported Nessus Agent 11.2.0 at
# /Library/NessusAgent while Sensors > Agents showed the same host running
# 11.2.3. The verdict has to tell "the binaries are old" apart from "a receipt
# still says they are old", because only the first one is a real finding.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
script=$(cd "$here/.." && pwd)/get-nessus-agent-version.sh

fail=0
check() {
  name=$1; got=$2; want=$3
  if [ "$got" != "$want" ]; then
    echo "FAIL $name: got '$got' want '$want'"
    fail=1
  else
    echo "OK   $name"
  fi
}
check_rc() {
  name=$1; want=$2; shift 2
  if "$@"; then got=0; else got=1; fi
  if [ "$got" != "$want" ]; then
    echo "FAIL $name: rc $got want $want"
    fail=1
  else
    echo "OK   $name"
  fi
}

export NESSUS_VER_SELFTEST=1
# shellcheck source=/dev/null
. "$script"

# --- version_ge -------------------------------------------------------------
check_rc '11.2.3 >= 11.2.1' 0 version_ge 11.2.3 11.2.1
check_rc '11.2.1 >= 11.2.1' 0 version_ge 11.2.1 11.2.1
check_rc '11.2.0 >= 11.2.1 is false' 1 version_ge 11.2.0 11.2.1
check_rc '11.1.3 >= 11.2.1 is false' 1 version_ge 11.1.3 11.2.1
check_rc '11.10.0 >= 11.2.1 (numeric, not lexical)' 0 version_ge 11.10.0 11.2.1
check_rc '11.2 >= 11.2.1 is false (missing field is 0)' 1 version_ge 11.2 11.2.1
check_rc '11.3 >= 11.2.1' 0 version_ge 11.3 11.2.1

# --- parse_version ----------------------------------------------------------
check 'nessuscli banner' "$(parse_version 'nessuscli (Nessus) 11.2.3 for Darwin')" '11.2.3'
check 'nessusd banner' "$(parse_version 'nessusd (Nessus) 11.2.0 for Darwin')" '11.2.0'
check 'pkgutil version line' "$(parse_version 'version: 11.2.0')" '11.2.0'
check 'four-part build' "$(parse_version 'Nessus Agent 11.2.3.20260910')" '11.2.3.20260910'
check 'no version present' "$(parse_version 'command not found')" ''
check 'empty input' "$(parse_version '')" ''

# --- pkgutil_version_from_text ---------------------------------------------
# Verbatim shape of `pkgutil --pkg-info com.tenablesecurity.nessusagent`.
receipt='package-id: com.tenablesecurity.nessusagent
version: 11.2.0
volume: /
location: 
install-time: 1758124800'
check 'receipt version' "$(pkgutil_version_from_text "$receipt")" '11.2.0'
check 'receipt without version line' "$(pkgutil_version_from_text 'package-id: x')" ''

# --- verdict_for ------------------------------------------------------------
# CSPRIM-08: binaries current, receipt left behind on the installed pkg.
check 'patched binary + stale receipt -> STALE_METADATA' \
  "$(verdict_for 11.2.3 11.2.1 'receipt:com.tenablesecurity.nessusagent=11.2.0')" 'STALE_METADATA'
check 'patched binary + nothing stale -> PATCHED' \
  "$(verdict_for 11.2.3 11.2.1 '')" 'PATCHED'
check 'old binary -> VULNERABLE' "$(verdict_for 11.2.0 11.2.1 '')" 'VULNERABLE'
check 'old binary wins over stale list' \
  "$(verdict_for 11.2.0 11.2.1 'receipt:x=11.2.0')" 'VULNERABLE'
check 'exactly at the floor -> PATCHED' "$(verdict_for 11.2.1 11.2.1 '')" 'PATCHED'
check 'no binary -> NOT_INSTALLED' "$(verdict_for '' 11.2.1 '')" 'NOT_INSTALLED'

if [ "$fail" -ne 0 ]; then
  echo "$fail test(s) failed"
  exit 1
fi
echo "All tests passed"
exit 0
