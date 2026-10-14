# Unit tests for update-adobe-rum.sh 'nothing offered' handling (CSMB-002, 2026-10-13).
# Run: bash macos/tests/update-adobe-rum.test.sh
set -u
here=$(cd "$(dirname "$0")" && pwd)
script=$(cd "$here/.." && pwd)/update-adobe-rum.sh
fix=$(mktemp -d)
trap 'rm -rf "$fix"' EXIT

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
rc_of() { "$@" >/dev/null 2>&1; echo $?; }

export RUM_SELFTEST=lib
# shellcheck source=/dev/null
. "$script" 2>/dev/null
LOG_FILE=/dev/null
WORK="$fix"

csmb002_out='RemoteUpdateManager version is : 3.1.0.3
Starting the RemoteUpdateManager...
**************************************************
No new updates are available for Acrobat/Reader
**************************************************
RemoteUpdateManager exiting with Return Code (2)'

check 'CSMB-002 stdout reads as no updates' "$(rc_of rum_said_no_updates "$csmb002_out")" 0
check 'generic RC 1 stdout is not no-updates' "$(rc_of rum_said_no_updates 'Starting the RemoteUpdateManager...
RemoteUpdateManager exiting with Return Code (1)')" 1
check 'no-updates plus a failure line is not trusted' "$(rc_of rum_said_no_updates 'No new updates are available for Acrobat/Reader
Failed to install Adobe Bridge')" 1

printf '%s\n' '/Applications/Adobe Acrobat DC/Adobe Acrobat.app|26.002.22008' \
  '/Applications/Adobe Acrobat DC/Acrobat Distiller.app|26.002.22008' > "$fix/acro"
printf '%s\n' '/Applications/Adobe Acrobat Reader.app|26.001.20000' > "$fix/reader"
printf '%s\n' '/Applications/Adobe Acrobat DC/Adobe Acrobat.app|26.002.22008' \
  '/Applications/Adobe Bridge 2026/Adobe Bridge 2026.app|16.0.5' > "$fix/bridge"
: > "$fix/empty"

check 'Acrobat DC bundle dir is Acrobat-only' "$(rc_of only_acrobat_apps "$fix/acro")" 0
check 'Reader is Acrobat-only' "$(rc_of only_acrobat_apps "$fix/reader")" 0
check 'Bridge present is not Acrobat-only' "$(rc_of only_acrobat_apps "$fix/bridge")" 1
check 'empty inventory is not Acrobat-only' "$(rc_of only_acrobat_apps "$fix/empty")" 1

fake="$fix/RemoteUpdateManager"
printf '#!/bin/bash\nprintf "%%s\\n" "$FAKE_OUT"\nexit "$FAKE_RC"\n' > "$fake"
chmod +x "$fake"
RUM="$fake"
export FAKE_OUT="$csmb002_out" FAKE_RC=2

cp "$fix/acro" "$fix/before"
rum_install_once >/dev/null 2>&1
check 'CSMB-002: RC 2 no-updates on Acrobat-only sets RUM_OK' "$RUM_OK" 1
check 'CSMB-002: RUM_NOTHING set' "$RUM_NOTHING" 1

cp "$fix/bridge" "$fix/before"
rum_install_once >/dev/null 2>&1
check 'Bridge installed: same RC 2 stays a failure' "$RUM_OK" 0
check 'Bridge installed: RUM_NOTHING not set' "$RUM_NOTHING" 0

export FAKE_OUT='Starting the RemoteUpdateManager...
RemoteUpdateManager exiting with Return Code (0)' FAKE_RC=0
rum_install_once >/dev/null 2>&1
check 'RC 0 is success' "$RUM_OK" 1
check 'RC 0 is not nothing-offered' "$RUM_NOTHING" 0

export FAKE_OUT="$csmb002_out" FAKE_RC=2
cp "$fix/acro" "$fix/before"
SAP_CODES=APRO
rum_install_once >/dev/null 2>&1
check 'SAP_CODES path: no-updates on Acrobat-only sets RUM_OK' "$RUM_OK" 1
SAP_CODES=

if [ "$fail" -ne 0 ]; then
  echo "test(s) failed"
  exit 1
fi
echo "All tests passed"
exit 0
