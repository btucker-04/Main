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

# --- CSMB-062 2026-11-10: two copies started in the same second ---
RUN_LOCK="$fix/run.lock"
HOLD_RUN_LOCK=0
take_run_lock
check 'free lock is taken' "$HOLD_RUN_LOCK" 1
check 'lock records our pid' "$(cat "$RUN_LOCK/pid")" "$$"
sleep 30 & other=$!
echo "$other" > "$RUN_LOCK/pid"; HOLD_RUN_LOCK=0
check 'live other copy keeps the lock' "$(rc_of take_run_lock)" 1
take_run_lock
check 'holder pid reported' "$HELD_BY" "$other"
kill "$other"; wait "$other" 2>/dev/null
take_run_lock
check 'dead holder: lock taken over' "$HOLD_RUN_LOCK" 1
check 'dead holder: our pid recorded' "$(cat "$RUN_LOCK/pid")" "$$"
rm -rf "$RUN_LOCK"

# 'Concurrent/young RUM (elapsed 117s < STALE_RUM_SECONDS=600 / or KILL_STALE_RUM=1)'
check 'young RUM reason with killing on' "$(rum_spare_reason 1 117 600)" 'elapsed 117s < STALE_RUM_SECONDS=600, so it is a young job, not a hung one'
check 'killing off is the reason' "$(rum_spare_reason 0 900 600)" 'KILL_STALE_RUM=0'

ps() {
  case "$4" in
    25708) echo '25690 /usr/local/bin/RemoteUpdateManager --action=install' ;;
    25690) echo '25001 /bin/bash /private/tmp/mosyle/update-adobe-rum.sh' ;;
    25001) echo '    1 /usr/local/bin/MosyleAgent' ;;
  esac
}
check 'launcher chain up to launchd' "$(rum_launcher_chain 25708)" \
  '25708 /usr/local/bin/RemoteUpdateManager --action=install <- 25690 /bin/bash /private/tmp/mosyle/update-adobe-rum.sh <- 25001 /usr/local/bin/MosyleAgent'
check 'gone pid gives an empty chain' "$(rum_launcher_chain 99999)" ''
unset -f ps

# --- CSMB-062 2026-11-10 14:25 run: Mosyle cut the log inside the RUM dump ---
cat > "$fix/rum.log" <<'EOF'
10/21/26 12:11:43:679 | [FATAL] |  | AAMEE | Utilities | RemoteUpdateManager |  | HDPIM | 86161 | 0 | Fatal Error &apos;113&apos; occurred while download
11/09/26 14:12:21:604 | [INFO] |  | AAMEE | Utilities | RemoteUpdateManager |  |  | 14373 | 0 | Ending the RemoteUpdateManager Return Code (0)
11/10/26 19:57:50:262 | [ERROR] |  | AAMEE | Utilities | RemoteUpdateManager | isSegmentSizeValid | OOBEUtils | 424150 | 0 | Downloaded Size=1465142 of segmentID=1 does match Validator Size=2097152
    continuation line without a timestamp
11/10/26 20:13:31:847 | [ERROR] |  | AAMEE | Utilities | RemoteUpdateManager | isSegmentSizeValid | OOBEUtils | 424150 | 0 | Downloaded Size=219205 of segmentID=2 does match Validator Size=2097152
11/10/26 20:53:57:475 | [ERROR] |  | AAMEE | Utilities | RemoteUpdateManager |  |  | 421425 | 0 | Failed to download HD media (PPROBETA, 27.1), library returned error (129)...
11/10/26 20:53:58:002 | [FATAL] |  | AAMEE | Utilities | RemoteUpdateManager |  | HDPIM | 421425 | 0 | Error occurred in accepting control request with error code &apos;102&apos;
EOF
since=$(rum_lines_since "$fix/rum.log" 261110142530)
check 'old RUM log lines are not this run' "$(printf '%s\n' "$since" | grep -c '^1[01]/2[01]/26\|^11/09')" 0
check 'this run: 4 stamped lines' "$(printf '%s\n' "$since" | grep -c .)" 4
cond=$(printf '%s\n' "$since" | grep -E "$RUM_LOG_SIGNAL" | condense_rum_lines)
check 'segment retries folded into one count' "$(printf '%s\n' "$cond" | tail -1)" '2 x isSegmentSizeValid: a downloaded segment was shorter than Adobe says'
check 'constant columns dropped' "$(printf '%s\n' "$cond" | head -1)" \
  '11/10/26 20:53:57:475 | [ERROR] |  |  |  | 421425 | 0 | Failed to download HD media (PPROBETA, 27.1), library returned error (129)...'
long=$(printf '11/10/26 20:00:00:000 | [ERROR] | %0300d\n' 0 | condense_rum_lines)
check 'long lines capped' "${#long}" 220

list_out='RemoteUpdateManager version is : 3.1.0.3
Starting the RemoteUpdateManager...
**************************************************
No new updates are available for Acrobat/Reader
**************************************************
Following Updates are applicable on the system :
		(PPROBETA/27.1.0.42/macarm64)
**************************************************
RemoteUpdateManager exiting with Return Code (0)'
check 'offered updates parsed from list' "$(rum_offered_updates "$list_out")" 'PPROBETA/27.1.0.42/macarm64'
check 'nothing offered parses empty' "$(rum_offered_updates "$csmb002_out")" ''

if [ "$fail" -ne 0 ]; then
  echo "test(s) failed"
  exit 1
fi
echo "All tests passed"
exit 0
