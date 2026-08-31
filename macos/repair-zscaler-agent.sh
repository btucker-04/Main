#!/bin/bash
# =============================================================================
# repair-zscaler-agent.sh
# AGENT   : Zscaler Client Connector (ZCC)
# PURPOSE : Diagnose + BOUNDED remediation for a Zscaler Client Connector that
#           has stopped checking in ("not clean" in the fleet agent-status
#           report -- see agent-zscaler-not-clean-*.xlsx). Emits exactly ONE
#           machine-parseable line per host to stdout, in the SAME schema as
#           windows/Repair-ZscalerAgent.ps1, so both platforms roll up into
#           one collector/report. Also writes a full evidence log per run to
#           /var/log/composecure for troubleshooting one specific host later.
# Platform: macOS (bash 3.2 compatible) | Deploy: Mosyle (runs as root)
#
# WHY DISCOVERY INSTEAD OF HARDCODED SERVICE NAMES: the Windows counterpart
# script was written against verified ZSA* service short names on a reference
# host. No equivalent verification has been done here against a real Mac in
# this fleet, and guessing launchd labels/process names with false confidence
# risks silently misdiagnosing a healthy agent as broken (or vice versa) on a
# script that takes remediation action. So this script DISCOVERS every
# zscaler-related launchd entry (`launchctl list | grep -i zscaler`) rather
# than checking a fixed label, and reports exactly what it found. Before a
# fleet run, verify the discovered labels/paths on one real host from this
# batch (CSMB-003, CSMB-021, CSMB-052, CSMB-064, CSPRMB-09-A, CSPRMB-27-A) --
# see the MANUAL VERIFICATION section at the bottom of this file.
#
# Never uninstalls, reinstalls, deletes binaries, or alters Zscaler policy.
# The only remediation performed is `launchctl kickstart -k` on an already-
# loaded daemon that is not running or is stale, the same bounded action
# repair-nessus-agent.sh uses for the Nessus Agent LaunchDaemon.
#
# STATUS BANDS / EXIT CODES (identical bands to the Windows script)
#   HEALTHY                0  installed, running, checking in; no action taken
#   RECOVERED              0  was unhealthy; bounded remediation succeeded
#   DEGRADED               1  partially working, or remediation blocked
#   REINSTALL_RECOMMENDED  2  safe remediation exhausted; see the log file
#   NOT_INSTALLED          3  agent not present on this host
#   ERROR                  4  script could not complete its own checks
#
# NOTE ON A REAL FLEET RUN (2026-08-31, agent-zscaler-not-clean-20260831.xlsx):
# 6 of the 25 flagged hosts are Mac (CSMB-003/021/052/064, CSPRMB-09-A/27-A).
# 2 of those 6 (CSPRMB-09-A: 151 days stale; CSPRMB-27-A: 13 days) are ALSO
# flagged 'Not in Device Export' in the Zscaler admin console -- the console
# has no device record at all for that host. This script can only diagnose
# and repair the LOCAL agent; a missing console device record needs console-
# side re-enrollment and cannot be fixed by anything running on the endpoint.
# Cross-reference this script's verdict against that console flag before
# assuming HEALTHY/RECOVERED here means the host will start reporting fleet-
# wide.
#
# ENVIRONMENT (all optional; Mosyle passes none, so edit CONFIG below):
#   CHECKIN_STALE_MINUTES=60   minutes of log inactivity treated as STALE
#   DRY_RUN=1                  report only, kickstart nothing
#
# Exit: matches the bands above.
# =============================================================================

set -uo pipefail
HOME="${HOME:-/var/root}"
export HOME

# =============================================================================
# CONFIG -- Mosyle passes no environment variables. Edit before deploying.
# ⚠️ MANUAL: verify these on a reference host from this fleet before a wide run
# (see MANUAL VERIFICATION at the bottom of this file).
# =============================================================================
CFG_APP_GLOB="/Applications/*[Zz]scaler*.app"
CFG_LOG_ROOTS="/Library/Application Support/Zscaler /var/log/zscaler $HOME/Library/Logs/Zscaler"
CFG_LOG_PATTERN="*.log"
CFG_CHECKIN_STALE_MINUTES="60"
CFG_DRY_RUN="0"
# =============================================================================
CHECKIN_STALE_MINUTES="${CHECKIN_STALE_MINUTES:-$CFG_CHECKIN_STALE_MINUTES}"
DRY_RUN="${DRY_RUN:-$CFG_DRY_RUN}"

LOG_DIR="/var/log/composecure"
HOST_SHORT=$(hostname -s 2>/dev/null || hostname)
LOG_FILE="$LOG_DIR/zscaler_agent_repair_${HOST_SHORT}_$(date '+%Y%m%d_%H%M%S').log"
mkdir -p "$LOG_DIR" 2>/dev/null || true

# Full evidence trail goes to disk ONLY -- best-effort and silent on failure,
# matching Write-DiagnosticLog in the Windows counterpart. The one stdout line
# this script emits is the final `echo "$FIELDS"` at the very end; nothing
# else may write to stdout, or it corrupts the single parseable row a fleet
# collector reads.
log() { { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"; } 2>/dev/null || true; }

EVIDENCE_OK=0; EVIDENCE_WARN=0; EVIDENCE_FAIL=0
FIRST_FAIL=""
evidence() {
    # $1=level $2=message
    log "[$1] $2"
    case "$1" in
        OK)   EVIDENCE_OK=$((EVIDENCE_OK+1)) ;;
        WARN) EVIDENCE_WARN=$((EVIDENCE_WARN+1)) ;;
        FAIL)
            EVIDENCE_FAIL=$((EVIDENCE_FAIL+1))
            [ -z "$FIRST_FAIL" ] && FIRST_FAIL="$2"
            ;;
    esac
}
LAST_ACTION=""
ACTIONS_TAKEN=0
action() { log "[ACTION] $1"; LAST_ACTION="$1"; ACTIONS_TAKEN=$((ACTIONS_TAKEN+1)); }

# Collapse free text for the single-line report: no pipes, no newlines, capped
# length, matching Format-Field in the Windows counterpart so both platforms'
# rows are equally safe for a naive split on '|'.
sanitize_field() {
    s=$(echo "$1" | tr '\n\r\t' ' ' | tr '|' '/' | sed -E 's/  +/ /g')
    s=$(echo "$s" | sed -E 's/^ *//; s/ *$//')
    if [ ${#s} -gt 160 ]; then
        s=$(echo "$s" | cut -c1-157)
        s="${s}..."
    fi
    printf '%s' "$s"
}

log "=============================================="
log " Zscaler Agent Check -- $HOST_SHORT"
log "=============================================="

INSTALLED=0
VERSION="UNKNOWN"
RUNNING_STATE="UNKNOWN"   # OK | PARTIAL | STOPPED | UNKNOWN
CHECKIN_STATE="UNKNOWN"   # OK | STALE | UNKNOWN
TAMPER=0
STATUS=""
CODE=0
REASON=""

# -----------------------------------------------------------------------
# Root required. No privileged action is attempted otherwise. The rest of
# the ladder is skipped entirely (not just aborted mid-way) so a permission
# problem can never be misread as an agent-health finding.
# -----------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    evidence FAIL "Running as $(id -un), which is not root. No privileged action attempted."
    STATUS="ERROR"; CODE=4
    REASON="Not running as root. Re-run via Mosyle (root) or sudo."
else

# =============================================================================
# 1. Installed? (app bundle + any zscaler launchd registration)
# =============================================================================
FOUND_APP=""
for cand in $CFG_APP_GLOB; do
    [ -d "$cand" ] || continue
    FOUND_APP="$cand"
    break
done

DISCOVERED_LABELS=""
if command -v launchctl >/dev/null 2>&1; then
    DISCOVERED_LABELS=$(launchctl list 2>/dev/null | awk '{print $3}' | grep -i zscaler || true)
fi

if [ -n "$FOUND_APP" ]; then
    INSTALLED=1
    evidence OK "App bundle present: $FOUND_APP"
    INFOPLIST="$FOUND_APP/Contents/Info.plist"
    if [ -f "$INFOPLIST" ]; then
        V=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$INFOPLIST" 2>/dev/null || true)
        [ -n "$V" ] && VERSION="$V"
    fi
    evidence INFO "Detected version: $VERSION"
else
    evidence WARN "No app bundle matching '$CFG_APP_GLOB' found."
fi

if [ -n "$DISCOVERED_LABELS" ]; then
    INSTALLED=1
    evidence OK "Discovered zscaler launchd label(s): $(echo "$DISCOVERED_LABELS" | tr '\n' ' ')"
else
    evidence WARN "No launchd entry with 'zscaler' in its label is currently loaded."
fi

if [ "$INSTALLED" -eq 0 ]; then
    STATUS="NOT_INSTALLED"; CODE=3
    REASON="No app bundle and no loaded launchd entry found for Zscaler."
    evidence FAIL "$REASON"
else

# =============================================================================
# 2. Running? Classify each discovered launchd entry by its PID column.
#    ('-' in the PID column means loaded but not running.)
# =============================================================================
RUNNING_COUNT=0
TOTAL_COUNT=0
if [ -n "$DISCOVERED_LABELS" ]; then
    while IFS= read -r label; do
        [ -n "$label" ] || continue
        TOTAL_COUNT=$((TOTAL_COUNT+1))
        line=$(launchctl list 2>/dev/null | awk -v l="$label" '$3==l {print $1}')
        if [ "$line" != "-" ] && [ -n "$line" ]; then
            RUNNING_COUNT=$((RUNNING_COUNT+1))
            evidence OK "launchd '$label' running (pid $line)."
        else
            evidence FAIL "launchd '$label' is loaded but NOT running (pid '-')."
        fi
    done <<EOF2
$DISCOVERED_LABELS
EOF2
fi

# Corroborating process-level check (best-effort; a heuristic name match, not
# an authoritative service list -- see the header note on discovery).
if pgrep -if 'zscaler' >/dev/null 2>&1; then
    evidence OK "At least one process matching 'zscaler' is running."
else
    evidence WARN "No running process matches 'zscaler' by name."
fi

if [ "$TOTAL_COUNT" -eq 0 ]; then
    RUNNING_STATE="UNKNOWN"
elif [ "$RUNNING_COUNT" -eq "$TOTAL_COUNT" ]; then
    RUNNING_STATE="OK"
elif [ "$RUNNING_COUNT" -eq 0 ]; then
    RUNNING_STATE="STOPPED"
else
    RUNNING_STATE="PARTIAL"
fi

# =============================================================================
# 3. Checking in? Log-write freshness is the check-in proxy, same as Windows.
#    UNKNOWN must never escalate to REINSTALL_RECOMMENDED -- a missing log
#    trail is a telemetry gap, not proof the agent is broken.
# =============================================================================
NEWEST_LOG=""
NEWEST_AGE_MIN=""
for root in $CFG_LOG_ROOTS; do
    [ -d "$root" ] || continue
    cand=$(find "$root" -type f -name "$CFG_LOG_PATTERN" -exec stat -f '%m %N' {} \; 2>/dev/null | sort -rn | head -1)
    [ -z "$cand" ] && continue
    epoch="${cand%% *}"
    path="${cand#* }"
    now=$(date '+%s')
    age=$(( (now - epoch) / 60 ))
    if [ -z "$NEWEST_AGE_MIN" ] || [ "$age" -lt "$NEWEST_AGE_MIN" ]; then
        NEWEST_AGE_MIN="$age"
        NEWEST_LOG="$path"
    fi
done

if [ -z "$NEWEST_LOG" ]; then
    evidence WARN "No files matching '$CFG_LOG_PATTERN' under any of: $CFG_LOG_ROOTS"
    CHECKIN_STATE="UNKNOWN"
elif [ "$NEWEST_AGE_MIN" -le "$CHECKIN_STALE_MINUTES" ]; then
    evidence OK "Most recent agent log write ${NEWEST_AGE_MIN} min ago (threshold ${CHECKIN_STALE_MINUTES} min): $NEWEST_LOG"
    CHECKIN_STATE="OK"
else
    evidence FAIL "Most recent agent log write ${NEWEST_AGE_MIN} min ago exceeds the ${CHECKIN_STALE_MINUTES} min threshold: $NEWEST_LOG"
    CHECKIN_STATE="STALE"
fi

# =============================================================================
# 4. Bounded remediation: kickstart a stopped or stale daemon. Never
#    uninstall/reinstall/delete binaries/alter policy.
# =============================================================================
REMEDIATION_BLOCKED=0
if [ "$RUNNING_STATE" != "OK" ] || [ "$CHECKIN_STATE" = "STALE" ]; then
    if [ "$TOTAL_COUNT" -eq 0 ]; then
        evidence WARN "No launchd entries discovered to remediate."
    elif [ "$DRY_RUN" = "1" ]; then
        evidence INFO "[DRY_RUN] Would kickstart: $(echo "$DISCOVERED_LABELS" | tr '\n' ' ')"
    else
        while IFS= read -r label; do
            [ -n "$label" ] || continue
            action "Kickstarting launchd '$label' to force re-check-in."
            OUT=$(launchctl kickstart -k "system/$label" 2>&1)
            RC=$?
            if [ "$RC" -ne 0 ]; then
                if echo "$OUT" | grep -qi "denied\|not authorized\|not permitted"; then
                    TAMPER=1
                    REMEDIATION_BLOCKED=1
                    evidence FAIL "launchd '$label': kickstart blocked - $OUT"
                else
                    evidence FAIL "launchd '$label': kickstart failed (rc=$RC) - $OUT"
                fi
            fi
        done <<EOF3
$DISCOVERED_LABELS
EOF3
        sleep "${SERVICE_WAIT_SECONDS:-10}"

        # Re-check after remediation.
        RUNNING_COUNT=0
        while IFS= read -r label; do
            [ -n "$label" ] || continue
            line=$(launchctl list 2>/dev/null | awk -v l="$label" '$3==l {print $1}')
            if [ "$line" != "-" ] && [ -n "$line" ]; then
                RUNNING_COUNT=$((RUNNING_COUNT+1))
                evidence OK "Post-remediation: launchd '$label' running (pid $line)."
            else
                evidence WARN "Post-remediation: launchd '$label' still not running."
            fi
        done <<EOF4
$DISCOVERED_LABELS
EOF4
        if [ "$TOTAL_COUNT" -gt 0 ]; then
            if [ "$RUNNING_COUNT" -eq "$TOTAL_COUNT" ]; then RUNNING_STATE="OK"
            elif [ "$RUNNING_COUNT" -eq 0 ]; then RUNNING_STATE="STOPPED"
            else RUNNING_STATE="PARTIAL"; fi
        fi

        # Re-check log freshness once, giving the agent a moment to write.
        for root in $CFG_LOG_ROOTS; do
            [ -d "$root" ] || continue
            cand=$(find "$root" -type f -name "$CFG_LOG_PATTERN" -newermt "-2 minutes" 2>/dev/null | head -1)
            if [ -n "$cand" ]; then CHECKIN_STATE="OK"; evidence OK "Fresh log write observed after remediation: $cand"; break; fi
        done
    fi
fi

# =============================================================================
# 5. Verdict
# =============================================================================
if [ "$REMEDIATION_BLOCKED" -eq 1 ]; then
    STATUS="DEGRADED"; CODE=1
    REASON="Remediation was blocked (permission denial) - console-side or MDM-profile action required."
elif [ "$RUNNING_STATE" = "OK" ] && [ "$CHECKIN_STATE" = "OK" ]; then
    if [ "$ACTIONS_TAKEN" -gt 0 ]; then
        STATUS="RECOVERED"; CODE=0
        REASON="Agent was unhealthy; bounded remediation restored it to a running, reporting state."
    else
        STATUS="HEALTHY"; CODE=0
        REASON="Installed, all discovered launchd entries running, recent check-in confirmed. No action taken."
    fi
elif [ "$RUNNING_STATE" = "OK" ] && [ "$CHECKIN_STATE" = "UNKNOWN" ]; then
    STATUS="DEGRADED"; CODE=1
    REASON="Discovered launchd entries are running, but check-in could not be verified (no readable agent logs). Telemetry gap, not proof of failure - verify this device in the admin portal."
elif [ "$ACTIONS_TAKEN" -gt 0 ]; then
    STATUS="REINSTALL_RECOMMENDED"; CODE=2
    REASON="Bounded remediation ran but the agent did not return to a running, reporting state. No supported non-destructive re-registration path exists on macOS either."
else
    STATUS="DEGRADED"; CODE=1
    REASON="Agent state could not be fully confirmed. Review the evidence log."
fi

fi   # end INSTALLED branch

fi   # end root-check else branch

# =============================================================================
# Emit: exactly ONE line to stdout, same schema as the Windows script.
# =============================================================================
FIELDS="schema=1|agent=Zscaler|os=Mac|host=${HOST_SHORT}"
FIELDS="${FIELDS}|status=${STATUS}|code=${CODE}"
FIELDS="${FIELDS}|installed=${INSTALLED}|version=$(sanitize_field "$VERSION")"
FIELDS="${FIELDS}|services=${RUNNING_STATE}|checkin=${CHECKIN_STATE}|tamper=${TAMPER}"
FIELDS="${FIELDS}|remediated=$([ "$ACTIONS_TAKEN" -gt 0 ] && echo 1 || echo 0)|actions=${ACTIONS_TAKEN}"
FIELDS="${FIELDS}|fails=${EVIDENCE_FAIL}|warns=${EVIDENCE_WARN}"
FIELDS="${FIELDS}|lastaction=$(sanitize_field "$LAST_ACTION")|firstfail=$(sanitize_field "$FIRST_FAIL")"
FIELDS="${FIELDS}|reason=$(sanitize_field "$REASON")"
FIELDS="${FIELDS}|ts=$(date '+%Y-%m-%dT%H:%M:%S%z')"

log ""
log "VERDICT: ${STATUS} (exit ${CODE})"
log "REASON : ${REASON}"
log "Log file: $LOG_FILE"

echo "$FIELDS"
exit "$CODE"

# =============================================================================
# MANUAL VERIFICATION -- complete before a fleet-wide run
# =============================================================================
#
# [ ] On a real Mac from this batch (CSMB-003, CSMB-021, CSMB-052, CSMB-064,
#     CSPRMB-09-A, CSPRMB-27-A), run as root:
#         launchctl list | grep -i zscaler
#         ls /Applications | grep -i zscaler
#     and confirm the discovered label(s)/app path match what this script
#     expects. If Zscaler installs under a different app name or its launchd
#     labels do not contain the substring "zscaler", update CFG_APP_GLOB and
#     the `grep -i zscaler` calls above.
# [ ] Confirm the real log directory. CFG_LOG_ROOTS is a best-effort guess list
#     (unverified against a real host) -- confirm which one(s) actually
#     receive writes on a healthy agent, and prune the rest so a stale
#     directory does not produce a false STALE/UNKNOWN read.
# [ ] Confirm CHECKIN_STALE_MINUTES against the agent's actual log verbosity,
#     same caution as the Windows script: a low-verbosity profile can make a
#     healthy agent look STALE and trigger a needless kickstart.
# [ ] Cross-reference against the Zscaler admin console's device export. A
#     host this script reports HEALTHY/RECOVERED but that is flagged 'Not in
#     Device Export' will still show as missing fleet-wide -- that half of
#     the problem is console-side and this script cannot see or fix it.
# [ ] Stagger the fleet run -- kickstarting the tunnel daemon briefly drops
#     connectivity, same caution as the Windows script's Rung 3.
# =============================================================================
