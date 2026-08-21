#!/bin/bash
# =============================================================================
# NessusAgentRepair_macOS.sh
# macOS counterpart of NessusAgentRepair.ps1 -- checks the agent's ACTUAL state
# and only fixes what is broken. A healthy, connected, correctly-linked agent is
# left completely alone.
#
# Platform : macOS (bash 3.2 compatible) | Deploy: Mosyle (runs as root)
#
# Why this exists alongside NessusRelink_macOS.sh: the relink script ALWAYS
# unlinks and relinks, which needlessly resets an agent's manager-side identity.
# This one reads status first and skips healthy hosts, matching the Windows
# repair script's behaviour.
#
# Decision flow:
#   agent installed?      no  -> report and exit 1 (staged pkg needed; this
#                                script does not install the agent)
#   daemon running?       no  -> start it (label discovered, not hardcoded)
#   already linked to the right host AND connected? -> exit 0, touch nothing
#   otherwise             -> resolve groups from the shared prefix rules,
#                            unlink only if stale link state exists, then link
#
# Group resolution matches NessusRelink_macOS.sh. Linking with NO group means no
# scan policy, no plugins, no results -- Tenable would keep reporting the old
# state forever -- so that condition exits 2 rather than claiming success.
#
# Exit: 0 = healthy (already, or repaired and grouped)
#       2 = linked but no group, or link succeeded without a confirmed connection
#       1 = agent missing / daemon dead / link failed
# =============================================================================

set -uo pipefail
HOME="${HOME:-/var/root}"
export HOME

LINK_KEY="${LINK_KEY:-4f858e2b28a33a5927c7805eab8b8533ecb35c983417b392c5b570b5a6a96fba}"
LINK_HOST="${LINK_HOST:-sensor.cloud.tenable.com}"
LINK_GROUPS_OVERRIDE="${LINK_GROUPS:-}"
FORCE_RELINK="${FORCE_RELINK:-0}"

CLI="/Library/NessusAgent/run/sbin/nessuscli"
LOG_DIR="/var/log/composecure"
LOG_FILE="$LOG_DIR/nessus_agent_repair.log"
mkdir -p "$LOG_DIR"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }

NO_GROUP=0

groups_for_host() {
    # Prefix rules (bash case matches in order, longest/most specific first).
    # Derived from the cleaned agents export 2026-08-04. All 87 Macs resolve.
    # An unmatched host returns empty -> the caller refuses to link with no
    # group, because an ungrouped agent never scans and its finding never clears.
    case "$1" in
        # Exact-host overrides -- checked first, win over any prefix rule
        # (mirrors the Windows $GroupOverride map). CV-MBPC02 is a MacBook
        # despite the CV- prefix, which on Windows maps to Windows Servers.
        CV-MBPC02) echo "MacBook" ;;
        JRIEGEL-MAC*) echo "MacBook" ;;
        CSPRMB*) echo "MacBook" ;;
        CSPRIM*) echo "MacBook" ;;
        CSMS*) echo "MacBook" ;;
        ARMB*) echo "MacBook" ;;
        CSIM*) echo "MacBook" ;;
        CSMB*) echo "MacBook" ;;
        *) echo "" ;;
    esac
}

log "=== Nessus Agent Repair (macOS) ==="
log "Host: $(hostname -s)"

# -----------------------------------------------------------------------
# 1. Agent installed?
# -----------------------------------------------------------------------
if [ ! -x "$CLI" ]; then
    log "ERROR: nessuscli not found at $CLI -- the agent is not installed."
    log "       This script repairs an existing install; it does not deploy one."
    log "       Stage the agent .pkg and install it, then re-run."
    exit 1
fi
log "nessuscli: $CLI"

# -----------------------------------------------------------------------
# 2. Daemon running? (discover the label rather than hardcoding it)
# -----------------------------------------------------------------------
DAEMON_LABEL=$(launchctl list 2>/dev/null | awk '{print $3}' | grep -i nessus | head -1 || true)
if [ -z "$DAEMON_LABEL" ]; then
    # not loaded -- look for the plist so we can bootstrap it
    PLIST=$(find /Library/LaunchDaemons -maxdepth 1 -iname '*nessus*.plist' 2>/dev/null | head -1 || true)
    if [ -n "$PLIST" ]; then
        LABEL_FROM_PLIST=$(/usr/libexec/PlistBuddy -c "Print :Label" "$PLIST" 2>/dev/null || true)
        log "Agent daemon not loaded. Bootstrapping ${LABEL_FROM_PLIST:-$PLIST}..."
        launchctl bootstrap system "$PLIST" 2>/dev/null || launchctl load -w "$PLIST" 2>/dev/null || true
        sleep 5
        DAEMON_LABEL=$(launchctl list 2>/dev/null | awk '{print $3}' | grep -i nessus | head -1 || true)
    fi
fi
if [ -z "$DAEMON_LABEL" ]; then
    log "ERROR: no Nessus agent LaunchDaemon is loaded and none could be started."
    log "       Treat this as a broken install rather than a link problem."
    exit 1
fi
log "Daemon: $DAEMON_LABEL (loaded)"
if ! pgrep -x nessusd >/dev/null 2>&1; then
    log "nessusd not running -- kickstarting $DAEMON_LABEL..."
    launchctl kickstart -k "system/$DAEMON_LABEL" 2>/dev/null || true
    sleep 5
fi
if pgrep -x nessusd >/dev/null 2>&1; then
    log "nessusd: running"
else
    log "WARNING: nessusd still not running; status output below may be unreliable."
fi

# -----------------------------------------------------------------------
# 3. Current state -- do nothing if healthy
# -----------------------------------------------------------------------
log ""
log "Current agent status:"
STATUS=$("$CLI" agent status 2>&1 || true)
echo "$STATUS" | while IFS= read -r line; do
    [ -n "$line" ] && log "  $line"
done

if echo "$STATUS" | grep -qiE 'FIPS module .*Integrity.*FAIL|Module_Integrity HMAC test[[:space:]]+FAIL'; then
    log "WARNING: FIPS module integrity failure reported. If the agent also cannot"
    log "         connect, treat this as a corrupted install and reinstall rather"
    log "         than repairing the link."
fi

LINKED_RIGHT=0
CONNECTED=0
echo "$STATUS" | grep -q "Linked to: *$LINK_HOST" && LINKED_RIGHT=1
echo "$STATUS" | grep -qi "Link status: *Connected" && CONNECTED=1

if [ "$LINKED_RIGHT" -eq 1 ] && [ "$CONNECTED" -eq 1 ] && [ "$FORCE_RELINK" != "1" ]; then
    log ""
    log "Agent is linked to $LINK_HOST and CONNECTED. Nothing to repair."
    log "=== END (healthy) ==="
    exit 0
fi
if [ "$LINKED_RIGHT" -eq 1 ] && [ "$FORCE_RELINK" != "1" ]; then
    log ""
    log "Agent is linked to $LINK_HOST but has not confirmed a connection yet."
    log "That is normal shortly after linking. Not relinking -- re-run later to"
    log "confirm 'Link status: Connected'. Exit 2 so this is not recorded as done."
    log "=== END (linked, connection unconfirmed) ==="
    exit 2
fi

# -----------------------------------------------------------------------
# 4. Resolve groups
# -----------------------------------------------------------------------
log ""
HOST_KEY=$(echo "$(hostname -s)" | tr '[:lower:]' '[:upper:]' | sed 's/\.LOCAL$//')
if [ -n "$LINK_GROUPS_OVERRIDE" ]; then
    GROUPS_CSV="$LINK_GROUPS_OVERRIDE"
    log "Using LINK_GROUPS override: $GROUPS_CSV"
else
    GROUPS_CSV=$(groups_for_host "$HOST_KEY")
    if [ -n "$GROUPS_CSV" ]; then
        log "Resolved groups for $HOST_KEY: $GROUPS_CSV"
    else
        log "WARNING: $HOST_KEY matches no prefix rule."
        log "         Linking with NO GROUP means no scan policy, no plugins and no"
        log "         results -- Tenable would keep reporting the old state forever."
        log "         Set LINK_GROUPS=..., add a prefix rule, or assign the group in"
        log "         Tenable (Sensors > Agents) after this run."
        NO_GROUP=1
    fi
fi

# -----------------------------------------------------------------------
# 5. Unlink stale state, then link
# -----------------------------------------------------------------------
if ! echo "$STATUS" | grep -q "Linked to: *None"; then
    log "Existing link state present -- unlinking first..."
    "$CLI" agent unlink --force 2>&1 | while IFS= read -r line; do
        [ -n "$line" ] && log "  $line"
    done
fi

log "Linking to $LINK_HOST..."
if [ -n "$GROUPS_CSV" ]; then
    LINK_OUT=$("$CLI" agent link --key="$LINK_KEY" --host="$LINK_HOST" --port=443 --groups="$GROUPS_CSV" 2>&1 || true)
else
    LINK_OUT=$("$CLI" agent link --key="$LINK_KEY" --host="$LINK_HOST" --port=443 2>&1 || true)
fi
echo "$LINK_OUT" | while IFS= read -r line; do
    [ -n "$line" ] && log "  $line"
done

if echo "$LINK_OUT" | grep -qi "empty response"; then
    log "ERROR: empty response from controller."
    log "       Check Zscaler SSL inspection of $LINK_HOST. Note other Macs on this"
    log "       network do connect, so suspect this host before the network."
    exit 1
fi

# -----------------------------------------------------------------------
# 6. Verify
# -----------------------------------------------------------------------
log ""
sleep 6
FINAL=$("$CLI" agent status 2>&1 || true)
echo "$FINAL" | while IFS= read -r line; do
    [ -n "$line" ] && log "  $line"
done

if ! echo "$FINAL" | grep -q "Linked to: *$LINK_HOST"; then
    log ""
    log "ERROR: agent is still not linked to $LINK_HOST."
    exit 1
fi

log ""
if [ "$NO_GROUP" -eq 1 ]; then
    log "ATTENTION: linked, but with NO GROUP -- it will not scan or report until a"
    log "           group is assigned. Exiting 2 so this is not recorded as done."
    exit 2
fi
if echo "$FINAL" | grep -qi "Link status: *Connected"; then
    log "SUCCESS: agent linked, grouped and connected."
    exit 0
fi
log "Agent linked and grouped. Connection not yet confirmed (normal this soon)."
log "Re-run later and look for 'Link status: Connected' plus a smart scan config."
log "Exiting 2 until that is confirmed."
exit 2
