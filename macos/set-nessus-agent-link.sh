#!/bin/bash
# =============================================================================
# NessusRelink_macOS.sh
# Relink Nessus Agent with per-host group preservation (macOS / Mosyle).
# Group resolution by PREFIX RULE (cleaned agents export 2026-08-04).
#
# 'nessuscli agent link --groups' REPLACES group membership, so this script
# relinks each Mac with exactly its exported group set (several Macs belong
# to Apple Computers / Laptops / Ad Hoc groups beyond just 'MacBook').
# Hosts not in the map are skipped (exit 2) unless FALLBACK_GROUPS is set.
# bash 3.2 compatible. Runs as root via Mosyle.
# =============================================================================

set -uo pipefail
HOME="${HOME:-/var/root}"
export HOME

LINK_KEY="4f858e2b28a33a5927c7805eab8b8533ecb35c983417b392c5b570b5a6a96fba"
LINK_HOST="sensor.cloud.tenable.com"
FALLBACK_GROUPS=""

CLI="/Library/NessusAgent/run/sbin/nessuscli"
LOG_DIR="/var/log/composecure"
LOG_FILE="$LOG_DIR/nessus_relink.log"
mkdir -p "$LOG_DIR"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }

RAW_HOST=$(hostname -s 2>/dev/null || hostname)
HOST_KEY=$(echo "$RAW_HOST" | tr '[:lower:]' '[:upper:]' | sed 's/\.LOCAL$//')

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

log "=== Nessus Agent Relink (group-preserving) ==="
log "Host: $HOST_KEY"

if [ ! -x "$CLI" ]; then
    log "ERROR: nessuscli not found at $CLI -- agent not installed."
    exit 1
fi

GROUPS_CSV=$(groups_for_host "$HOST_KEY")
if [ -z "$GROUPS_CSV" ]; then
    if [ -n "$FALLBACK_GROUPS" ]; then
        GROUPS_CSV="$FALLBACK_GROUPS"
        log "WARN: host not in map -- using fallback groups: $GROUPS_CSV"
    else
        log "WARN: host not in group map and no fallback set. Skipping relink"
        log "      to avoid wiping unknown group membership. Exit 2."
        exit 2
    fi
else
    log "Mapped groups: $GROUPS_CSV"
fi

STATUS=$("$CLI" agent status 2>&1 || true)
log "$STATUS"

if ! echo "$STATUS" | grep -q "Linked to: None"; then
    log "Unlinking existing state..."
    "$CLI" agent unlink --force 2>&1 | tee -a "$LOG_FILE"
fi

log "Linking to $LINK_HOST with groups [$GROUPS_CSV]..."
LINK_OUT=$("$CLI" agent link --key="$LINK_KEY" --host="$LINK_HOST" --port=443 --groups="$GROUPS_CSV" 2>&1)
log "$LINK_OUT"

if echo "$LINK_OUT" | grep -qi "empty response"; then
    log "ERROR: empty response from controller -- Zscaler SSL inspection of $LINK_HOST?"
    exit 1
fi

sleep 5
FINAL=$("$CLI" agent status 2>&1 || true)
log "$FINAL"
if echo "$FINAL" | grep -q "Linked to:" && ! echo "$FINAL" | grep -q "Linked to: None"; then
    log "SUCCESS: relinked."
    exit 0
fi
log "ERROR: still not linked after relink attempt."
exit 1
