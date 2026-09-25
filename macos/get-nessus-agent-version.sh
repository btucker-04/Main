#!/bin/bash
# =============================================================================
# get-nessus-agent-version.sh
# AGENT   : Tenable Nessus Agent (macOS)
# PURPOSE : READ-ONLY. Reports EVERY version the host can self-report, so a
#           Tenable finding that disagrees with the Linked Agents page can be
#           pinned on a specific source instead of guessed at. Changes nothing.
# Platform: macOS (bash 3.2 compatible) | Deploy: Mosyle (runs as root)
#
# Deploy as a FILE (Mosyle Custom Script / copy then `bash /path/to/this.sh`).
# Do NOT paste this file into a Mosyle Unix Command -- that field truncates
# and the "output" you get back is the source, not a run. Use
# macos/get-nessus-agent-version-oneshot.sh for a paste-safe command.
#
# Written for CSPRIM-08 (2026-09-25):
#   Finding : plugin 326953 "Tenable Nessus Agent older than 11.2.1 (TNS-2026-18)"
#             CVE-2026-15265, severity 4
#             Path              : /Library/NessusAgent
#             Installed version : 11.2.0
#             Fixed version     : 11.2.1
#   Console : Sensors > Agents shows CSPRIM-08 Online / Healthy, version
#             11.2.3, last scanned today.
#
# Both can be true at once, and they mean different things:
#
#   * Plugin 326953 is a LOCAL check -- its own description says it "relied
#     only on the application's self-reported version number." On macOS the
#     host self-reports in more than one place, and the agent UPDATES ITSELF
#     IN PLACE. A self-update rewrites the binaries under /Library/NessusAgent
#     but does NOT re-run the installer, so the macOS package receipt keeps
#     the version of the pkg that was originally installed. A receipt left on
#     11.2.0 keeps answering 11.2.0 forever, no matter how current the running
#     agent is. This is the same failure mode as an orphaned ARP DisplayVersion
#     on Windows (see windows/Update-DotNetRuntimes.ps1 v3.4).
#   * The Linked Agents page shows what the agent TOLD THE MANAGER at its last
#     check-in, which comes from the running binary. That is the version that
#     is actually executing.
#
#   So: if the binaries are >= the fixed version and a receipt (or a leftover
#   tree) still says otherwise, the host is patched and the finding is being
#   fed by stale metadata. If the binaries themselves are below the floor, the
#   agent genuinely did not update and the finding is real.
#
# This script does NOT decide that from a distance -- it prints every source
# with its value so the disagreeing one is named.
#
# WHAT IT READS (never writes):
#   1. nessuscli -v / nessusd -v          the running build (authoritative)
#   2. pkgutil receipts                   what the installer last recorded
#   3. Info.plist / version files in tree discovered, not hardcoded
#   4. launchd + process state            is the new binary actually running
#   5. nessuscli agent status             link state, last scan, plugin set
#   6. other nessusd/nessuscli on disk    leftover trees from old installs
#
# ENVIRONMENT (all optional; Mosyle passes none, so edit CONFIG below):
#   FIXED_VERSION=11.2.1   version floor to judge each source against
#   AGENT_ROOT=/Library/NessusAgent
#   DEEP_SCAN=1            also search /Applications /opt /usr/local for
#                          stray agent binaries (slower)
#
# EXIT CODES
#   0 PATCHED         every source >= FIXED_VERSION; a finding is stale data
#   1 VULNERABLE      the running binary is below FIXED_VERSION
#   2 STALE_METADATA  running binary is patched, but a source still reports old
#   3 NOT_INSTALLED   no Nessus Agent on this host
# =============================================================================

set -uo pipefail
HOME="${HOME:-/var/root}"
export HOME

# =============================================================================
CFG_FIXED_VERSION="11.2.1"
CFG_AGENT_ROOT="/Library/NessusAgent"
CFG_DEEP_SCAN="0"
# =============================================================================
FIXED_VERSION="${FIXED_VERSION:-$CFG_FIXED_VERSION}"
AGENT_ROOT="${AGENT_ROOT:-$CFG_AGENT_ROOT}"
DEEP_SCAN="${DEEP_SCAN:-$CFG_DEEP_SCAN}"

LOG_DIR="/var/log/composecure"
LOG_FILE="$LOG_DIR/nessus_agent_version.log"

log() {
    line="$1"
    echo "$line"
    if [ -d "$LOG_DIR" ] && { [ -w "$LOG_FILE" ] || [ -w "$LOG_DIR" ]; }; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] $line" >> "$LOG_FILE" 2>/dev/null || true
    fi
}

version_ge() {
    # 0 when $1 >= $2. Field-by-field numeric compare: `sort -V` is not
    # dependable across the BSD/GNU split and this has to run on stock macOS.
    awk -v a="$1" -v b="$2" 'BEGIN {
        na = split(a, A, "."); nb = split(b, B, ".")
        n = (na > nb) ? na : nb
        for (i = 1; i <= n; i++) {
            x = (i <= na) ? A[i] + 0 : 0
            y = (i <= nb) ? B[i] + 0 : 0
            if (x > y) exit 0
            if (x < y) exit 1
        }
        exit 0
    }'
}

parse_version() {
    # First dotted numeric run in a line, e.g.
    #   "nessuscli (Nessus) 11.2.3 for Darwin"  -> 11.2.3
    #   "version: 11.2.0"                       -> 11.2.0
    printf '%s\n' "$1" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)*' | head -n1
}

pkgutil_version_from_text() {
    # `pkgutil --pkg-info PACKAGE_ID` prints a "version: x.y.z" line among others.
    printf '%s\n' "$1" | awk -F': *' '/^version:/ { print $2; exit }'
}

verdict_for() {
    # $1 running version, $2 floor, $3 comma-separated stale sources
    running="$1"
    floor="$2"
    stale="$3"
    if [ -z "$running" ]; then echo "NOT_INSTALLED"; return 0; fi
    if ! version_ge "$running" "$floor"; then echo "VULNERABLE"; return 0; fi
    if [ -n "$stale" ]; then echo "STALE_METADATA"; return 0; fi
    echo "PATCHED"
}

# Unit tests source this file for the helpers above; stop before the run.
if [ "${NESSUS_VER_SELFTEST:-0}" = "1" ]; then
    return 0 2>/dev/null || exit 0
fi

mkdir -p "$LOG_DIR" 2>/dev/null || true

STALE_SOURCES=""
note_stale() {
    if [ -z "$STALE_SOURCES" ]; then
        STALE_SOURCES="$1=$2"
    else
        STALE_SOURCES="$STALE_SOURCES,$1=$2"
    fi
}

JUDGE_NOTE=""
judge() {
    # $1 label, $2 version. Sets JUDGE_NOTE and records the source when it is
    # below the floor. Deliberately NOT called as $(judge ...): a command
    # substitution runs in a subshell, so the note_stale record would be
    # discarded and every run would end up reporting PATCHED.
    if [ -z "$2" ]; then
        JUDGE_NOTE="no version"
        return 0
    fi
    if version_ge "$2" "$FIXED_VERSION"; then
        JUDGE_NOTE="OK (>= $FIXED_VERSION)"
    else
        note_stale "$1" "$2"
        JUDGE_NOTE="BELOW $FIXED_VERSION  -- a check reading this source reports vulnerable"
    fi
}

log "=============================================="
log " Nessus Agent version report (read-only)"
log " Host         : $(hostname -s 2>/dev/null || hostname)"
log " Date         : $(date '+%Y-%m-%d %H:%M:%S')"
log " Version floor: $FIXED_VERSION   (plugin 326953 / TNS-2026-18)"
log " Agent root   : $AGENT_ROOT"
log "=============================================="

CLI="$AGENT_ROOT/run/sbin/nessuscli"
DAEMON="$AGENT_ROOT/run/sbin/nessusd"

# -----------------------------------------------------------------------
log ""
log "[1] Running build (authoritative -- this is the code that executes)"
RUNNING=""
if [ -x "$CLI" ]; then
    CLI_RAW=$("$CLI" -v 2>&1 | head -n 3 || true)
    echo "$CLI_RAW" | while IFS= read -r l; do [ -n "$l" ] && log "    $l"; done
    RUNNING=$(parse_version "$(echo "$CLI_RAW" | head -n1)")
    judge nessuscli "$RUNNING"
    log "  nessuscli version : ${RUNNING:-unreadable}   $JUDGE_NOTE"
else
    log "  $CLI not present."
fi
if [ -x "$DAEMON" ]; then
    D_RAW=$("$DAEMON" -v 2>&1 | head -n 2 || true)
    DVER=$(parse_version "$(echo "$D_RAW" | head -n1)")
    judge nessusd "$DVER"
    log "  nessusd version   : ${DVER:-unreadable}   $JUDGE_NOTE"
    [ -z "$RUNNING" ] && RUNNING="$DVER"
else
    log "  $DAEMON not present."
fi

if [ -z "$RUNNING" ]; then
    log ""
    log "No Nessus Agent binaries found under $AGENT_ROOT."
    log "VERDICT: NOT_INSTALLED"
    log "NESSUS_AGENT_VERSION|host=$(hostname -s 2>/dev/null)|running=|floor=$FIXED_VERSION|verdict=NOT_INSTALLED|stale_sources="
    exit 3
fi

# -----------------------------------------------------------------------
log ""
log "[2] macOS package receipts (prime suspect for a stale self-reported version)"
log "    The agent self-updates in place; a self-update does NOT refresh the"
log "    receipt, so this can sit on the originally-installed version forever."
RECEIPTS=$(pkgutil --pkgs 2>/dev/null | grep -i nessus || true)
if [ -z "$RECEIPTS" ]; then
    log "  No nessus package receipts registered."
else
    for pkgid in $RECEIPTS; do
        INFO=$(pkgutil --pkg-info "$pkgid" 2>/dev/null || true)
        PVER=$(pkgutil_version_from_text "$INFO")
        PTIME=$(printf '%s\n' "$INFO" | awk -F': *' '/^install-time:/ { print $2; exit }')
        PWHEN=""
        if [ -n "$PTIME" ]; then
            PWHEN=$(date -r "$PTIME" '+%Y-%m-%d' 2>/dev/null || true)
        fi
        judge "receipt:$pkgid" "$PVER"
        log "  $pkgid"
        log "    version      : ${PVER:-unknown}   $JUDGE_NOTE"
        log "    installed    : ${PWHEN:-unknown}"
    done
fi

# -----------------------------------------------------------------------
log ""
log "[3] Version-bearing files inside the tree (discovered, not hardcoded)"
FOUND_PLIST=0
while IFS= read -r plist; do
    [ -f "$plist" ] || continue
    PV=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$plist" 2>/dev/null || true)
    [ -n "$PV" ] || PV=$(/usr/libexec/PlistBuddy -c "Print :CFBundleVersion" "$plist" 2>/dev/null || true)
    [ -n "$PV" ] || continue
    FOUND_PLIST=1
    judge "plist:$(basename "$(dirname "$plist")")" "$(parse_version "$PV")"
    log "  $plist"
    log "    CFBundle version : $PV   $JUDGE_NOTE"
done < <(find "$AGENT_ROOT" -maxdepth 6 -name 'Info.plist' -type f 2>/dev/null | head -20)
if [ "$FOUND_PLIST" -eq 0 ]; then
    log "  No Info.plist with a version string under $AGENT_ROOT."
fi

# -----------------------------------------------------------------------
log ""
log "[4] Daemon + process state"
log "    A self-update rewrites the binary, but the OLD code keeps running"
log "    until the daemon restarts. Compare the start time with the file date."
DAEMON_LABEL=$(launchctl list 2>/dev/null | awk '{print $3}' | grep -i nessus | head -1 || true)
log "  LaunchDaemon loaded : ${DAEMON_LABEL:-none}"
if pgrep -x nessusd >/dev/null 2>&1; then
    for p in $(pgrep -x nessusd 2>/dev/null); do
        PS_LINE=$(ps -o pid=,lstart=,comm= -p "$p" 2>/dev/null | sed 's/^ *//' || true)
        [ -n "$PS_LINE" ] && log "  running : $PS_LINE"
    done
else
    log "  nessusd is NOT running."
fi
if [ -x "$DAEMON" ]; then
    # BSD stat. GNU stat reads -f as "file system", so it is not a fallback.
    if [ "$(uname)" = "Darwin" ]; then
        log "  binary mtime : $(stat -f '%Sm' -t '%Y-%m-%d %H:%M' "$DAEMON" 2>/dev/null || echo unknown)"
    else
        log "  binary mtime : $(stat -c '%y' "$DAEMON" 2>/dev/null | cut -c1-16 || echo unknown)"
    fi
fi

# -----------------------------------------------------------------------
log ""
log "[5] Link + last-report state (when did Tenable last hear from this agent)"
if [ -x "$CLI" ]; then
    "$CLI" agent status 2>&1 | while IFS= read -r l; do
        [ -n "$l" ] && log "    $l"
    done
else
    log "  nessuscli unavailable."
fi

# -----------------------------------------------------------------------
log ""
log "[6] Other agent binaries on disk (leftover trees report old versions too)"
SEARCH_DIRS="/Library"
if [ "$DEEP_SCAN" = "1" ]; then
    SEARCH_DIRS="/Library /Applications /opt /usr/local"
    log "  DEEP_SCAN=1 -- searching: $SEARCH_DIRS"
fi
OTHER_FOUND=0
while IFS= read -r bin; do
    [ -x "$bin" ] || continue
    case "$bin" in "$CLI"|"$DAEMON") continue ;; esac
    OTHER_FOUND=1
    OV=$(parse_version "$("$bin" -v 2>&1 | head -n1)")
    judge "other:$bin" "$OV"
    log "  $bin"
    log "    version : ${OV:-unreadable}   $JUDGE_NOTE"
done < <(find $SEARCH_DIRS -maxdepth 6 -type f \( -name nessuscli -o -name nessusd \) 2>/dev/null | head -20)
if [ "$OTHER_FOUND" -eq 0 ]; then
    log "  None besides $AGENT_ROOT."
fi

# -----------------------------------------------------------------------
VERDICT=$(verdict_for "$RUNNING" "$FIXED_VERSION" "$STALE_SOURCES")
log ""
log "=============================================="
log " Running build : $RUNNING"
log " Floor         : $FIXED_VERSION"
log " VERDICT       : $VERDICT"
case "$VERDICT" in
    PATCHED)
        log ""
        log " Every source on this host is at or above $FIXED_VERSION."
        log " Nothing to remediate here. A finding that still reports an older"
        log " version is being served from data Tenable already holds, not from"
        log " this host's current state. Check the finding's Last Seen date: it"
        log " stays ACTIVE until a scan re-evaluates it. Also check whether the"
        log " asset carries results from a second source -- this host is tagged"
        log " 'Scanned Twice' and 'Nessus Network Monitor', and a network-scan or"
        log " NNM finding does not clear on an agent scan."
        ;;
    STALE_METADATA)
        log ""
        log " The RUNNING agent is patched ($RUNNING), but these sources still"
        log " report a version below $FIXED_VERSION:"
        log "   $STALE_SOURCES"
        log " A local check that reads one of those reports this host vulnerable"
        log " no matter how current the binaries are. For a package receipt, the"
        log " fix is to reinstall the current agent .pkg so the receipt is"
        log " rewritten (macos/repair-nessus-agent.sh does not do this -- it"
        log " repairs link state, not the installed package). For a leftover"
        log " tree, remove it once nothing points at it."
        ;;
    VULNERABLE)
        log ""
        log " The running agent is genuinely below $FIXED_VERSION. It did not"
        log " self-update. Install the current agent .pkg on this host."
        ;;
esac
log "=============================================="
log "NESSUS_AGENT_VERSION|host=$(hostname -s 2>/dev/null)|running=$RUNNING|floor=$FIXED_VERSION|verdict=$VERDICT|stale_sources=$STALE_SOURCES"

case "$VERDICT" in
    PATCHED)        exit 0 ;;
    VULNERABLE)     exit 1 ;;
    STALE_METADATA) exit 2 ;;
    *)              exit 3 ;;
esac
