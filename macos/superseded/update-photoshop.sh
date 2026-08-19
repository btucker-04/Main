#!/bin/bash
# =============================================================================
# update-photoshop-306395.sh  (v2)
# Remediates : Adobe Photoshop 27.x < 27.5 (macOS APSB26-40 / CVE-2026-27289)
# Nessus Plugin ID : 306395
# Method     : Adobe Remote Update Manager (RUM), which is already deployed
# Platform   : macOS (bash 3.2 compatible) | Deploy: Mosyle (runs as root)
# Hosts      : csmb-061, csprmb-12-a  (both at 27.1.0, target 27.5)
#
# Why the verification matters: RUM is documented to exit 0 while leaving apps
# on their old version -- if the app was packaged with updates disabled, if an
# AUSST server has not synced, or if the update simply is not on the update
# server. Exit 0 from RUM is NOT evidence of an update, so this script compares
# the app's Info.plist version before and after and only reports success when
# the version actually moved.
#
# Behaviour:
#   * Finds every /Applications/Adobe Photoshop*/Adobe Photoshop*.app so it does
#     not care which year-labelled folder is installed.
#   * ABORTS (exit 2) if Photoshop is running -- an in-place update under a live
#     Photoshop risks the user's unsaved work. Set FORCE_CLOSE=1 to override.
#   * Runs 'RUM --action=list' first and logs it, so if RUM sees no update the
#     log says so plainly instead of looking like a silent failure.
#   * caffeinate holds the Mac awake; these updates can run for many minutes.
#   * RUM requires admin privileges (it returns code 1 otherwise). Mosyle runs
#     this as root, which satisfies that.
#
# v2 (from the 2026-08-07 CSPRMB-12-A run):
#   * RUM returned Code (1) INSTANTLY on both --action=list and --action=install
#     while running as root. Adobe state that RC 1 is a GENERIC error, and there
#     is a documented, long-standing RUM defect where the --productVersions
#     filter itself causes an immediate RC 1 while the same command without the
#     filter works. So v2 now: tries the targeted call, and on any non-zero
#     result RETRIES WITHOUT --productVersions.
#   * The RUM log is tailed into our log on failure, because RC 1 is generic and
#     the reason only exists in Adobe's own log.
#   * NOTE on the fallback: without --productVersions, RUM updates EVERY Adobe
#     product it can on the machine, not just Photoshop. On a designer's Mac
#     that can be a large download and will patch Illustrator/InDesign/etc too.
#     That is usually desirable, but it is a real behaviour change -- set
#     NO_FALLBACK=1 to keep the run Photoshop-only and simply fail instead.
#
# Exit: 0 = at/above 27.5 (updated or already current)
#       2 = skipped, Photoshop was running
#       1 = RUM failed, or ran but the version did not reach the target
# =============================================================================

set -uo pipefail
HOME="${HOME:-/var/root}"
export HOME

TARGET_VERSION="27.5"
SAP_CODE="PHSP"
RUM="/usr/local/bin/RemoteUpdateManager"
FORCE_CLOSE="${FORCE_CLOSE:-0}"
NO_FALLBACK="${NO_FALLBACK:-0}"

LOG_DIR="/var/log/composecure"
LOG_FILE="$LOG_DIR/photoshop_update.log"
mkdir -p "$LOG_DIR"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }

version_ge() { [ "$(printf '%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

dump_rum_log() {
    # RC 1 is generic; the reason lives only in Adobe's own log.
    log "  --- tail of Adobe RemoteUpdateManager log(s) ---"
    FOUND_LOG=0
    for cand in /var/root/Library/Logs/RemoteUpdateManager.log \
                /Library/Logs/Adobe/RemoteUpdateManager.log \
                "$HOME/Library/Logs/RemoteUpdateManager.log"; do
        [ -f "$cand" ] || continue
        FOUND_LOG=1
        log "  == $cand =="
        tail -40 "$cand" 2>/dev/null | while IFS= read -r l; do
            [ -n "$l" ] && log "    $l"
        done
    done
    for udir in /Users/*; do
        cand="$udir/Library/Logs/RemoteUpdateManager.log"
        [ -f "$cand" ] || continue
        FOUND_LOG=1
        log "  == $cand =="
        tail -20 "$cand" 2>/dev/null | while IFS= read -r l; do
            [ -n "$l" ] && log "    $l"
        done
    done
    [ "$FOUND_LOG" -eq 0 ] && log "  (no RemoteUpdateManager.log found)"
}

run_rum() {
    # $1 = description, remaining args = RUM arguments
    desc="$1"; shift
    log "  RUM $desc: $RUM $*"
    RUM_OUT=$("$RUM" "$@" 2>&1)
    RUM_RC=$?
    echo "$RUM_OUT" | while IFS= read -r l; do
        [ -n "$l" ] && log "    $l"
    done
    log "    return code: $RUM_RC"
    return $RUM_RC
}

CAFFEINATE_PID=""
cleanup() { [ -n "$CAFFEINATE_PID" ] && kill "$CAFFEINATE_PID" 2>/dev/null; }
trap cleanup EXIT

log "===== update-photoshop-306395.sh START ====="
log "Host: $(hostname)   Target: Photoshop >= $TARGET_VERSION"

# -----------------------------------------------------------------------
# 1. Locate Photoshop and read the installed version(s)
# -----------------------------------------------------------------------
log ""
log "[1] Locating Adobe Photoshop..."
FOUND_ANY=0
NEEDS_UPDATE=0
while IFS= read -r app; do
    [ -d "$app" ] || continue
    FOUND_ANY=1
    ver=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$app/Contents/Info.plist" 2>/dev/null || true)
    if [ -z "$ver" ]; then
        log "  $app  -> version unreadable"
        continue
    fi
    if version_ge "$ver" "$TARGET_VERSION"; then
        log "  $app  -> $ver  [OK >= $TARGET_VERSION]"
    else
        log "  $app  -> $ver  [NEEDS UPDATE < $TARGET_VERSION]"
        NEEDS_UPDATE=1
    fi
done < <(find /Applications -maxdepth 2 -type d -name 'Adobe Photoshop*.app' 2>/dev/null | sort)

if [ "$FOUND_ANY" -eq 0 ]; then
    log "  Photoshop not installed. Nothing to do."
    log "===== END ====="
    exit 0
fi
if [ "$NEEDS_UPDATE" -eq 0 ]; then
    log "  All installed Photoshop versions already meet $TARGET_VERSION."
    log "===== END ====="
    exit 0
fi

# -----------------------------------------------------------------------
# 2. RUM present and runnable?
# -----------------------------------------------------------------------
log ""
log "[2] Checking Remote Update Manager..."
if [ ! -x "$RUM" ]; then
    log "  ERROR: RUM not found or not executable at $RUM"
    log "  RUM ships with Adobe enterprise packages when 'enable RUM' is selected."
    log "===== END (cannot proceed) ====="
    exit 1
fi
log "  Found: $RUM"
if [ "$(id -u)" -ne 0 ]; then
    log "  WARNING: not running as root. RUM requires admin privileges and will"
    log "           exit with return code 1 without them."
fi

# -----------------------------------------------------------------------
# 3. Refuse to update a running Photoshop
# -----------------------------------------------------------------------
log ""
log "[3] Checking whether Photoshop is running..."
PS_PIDS=$(pgrep -f "/Adobe Photoshop [0-9]*\.app/Contents/MacOS/" 2>/dev/null || true)
if [ -n "$PS_PIDS" ]; then
    log "  Photoshop is RUNNING (pids: $PS_PIDS)."
    if [ "$FORCE_CLOSE" != "1" ]; then
        log "  Updating in place under a live Photoshop risks the user's unsaved work."
        log "  Skipping. Re-run when it is closed, or set FORCE_CLOSE=1 to override."
        log "===== END (deferred) ====="
        exit 2
    fi
    log "  FORCE_CLOSE=1 set: terminating Photoshop."
    for pid in $PS_PIDS; do kill "$pid" 2>/dev/null || true; done
    sleep 5
    STILL=$(pgrep -f "/Adobe Photoshop [0-9]*\.app/Contents/MacOS/" 2>/dev/null || true)
    if [ -n "$STILL" ]; then
        for pid in $STILL; do kill -9 "$pid" 2>/dev/null || true; done
        sleep 3
    fi
else
    log "  Not running."
fi

# -----------------------------------------------------------------------
# 4. What does RUM think is available?
# -----------------------------------------------------------------------
log ""
log "[4] What does RUM see? (advisory only -- see note below)"
if run_rum "list (Photoshop only)" --productVersions="$SAP_CODE" --action=list; then
    LIST_RC=0
else
    LIST_RC=$?
fi
if [ "$LIST_RC" -ne 0 ]; then
    log "  RUM returned $LIST_RC for the targeted list. Adobe document RC 1 as a"
    log "  GENERIC error, and the --productVersions filter is itself a known cause"
    log "  of an immediate RC 1 on some RUM builds. Retrying the list unfiltered..."
    run_rum "list (all products)" --action=list || true
    log "  (List output is advisory only. The authority is the version check in [6].)"
fi

# -----------------------------------------------------------------------
# 5. Install (kept awake; this can take a long time)
# -----------------------------------------------------------------------
log ""
log "[5] Installing (kept awake; this can take a long time)..."
{ caffeinate -dimu & } 2>/dev/null
CAFFEINATE_PID=$!
disown "$CAFFEINATE_PID" 2>/dev/null || true

INSTALL_OK=0
if run_rum "install (Photoshop only)" --productVersions="$SAP_CODE" --action=install; then
    INSTALL_OK=1
else
    TARGETED_RC=$?
    log "  Targeted install returned $TARGETED_RC."
    dump_rum_log
    if [ "$NO_FALLBACK" = "1" ]; then
        log "  NO_FALLBACK=1 -- not retrying without --productVersions."
    else
        log "  Retrying WITHOUT --productVersions. This is the documented workaround"
        log "  for an immediate RC 1 on a targeted call. NOTE: this updates EVERY"
        log "  Adobe product on this machine, not just Photoshop."
        if run_rum "install (all products)" --action=install; then
            INSTALL_OK=1
        else
            FALLBACK_RC=$?
            log "  Unfiltered install also returned $FALLBACK_RC."
            dump_rum_log
        fi
    fi
fi
kill "$CAFFEINATE_PID" 2>/dev/null; CAFFEINATE_PID=""

# -----------------------------------------------------------------------
# 6. Verify by version, not by exit code
# -----------------------------------------------------------------------
log ""
log "[6] Verification (RUM exit 0 is not proof of an update)..."
REMAIN=0
while IFS= read -r app; do
    [ -d "$app" ] || continue
    ver=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$app/Contents/Info.plist" 2>/dev/null || true)
    if [ -n "$ver" ] && version_ge "$ver" "$TARGET_VERSION"; then
        log "  $app  -> $ver  [OK]"
    else
        log "  $app  -> ${ver:-unreadable}  [STILL BELOW $TARGET_VERSION]"
        REMAIN=1
    fi
done < <(find /Applications -maxdepth 2 -type d -name 'Adobe Photoshop*.app' 2>/dev/null | sort)

log ""
if [ "$REMAIN" -eq 1 ]; then
    log "RESULT: Photoshop is still below $TARGET_VERSION."
    if [ "$INSTALL_OK" -eq 0 ]; then
        log "        Both the targeted and unfiltered RUM calls failed. The Adobe log"
        log "        tail above is the authoritative reason -- RC 1 is generic."
    else
        log "        RUM reported success but the version did not move, which points at"
        log "        the deployment package rather than at RUM."
    fi
    log "        Ranked causes: updates DISABLED in the Admin Console package (most"
    log "        common, and no script can work around it -- the package must be"
    log "        rebuilt with updates enabled); AUSST not synced; update server"
    log "        unreachable; or the build not published for this base version."
    log "===== END (not remediated) ====="
    exit 1
fi
log "RESULT: Photoshop is at or above $TARGET_VERSION."
log "Re-run a Nessus scan to confirm plugin 306395 clears."
log "===== update-photoshop-306395.sh END ====="
exit 0
