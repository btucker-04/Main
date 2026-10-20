#!/bin/bash
# =============================================================================
# remove-apple-pages.sh
# Removes Apple Pages (com.apple.iWork.Pages) from a Mac.
# Platform : macOS (bash 3.2 compatible) | Deploy: Mosyle (runs as root)
#
# Why removal and not update: the Tenable finding keys on the app bundle being
# present at an old version, so deleting the bundle clears it.
#
# SAFETY
#   * Only a bundle whose CFBundleIdentifier is exactly com.apple.iWork.Pages is
#     removed. Any other app that happens to be named Pages.app is left alone.
#   * Only the app BUNDLE is removed. User documents, iCloud Drive files, and the
#     per-user container (~/Library/Containers/com.apple.iWork.Pages) are NEVER
#     touched, so nobody loses a document and reinstalling restores their settings.
#   * If Pages is running the script stops (exit 2) rather than risk unsaved work.
#     Set FORCE_CLOSE="1" below to quit it first (graceful quit, then terminate).
#
# MOSYLE NOTE: Mosyle passes no environment variables, so edit the CONFIG block
# before pasting. Environment variables still override it for terminal use.
#
# WILL IT COME BACK? If Pages is assigned to this Mac as a managed app in Mosyle
# (Apps / VPP), or the user reinstalls it from the App Store, it returns. Remove
# the assignment in Mosyle too, or this fix will not last.
#
# Exit: 0 = removed, or not installed
#       2 = skipped because Pages is running (re-run later, or set FORCE_CLOSE)
#       1 = a copy could not be removed
# =============================================================================

set -uo pipefail
HOME="${HOME:-/var/root}"
export HOME

# ---- CONFIG: edit these before deploying -----------------------------------
CFG_FORCE_CLOSE="0"     # 1 = quit Pages if it is running (can lose unsaved work)
CFG_DRY_RUN="0"         # 1 = report what would be removed, change nothing
# -----------------------------------------------------------------------------
FORCE_CLOSE="${FORCE_CLOSE:-$CFG_FORCE_CLOSE}"
DRY_RUN="${DRY_RUN:-$CFG_DRY_RUN}"
PLISTBUDDY="${PLISTBUDDY:-/usr/libexec/PlistBuddy}"
# Where to look. Overridable for testing.
APP_ROOTS="${APP_ROOTS:-/Applications /Users/*/Applications}"

BUNDLE_ID="com.apple.iWork.Pages"
LOG_DIR="${LOG_DIR:-/var/log/composecure}"
LOG_FILE="$LOG_DIR/remove_apple_pages.log"
mkdir -p "$LOG_DIR"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }

plist_get() { "$PLISTBUDDY" -c "Print :$2" "$1/Contents/Info.plist" 2>/dev/null || true; }

# A MAIN application binary ends in <App>.app/Contents/MacOS/<binary>. Matching
# this (not any process under the bundle) avoids false positives from helpers.
pages_running_pids() {
    ps -axo pid=,comm= 2>/dev/null | grep -E '/Pages\.app/Contents/MacOS/Pages$' | awk '{print $1}'
}

log "===== remove-apple-pages.sh START ====="
log "Host: $(hostname -s)   FORCE_CLOSE=$FORCE_CLOSE   DRY_RUN=$DRY_RUN"

# -----------------------------------------------------------------------
# 1. Find every Pages.app and keep only genuine Apple Pages
# -----------------------------------------------------------------------
log ""
log "[1] Looking for Pages.app..."
FOUND=""
# shellcheck disable=SC2086
for root in $APP_ROOTS; do
    [ -d "$root" ] || continue
    while IFS= read -r app; do
        [ -d "$app" ] || continue
        bid=$(plist_get "$app" "CFBundleIdentifier")
        ver=$(plist_get "$app" "CFBundleShortVersionString")
        if [ "$bid" = "$BUNDLE_ID" ]; then
            log "  Apple Pages $ver at $app"
            FOUND="$FOUND
$app"
        else
            log "  SKIPPING $app (bundle id '${bid:-unreadable}' is not $BUNDLE_ID)"
        fi
    done < <(find "$root" -maxdepth 2 -type d -name 'Pages.app' 2>/dev/null)
done
FOUND=$(echo "$FOUND" | sed '/^$/d')

if [ -z "$FOUND" ]; then
    log "  Apple Pages is not installed. Nothing to do."
    log "===== END ====="
    exit 0
fi

# -----------------------------------------------------------------------
# 2. Running?
# -----------------------------------------------------------------------
log ""
log "[2] Is Pages running?"
PIDS=$(pages_running_pids)
if [ -n "$PIDS" ]; then
    log "  Pages is RUNNING (pid: $(echo $PIDS | tr '\n' ' '))."
    if [ "$FORCE_CLOSE" != "1" ]; then
        log "  Not removing it under a live Pages, which could lose unsaved work."
        log "  Re-run when the user has closed it, or set FORCE_CLOSE to 1."
        log "===== END (deferred) ====="
        exit 2
    fi
    if [ "$DRY_RUN" = "1" ]; then
        log "  [DRY_RUN] Would quit Pages."
    else
        CONSOLE_USER=$(stat -f "%Su" /dev/console 2>/dev/null || true)
        if [ -n "$CONSOLE_USER" ] && [ "$CONSOLE_USER" != "root" ] && [ "$CONSOLE_USER" != "loginwindow" ]; then
            CUID=$(id -u "$CONSOLE_USER" 2>/dev/null || true)
            log "  FORCE_CLOSE=1: asking Pages to quit as $CONSOLE_USER..."
            [ -n "$CUID" ] && launchctl asuser "$CUID" sudo -u "$CONSOLE_USER" \
                /usr/bin/osascript -e 'tell application "Pages" to quit' >/dev/null 2>&1 || true
            sleep 10
        fi
        PIDS=$(pages_running_pids)
        if [ -n "$PIDS" ]; then
            log "  Still running. Sending TERM, then KILL."
            for p in $PIDS; do kill "$p" 2>/dev/null || true; done
            sleep 5
            for p in $(pages_running_pids); do kill -9 "$p" 2>/dev/null || true; done
            sleep 2
        fi
        if [ -n "$(pages_running_pids)" ]; then
            log "  ERROR: Pages would not quit. Not removing."
            log "===== END (failed) ====="
            exit 1
        fi
    fi
else
    log "  Not running."
fi

# -----------------------------------------------------------------------
# 3. Remove the bundle(s)
# -----------------------------------------------------------------------
log ""
log "[3] Removing the app bundle(s). User documents and settings are not touched."
FAILED=0
while IFS= read -r app; do
    [ -z "$app" ] && continue
    if [ "$DRY_RUN" = "1" ]; then
        log "  [DRY_RUN] Would remove $app"
        continue
    fi
    log "  Removing $app"
    rm -rf "$app" 2>>"$LOG_FILE"
    if [ -e "$app" ]; then
        log "  Still present. Clearing immutable flags and retrying..."
        chflags -R nouchg,noschg "$app" 2>>"$LOG_FILE" || true
        rm -rf "$app" 2>>"$LOG_FILE"
    fi
    if [ -e "$app" ]; then
        log "  ERROR: could not remove $app"
        FAILED=1
    fi
done <<EOF2
$FOUND
EOF2

# -----------------------------------------------------------------------
# 4. Verify by looking again, not by trusting rm
# -----------------------------------------------------------------------
log ""
log "[4] Verification..."
LEFT=""
# shellcheck disable=SC2086
for root in $APP_ROOTS; do
    [ -d "$root" ] || continue
    while IFS= read -r app; do
        [ -d "$app" ] || continue
        [ "$(plist_get "$app" "CFBundleIdentifier")" = "$BUNDLE_ID" ] && LEFT="$LEFT
$app"
    done < <(find "$root" -maxdepth 2 -type d -name 'Pages.app' 2>/dev/null)
done
LEFT=$(echo "$LEFT" | sed '/^$/d')

if [ "$DRY_RUN" = "1" ]; then
    log "DRY_RUN=1: nothing was changed."
    log "===== END (dry run) ====="
    exit 0
fi
if [ -n "$LEFT" ] || [ "$FAILED" -eq 1 ]; then
    log "  Still present:"
    echo "$LEFT" | while IFS= read -r a; do [ -n "$a" ] && log "    $a"; done
    log "RESULT: Apple Pages was NOT fully removed."
    log "===== END (failed) ====="
    exit 1
fi
log "  No Apple Pages bundle remains."
log "RESULT: Apple Pages removed."
log "Check Mosyle for an app assignment, or the app will return. Rescan to confirm the finding clears."
log "===== remove-apple-pages.sh END ====="
exit 0
