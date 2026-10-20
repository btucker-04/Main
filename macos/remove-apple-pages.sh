#!/bin/bash
# =============================================================================
# remove-apple-pages.sh  (v2)
# Removes Apple Pages (com.apple.iWork.Pages) from a Mac, e.g. Tenable plugin
# 298993 "Apple Pages < 15.1 Out-of-Bounds Read (HT126255)", CVE-2025-46316.
# Platform : macOS (bash 3.2 compatible) | Deploy: Mosyle (runs as root)
#
# Why removal and not update: the finding keys on an app bundle being present
# at an old version, so deleting every old bundle clears it. If the user needs
# Pages and the Mac's macOS can run the fixed release, update it instead
# (Mosyle VPP app update or the App Store).
#
# FINDING EVERY COPY: Tenable reports a copy wherever Spotlight sees one, not
# only in /Applications. This script asks Spotlight (mdfind, by bundle id, so
# renamed copies like "Pages 2.app" count) and also walks /Applications and
# /Users (Downloads, Desktop, Trash, nested folders) in case Spotlight is off.
#
# SAFETY
#   * Only a bundle whose CFBundleIdentifier is exactly com.apple.iWork.Pages is
#     removed. Any other app that happens to be named Pages.app is left alone.
#   * Only the app BUNDLE is removed. User documents, iCloud Drive files, and the
#     per-user container (~/Library/Containers/com.apple.iWork.Pages) are NEVER
#     touched, so nobody loses a document and reinstalling restores their settings.
#   * Copies on other volumes (/Volumes: external disks, mounted disk images,
#     backups) are reported, never deleted.
#   * If Pages is running the script stops (exit 2) rather than risk unsaved work.
#     Set FORCE_CLOSE="1" below to quit it first (graceful quit, then terminate).
#
# PERMISSIONS: on macOS 13+ deleting another developer's app needs the Mosyle
# agent to hold App Management, and searching Desktop / Documents / Downloads /
# Trash needs Full Disk Access. Without them macOS answers "Operation not
# permitted"; the script names the missing permission (exit 2). Grant both with
# a Mosyle Privacy Preferences (PPPC) profile for the Mosyle agent.
#
# MOSYLE NOTE: Mosyle passes no environment variables, so edit the CONFIG block
# before pasting. Environment variables still override it for terminal use.
#
# WILL IT COME BACK? If Pages is assigned to this Mac as a managed app in Mosyle
# (Apps / VPP), or the user reinstalls it from the App Store, it returns. Remove
# the assignment in Mosyle too, or this fix will not last.
#
# Exit: 0 = no Apple Pages copy is left that this run should remove
#       2 = a human must look: Pages running, a copy could not be removed or
#           searched for, a copy on another volume, or a dry run that would
#           change something (all listed under "Problems")
#       1 = could not run (PlistBuddy missing)
# =============================================================================

set -uo pipefail
HOME="${HOME:-/var/root}"
export HOME

# ---- CONFIG: edit these before deploying -----------------------------------
CFG_FORCE_CLOSE="0"     # 1 = quit Pages if it is running (can lose unsaved work)
CFG_DRY_RUN="0"         # 1 = report what would be removed, change nothing
CFG_KEEP_FROM_VERSION="" # e.g. "15.1" = keep copies at or above this version;
                        # empty = remove every Apple Pages copy
# -----------------------------------------------------------------------------
FORCE_CLOSE="${FORCE_CLOSE:-$CFG_FORCE_CLOSE}"
DRY_RUN="${DRY_RUN:-$CFG_DRY_RUN}"
KEEP_FROM_VERSION="${KEEP_FROM_VERSION:-$CFG_KEEP_FROM_VERSION}"
PLISTBUDDY="${PLISTBUDDY:-/usr/libexec/PlistBuddy}"
# Where to walk for copies Spotlight may not know about. Overridable for testing.
SEARCH_ROOTS="${SEARCH_ROOTS:-/Applications /Users}"
SEARCH_DEPTH="${SEARCH_DEPTH:-5}"
VOLUMES_PREFIX="${VOLUMES_PREFIX:-/Volumes/}"
QUIT_WAIT="${QUIT_WAIT:-10}"

BUNDLE_ID="com.apple.iWork.Pages"
LOG_DIR="${LOG_DIR:-/var/log/composecure}"
LOG_FILE="$LOG_DIR/remove_apple_pages.log"

# ---- pure helpers (unit-tested via PAGES_REMOVE_SELFTEST) -------------------

# 0 when version $1 is lower than $2 (numeric per dot-field; "14.4" < "15.1",
# "15.10" > "15.9"). An empty or unreadable $1 counts as lower.
version_lt() {
    awk -v a="$1" -v b="$2" 'BEGIN {
        if (a !~ /^[0-9]+(\.[0-9]+)*$/) exit 0
        na = split(a, x, "."); nb = split(b, y, ".")
        n = (na > nb) ? na : nb
        for (i = 1; i <= n; i++) {
            p = (i <= na) ? x[i] + 0 : 0; q = (i <= nb) ? y[i] + 0 : 0
            if (p < q) exit 0
            if (p > q) exit 1
        }
        exit 1
    }'
}

# 0 when the path is on another volume (external disk, disk image, backup).
on_other_volume() {
    case "$1" in "$VOLUMES_PREFIX"*) return 0 ;; esac
    return 1
}

# find/rm stderr on stdin -> 0 when macOS privacy controls (TCC) refused it.
tcc_denied() { grep -q 'Operation not permitted'; }

# `ps -axo pid=,comm=` on stdin -> PIDs of a Pages main binary. Matching the
# main binary (not any process under the bundle) avoids helper false positives;
# the bundle may be renamed ("Pages 2.app").
pages_pids_from_ps() {
    grep -E '/[^/]*\.app/Contents/MacOS/Pages$' | awk '{print $1}'
}

if [ "${PAGES_REMOVE_SELFTEST:-0}" = "1" ]; then
    return 0 2>/dev/null || exit 0
fi

# -----------------------------------------------------------------------------
mkdir -p "$LOG_DIR"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }
ISSUES=""
add_issue() { ISSUES="${ISSUES}${ISSUES:+
}$1"; log "  PROBLEM: $1"; }
WORK=$(mktemp -d "${TMPDIR:-/tmp}/remove-pages.XXXXXX") || exit 1
trap 'rm -rf "$WORK"' EXIT

plist_get() { "$PLISTBUDDY" -c "Print :$2" "$1/Contents/Info.plist" 2>/dev/null || true; }
pages_running_pids() { ps -axo pid=,comm= 2>/dev/null | pages_pids_from_ps; }

# Every directory that might be Apple Pages, one per line, deduplicated.
# Folders macOS refused to list are appended to $WORK/denied.
candidates() {
    if command -v mdfind >/dev/null 2>&1; then
        mdfind "kMDItemCFBundleIdentifier == '$BUNDLE_ID'" 2>/dev/null
    fi
    # shellcheck disable=SC2086
    for root in $SEARCH_ROOTS; do
        [ -d "$root" ] || continue
        find "$root" -maxdepth "$SEARCH_DEPTH" \( -name Library -o -name 'Pages*.app' \) -prune \
            -name 'Pages*.app' -type d -print 2>>"$WORK/find.err"
    done
    if [ -s "$WORK/find.err" ]; then
        grep 'Operation not permitted' "$WORK/find.err" \
            | sed -e 's/^find: //' -e 's/: Operation not permitted.*$//' >> "$WORK/denied"
        : > "$WORK/find.err"
    fi
}

# Apple Pages bundles that exist right now, one per line.
apple_pages_copies() {
    candidates | sed 's:/*$::' | sort -u | while IFS= read -r app; do
        [ -n "$app" ] && [ -d "$app" ] || continue
        bid=$(plist_get "$app" CFBundleIdentifier)
        if [ "$bid" = "$BUNDLE_ID" ]; then
            echo "$app"
        else
            echo "$app	${bid:-unreadable}" >> "$WORK/foreign"
        fi
    done
}

log "===== remove-apple-pages.sh v2 START ====="
log "Host: $(hostname -s)   FORCE_CLOSE=$FORCE_CLOSE   DRY_RUN=$DRY_RUN   KEEP_FROM_VERSION=${KEEP_FROM_VERSION:-none}"

if [ ! -x "$PLISTBUDDY" ]; then
    log "ERROR: $PLISTBUDDY not found; cannot identify Apple Pages safely."
    log "===== END (could not run) ====="
    exit 1
fi

# -----------------------------------------------------------------------
# 1. Inventory
# -----------------------------------------------------------------------
log ""
log "[1] Looking for Apple Pages (Spotlight by bundle id, plus a folder walk)..."
: > "$WORK/denied"; : > "$WORK/foreign"
TARGETS=""
SKIP_REMOVE=0
while IFS= read -r app; do
    [ -n "$app" ] || continue
    ver=$(plist_get "$app" CFBundleShortVersionString)
    if on_other_volume "$app"; then
        log "  Apple Pages ${ver:-?} at $app (other volume: report only)"
        add_issue "$app (Pages ${ver:-?}) is on another volume; remove it by hand or eject that disk/image before the rescan"
    elif [ -n "$KEEP_FROM_VERSION" ] && ! version_lt "$ver" "$KEEP_FROM_VERSION"; then
        log "  Apple Pages $ver at $app (at or above $KEEP_FROM_VERSION: keeping)"
    else
        log "  Apple Pages ${ver:-?} at $app (will remove)"
        TARGETS="${TARGETS}${TARGETS:+
}$app"
    fi
done < <(apple_pages_copies)
while IFS='	' read -r app bid; do
    [ -n "$app" ] && log "  SKIPPING $app (bundle id '$bid' is not $BUNDLE_ID)"
done < "$WORK/foreign"
sort -u "$WORK/denied" | while IFS= read -r d; do
    [ -n "$d" ] && log "  Could not search $d (Operation not permitted)"
done
DENIED=$(sort -u "$WORK/denied" | sed '/^$/d' | tr '\n' ' ' | sed 's/ $//')
if [ -n "$DENIED" ]; then
    add_issue "macOS refused to let this run search: $DENIED. Grant the Mosyle agent Full Disk Access (PPPC profile) so a copy there cannot be missed"
fi

if [ -z "$TARGETS" ]; then
    log "  No Apple Pages copy to remove."
else
    # -------------------------------------------------------------------
    # 2. Running?
    # -------------------------------------------------------------------
    log ""
    log "[2] Is Pages running?"
    PIDS=$(pages_running_pids | tr '\n' ' ' | sed 's/ $//')
    if [ -z "$PIDS" ]; then
        log "  Not running."
    elif [ "$FORCE_CLOSE" != "1" ]; then
        log "  Pages is RUNNING (pid: $PIDS)."
        add_issue "Pages is running (pid $PIDS); not removed so no unsaved work is lost. Re-run when it is closed, or set FORCE_CLOSE to 1"
        SKIP_REMOVE=1
    elif [ "$DRY_RUN" = "1" ]; then
        log "  Pages is RUNNING (pid: $PIDS). [DRY_RUN] Would quit it."
    else
        log "  Pages is RUNNING (pid: $PIDS). FORCE_CLOSE=1: quitting it."
        CONSOLE_USER=$(stat -f "%Su" /dev/console 2>/dev/null || true)
        CUID=""
        case "$CONSOLE_USER" in ""|root|loginwindow) ;; *) CUID=$(id -u "$CONSOLE_USER" 2>/dev/null || true) ;; esac
        if [ -n "$CUID" ]; then
            log "  Asking Pages to quit as $CONSOLE_USER..."
            launchctl asuser "$CUID" sudo -u "$CONSOLE_USER" /usr/bin/osascript \
                -e 'with timeout of 10 seconds' -e 'tell application id "com.apple.iWork.Pages" to quit' -e 'end timeout' \
                >/dev/null 2>&1 || true
            w=0
            while [ "$w" -lt "$QUIT_WAIT" ] && [ -n "$(pages_running_pids)" ]; do sleep 1; w=$((w + 1)); done
        fi
        if [ -n "$(pages_running_pids)" ]; then
            log "  Still running. Sending TERM, then KILL."
            for p in $(pages_running_pids); do kill "$p" 2>/dev/null || true; done
            sleep 5
            for p in $(pages_running_pids); do kill -9 "$p" 2>/dev/null || true; done
            sleep 2
        fi
        if [ -n "$(pages_running_pids)" ]; then
            add_issue "Pages would not quit (pid $(pages_running_pids | tr '\n' ' ' | sed 's/ $//')); not removed"
            SKIP_REMOVE=1
        else
            log "  Pages has quit."
        fi
    fi

    # -------------------------------------------------------------------
    # 3. Remove
    # -------------------------------------------------------------------
    if [ "$SKIP_REMOVE" = "0" ]; then
        log ""
        log "[3] Removing the app bundle(s). User documents and settings are not touched."
        while IFS= read -r app; do
            [ -n "$app" ] || continue
            if [ "$DRY_RUN" = "1" ]; then
                log "  [DRY_RUN] Would remove $app"
                continue
            fi
            log "  Removing $app"
            rm -rf "$app" 2>"$WORK/rm.err"
            if [ -e "$app" ]; then
                log "  Still present. Clearing immutable flags and retrying..."
                chflags -R nouchg,noschg "$app" 2>>"$WORK/rm.err" || true
                rm -rf "$app" 2>>"$WORK/rm.err"
            fi
            cat "$WORK/rm.err" >> "$LOG_FILE"
            if [ -e "$app" ]; then
                if tcc_denied < "$WORK/rm.err"; then
                    add_issue "could not remove $app: Operation not permitted. Grant the Mosyle agent App Management (PPPC SystemPolicyAppBundles), or uninstall Pages from Mosyle if it is a managed app"
                else
                    rm_msg=$(head -n 1 "$WORK/rm.err")
                    add_issue "could not remove $app (${rm_msg:-rm reported no error})"
                fi
            fi
        done <<EOF
$TARGETS
EOF
    fi
fi

# -----------------------------------------------------------------------
# 4. Verify by looking again, not by trusting rm
# -----------------------------------------------------------------------
log ""
log "[4] Verification..."
if [ "$DRY_RUN" = "1" ]; then
    if [ -n "$TARGETS" ]; then
        add_issue "DRY_RUN=1: $(echo "$TARGETS" | grep -c .) copy(ies) would be removed; nothing was changed"
    fi
elif [ -n "$TARGETS" ] && [ "$SKIP_REMOVE" = "0" ]; then
    : > "$WORK/denied"; : > "$WORK/foreign"
    LEFT=0
    while IFS= read -r app; do
        [ -n "$app" ] || continue
        echo "$TARGETS" | grep -qxF -- "$app" || continue
        LEFT=1
        echo "$ISSUES" | grep -qF -- "$app" || add_issue "$app is still present after removal"
    done < <(apple_pages_copies)
    [ "$LEFT" = "0" ] && log "  None of the targeted copies remain."
fi

log ""
if [ -n "$ISSUES" ]; then
    log "Problems:"
    echo "$ISSUES" | while IFS= read -r i; do log "  - $i"; done
    log "RESULT: Apple Pages NOT fully remediated (see Problems)."
    log "===== remove-apple-pages.sh END (needs attention) ====="
    exit 2
fi
if [ -n "$TARGETS" ]; then
    log "RESULT: Apple Pages removed."
    log "Check Mosyle for an app assignment, or the app will return. Rescan to confirm the finding clears."
else
    log "RESULT: nothing to remove."
fi
log "===== remove-apple-pages.sh END ====="
exit 0
