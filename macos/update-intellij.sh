#!/bin/bash
# =============================================================================
# update-intellij-312365.sh (v3)
# Remediates : JetBrains IntelliJ IDEA Arbitrary Local File Read
# Nessus Plugin ID : 312365 | CVE-2026-41882
# Fix        : IntelliJ IDEA -> 2026.1.1
# Platform   : macOS (bash 3.2 compatible) | Deploy: Mosyle (root)
#
# v3 change:
#  * Now FORCE-CLOSES a running IntelliJ instead of deferring. A graceful
#    quit (AppleScript) is attempted first so unsaved buffers can flush,
#    then any surviving PIDs are killed. User notification removed.
#    WARNING: this can lose unsaved work in the IDE. Deploy during a window
#    where that is acceptable (the previous defer-and-notify behavior is
#    preserved in v2 if you need it back).
#
# v2 behavior retained:
#  * hdiutil attach without -quiet (parseable mount table).
#  * Stage -> verify (codesign + JetBrains TeamID 2ZEFAR8TH3 + version) -> swap,
#    so a failed download/copy leaves the old IDE intact.
#  * Edition (IU/IC) from bundle id, arch-aware DMG, quarantine flag cleared,
#    Toolbox-symlink detection.
# =============================================================================

set -uo pipefail

HOME="${HOME:-/var/root}"
export HOME

TARGET_VERSION="2026.1.1"
JETBRAINS_TEAM_ID="2ZEFAR8TH3"
LOG_DIR="/var/log/composecure"
LOG_FILE="$LOG_DIR/intellij_update.log"
WORK_DIR="/tmp/intellij_update_$$"
MIN_DMG_BYTES=$((100 * 1024 * 1024))

mkdir -p "$LOG_DIR"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }

MOUNT_POINT=""
STAGING_APP=""
cleanup() {
    [ -n "$MOUNT_POINT" ] && [ -d "$MOUNT_POINT" ] && hdiutil detach "$MOUNT_POINT" -quiet 2>/dev/null
    [ -n "$STAGING_APP" ] && [ -d "$STAGING_APP" ] && rm -rf "$STAGING_APP"
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

version_ge() { [ "$(printf '%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

log "===== update-intellij-312365.sh (v3) START ====="
log "Host: $(hostname)"

# -----------------------------------------------------------------------
# 1. Locate the app and read version + edition
# -----------------------------------------------------------------------
APP_PATH=""
for cand in "/Applications/IntelliJ IDEA.app" "/Applications/IntelliJ IDEA CE.app"; do
    [ -d "$cand" ] && APP_PATH="$cand" && break
done

if [ -z "$APP_PATH" ]; then
    log "IntelliJ IDEA not found in /Applications. Nothing to remediate."
    log "===== END ====="
    exit 0
fi

if [ -L "$APP_PATH" ]; then
    log "WARN: $APP_PATH is a symlink -- likely a JetBrains Toolbox install."
    log "      Toolbox manages its own updates; update it there instead. Exiting."
    exit 0
fi

PLIST="$APP_PATH/Contents/Info.plist"
CURRENT_VERSION=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$PLIST" 2>/dev/null || true)
BUNDLE_ID=$(/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$PLIST" 2>/dev/null || true)

log "App      : $APP_PATH"
log "Version  : ${CURRENT_VERSION:-unknown}"
log "BundleID : ${BUNDLE_ID:-unknown}"

if [ -n "$CURRENT_VERSION" ] && version_ge "$CURRENT_VERSION" "$TARGET_VERSION"; then
    log "Already at or above $TARGET_VERSION. No action needed."
    log "===== END ====="
    exit 0
fi

case "$BUNDLE_ID" in
    *ce*|*CE*) EDITION="IC" ;;
    *)         EDITION="IU" ;;
esac

case "$(uname -m)" in
    arm64)  ARCH_SUFFIX="-aarch64" ;;
    x86_64) ARCH_SUFFIX="" ;;
    *) log "ERROR: unsupported architecture $(uname -m)"; exit 1 ;;
esac

DMG_NAME="idea${EDITION}-${TARGET_VERSION}${ARCH_SUFFIX}.dmg"
DMG_URL="https://download.jetbrains.com/idea/${DMG_NAME}"
DMG_PATH="$WORK_DIR/$DMG_NAME"

log "Edition  : $EDITION ($([ "$EDITION" = "IU" ] && echo Ultimate || echo Community))"
log "Download : $DMG_URL"

# -----------------------------------------------------------------------
# 2. Force-close a running IDE (v3: graceful quit, then kill)
# -----------------------------------------------------------------------
IDEA_PIDS=$(pgrep -f "IntelliJ IDEA.*\.app/Contents/MacOS/idea" 2>/dev/null || true)
if [ -n "$IDEA_PIDS" ]; then
    log "IntelliJ IDEA is RUNNING (pids: $IDEA_PIDS). Force-closing for update."
    log "WARNING: unsaved in-IDE work may be lost."

    # Attempt a graceful quit first so buffers can flush.
    CONSOLE_USER=$(stat -f "%Su" /dev/console 2>/dev/null || true)
    if [ -n "$CONSOLE_USER" ] && [ "$CONSOLE_USER" != "root" ] && [ "$CONSOLE_USER" != "loginwindow" ]; then
        USER_ID=$(id -u "$CONSOLE_USER" 2>/dev/null || true)
        if [ -n "$USER_ID" ]; then
            launchctl asuser "$USER_ID" sudo -u "$CONSOLE_USER" osascript -e 'tell application "IntelliJ IDEA" to quit' 2>/dev/null || true
        fi
    fi

    # Give the graceful quit a few seconds to complete.
    for i in 1 2 3 4 5; do
        sleep 1
        pgrep -f "IntelliJ IDEA.*\.app/Contents/MacOS/idea" >/dev/null 2>&1 || break
    done

    # Hard-kill anything still alive.
    STILL=$(pgrep -f "IntelliJ IDEA.*\.app/Contents/MacOS/idea" 2>/dev/null || true)
    if [ -n "$STILL" ]; then
        log "Graceful quit did not fully close it; sending SIGKILL to: $STILL"
        for pid in $STILL; do
            kill -9 "$pid" 2>/dev/null || true
        done
        sleep 2
    fi

    if pgrep -f "IntelliJ IDEA.*\.app/Contents/MacOS/idea" >/dev/null 2>&1; then
        log "ERROR: IntelliJ still running after kill attempts. Aborting to avoid a partial update."
        exit 1
    fi
    log "IntelliJ closed."
fi

# -----------------------------------------------------------------------
# 3. Download the DMG (with size validation)
# -----------------------------------------------------------------------
mkdir -p "$WORK_DIR"
log "Downloading ${DMG_NAME}..."

if ! curl -fL --retry 3 --retry-delay 5 -o "$DMG_PATH" "$DMG_URL" 2>>"$LOG_FILE"; then
    log "ERROR: download failed. If Zscaler is blocking download.jetbrains.com,"
    log "       stage the DMG locally and point DMG_URL at an internal path."
    exit 1
fi

DL_SIZE=$(stat -f "%z" "$DMG_PATH" 2>/dev/null || echo 0)
log "Downloaded: $((DL_SIZE / 1024 / 1024)) MB"

if [ "$DL_SIZE" -lt "$MIN_DMG_BYTES" ]; then
    log "ERROR: download is < 100MB -- likely a Zscaler block page, not a DMG. Aborting."
    exit 1
fi

# -----------------------------------------------------------------------
# 4. Mount (no -quiet, so the mount table is parseable)
# -----------------------------------------------------------------------
log "Mounting DMG..."
ATTACH_OUT=$(hdiutil attach "$DMG_PATH" -nobrowse 2>>"$LOG_FILE")
MOUNT_POINT=$(echo "$ATTACH_OUT" | grep -o '/Volumes/.*' | head -1)

if [ -z "$MOUNT_POINT" ] || [ ! -d "$MOUNT_POINT" ]; then
    log "ERROR: could not determine mount point. hdiutil output:"
    log "$ATTACH_OUT"
    exit 1
fi
log "Mounted at: $MOUNT_POINT"

SRC_APP=$(find "$MOUNT_POINT" -maxdepth 1 -name "*.app" -type d | head -1)
if [ -z "$SRC_APP" ]; then
    log "ERROR: no .app bundle found inside DMG."
    exit 1
fi
log "Source app: $SRC_APP"

# -----------------------------------------------------------------------
# 5. Stage -> verify -> swap (old app survives any failure)
# -----------------------------------------------------------------------
STAGING_APP="/Applications/.intellij_staging_$$.app"
log "Staging new bundle to $STAGING_APP (this can take a minute)..."
if ! ditto "$SRC_APP" "$STAGING_APP" 2>>"$LOG_FILE"; then
    log "ERROR: staging copy failed. Old IDE untouched."
    exit 1
fi

hdiutil detach "$MOUNT_POINT" -quiet 2>/dev/null && MOUNT_POINT=""

log "Verifying code signature of staged bundle..."
if ! codesign --verify --deep --strict "$STAGING_APP" 2>>"$LOG_FILE"; then
    log "ERROR: codesign verification FAILED on the staged bundle. Old IDE untouched."
    exit 1
fi
TEAM_ID=$(codesign -dv "$STAGING_APP" 2>&1 | grep '^TeamIdentifier=' | cut -d= -f2)
if [ "$TEAM_ID" != "$JETBRAINS_TEAM_ID" ]; then
    log "ERROR: TeamIdentifier '$TEAM_ID' is not JetBrains ($JETBRAINS_TEAM_ID). Old IDE untouched."
    exit 1
fi
log "Signature OK (TeamIdentifier: $TEAM_ID)"

STAGED_VERSION=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$STAGING_APP/Contents/Info.plist" 2>/dev/null || true)
if [ -z "$STAGED_VERSION" ] || ! version_ge "$STAGED_VERSION" "$TARGET_VERSION"; then
    log "ERROR: staged bundle version (${STAGED_VERSION:-unknown}) does not meet $TARGET_VERSION. Old IDE untouched."
    exit 1
fi
log "Staged version: $STAGED_VERSION"

log "Swapping: removing old bundle and moving staged bundle into place..."
rm -rf "$APP_PATH"
if ! mv "$STAGING_APP" "$APP_PATH"; then
    log "ERROR: final move failed -- IDE may be absent; re-run to restore."
    exit 1
fi
STAGING_APP=""

xattr -dr com.apple.quarantine "$APP_PATH" 2>/dev/null || true

# -----------------------------------------------------------------------
# 6. Verify installed
# -----------------------------------------------------------------------
NEW_VERSION=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$APP_PATH/Contents/Info.plist" 2>/dev/null || true)
log "Post-install version: ${NEW_VERSION:-unknown}"

if [ -n "$NEW_VERSION" ] && version_ge "$NEW_VERSION" "$TARGET_VERSION"; then
    log "SUCCESS: IntelliJ IDEA ${CURRENT_VERSION:-?} -> $NEW_VERSION"
    log "Re-run a Nessus scan to confirm plugin 312365 clears."
else
    log "ERROR: version after install (${NEW_VERSION:-unknown}) does not meet $TARGET_VERSION."
    exit 1
fi

log "===== update-intellij-312365.sh (v3) END ====="
exit 0
