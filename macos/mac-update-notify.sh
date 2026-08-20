#!/bin/bash
# =============================================================================
# mac_update_notify.sh
# Purpose : Check for pending macOS software updates and, if any exist,
#           prompt the logged-in user with a native dialog to install them.
# Platform: macOS
# Deploy  : Mosyle (runs as root; GUI dialog shown in the console user's session)
# =============================================================================

set -uo pipefail

LOG_DIR="/var/log/composecure"
LOG_FILE="$LOG_DIR/mac_update_notify.log"
mkdir -p "$LOG_DIR"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }

log "===== mac_update_notify.sh START ====="
log "Host: $(hostname)"

# -----------------------------------------------------------------------
# 1. Detect console (logged-in GUI) user
# -----------------------------------------------------------------------
CURRENT_USER=$(stat -f "%Su" /dev/console 2>/dev/null || true)

if [ -z "$CURRENT_USER" ] || [ "$CURRENT_USER" = "root" ] || [ "$CURRENT_USER" = "loginwindow" ]; then
    log "No GUI user currently logged in (console user: '${CURRENT_USER:-none}')."
    log "Nothing to notify — exiting cleanly. This will re-run on next check-in."
    log "===== mac_update_notify.sh END ====="
    exit 0
fi

USER_ID=$(id -u "$CURRENT_USER" 2>/dev/null || true)
if [ -z "$USER_ID" ]; then
    log "ERROR: Could not resolve UID for user '$CURRENT_USER'. Exiting."
    exit 1
fi
log "Console user: $CURRENT_USER (uid $USER_ID)"

# Helper: run a command inside the console user's GUI session
# (required for osascript dialogs to actually appear on screen)
run_in_user_session() {
    launchctl asuser "$USER_ID" sudo -u "$CURRENT_USER" "$@"
}

# -----------------------------------------------------------------------
# 2. Check for available software updates
# -----------------------------------------------------------------------
log "Checking for available macOS software updates (this can take a minute)..."
SU_OUTPUT=$(softwareupdate -l 2>&1)
log "softwareupdate -l output:"
log "$SU_OUTPUT"

if echo "$SU_OUTPUT" | grep -qi "No new software available"; then
    log "No updates available. Exiting cleanly."
    log "===== mac_update_notify.sh END ====="
    exit 0
fi

# Extract human-readable update titles (lines starting with '* Label:' or '* Title:')
UPDATE_LIST=$(echo "$SU_OUTPUT" | grep -E '^\s*\*' | sed -E 's/^\s*\*\s*(Label|Title):?\s*//' | sed 's/^ *//;s/ *$//')

if [ -z "$UPDATE_LIST" ]; then
    UPDATE_LIST="one or more updates"
fi

log "Updates available:"
log "$UPDATE_LIST"

# Build a display-friendly, newline-joined list for the dialog (max ~5 lines to keep it readable)
DIALOG_LIST=$(echo "$UPDATE_LIST" | head -5 | sed 's/"/\\"/g')

# -----------------------------------------------------------------------
# 3. Show a native dialog to the console user
# -----------------------------------------------------------------------
log "Displaying update prompt to $CURRENT_USER..."

DIALOG_TEXT="Your MacBook has software updates available:

${DIALOG_LIST}

Please install these updates as soon as possible to keep your device secure and compliant with IT policy."

# AppleScript dialog with two choices. Exit code / button result captured for logging.
BUTTON_RESULT=$(run_in_user_session osascript <<APPLESCRIPT
display dialog "$DIALOG_TEXT" ¬
    with title "macOS Update Required" ¬
    buttons {"Remind Me Later", "Open Software Update"} ¬
    default button "Open Software Update" ¬
    with icon caution ¬
    giving up after 120
return button returned of result
APPLESCRIPT
)

log "User response: ${BUTTON_RESULT:-no response / timed out}"

if echo "$BUTTON_RESULT" | grep -qi "Open Software Update"; then
    log "Opening Software Update pane for $CURRENT_USER..."
    run_in_user_session open "x-apple.systempreferences:com.apple.preferences.softwareupdate"
else
    log "User deferred (or dialog timed out). Will prompt again on next run."
fi

log "===== mac_update_notify.sh END ====="
exit 0
