#!/bin/bash
# =============================================================================
# mac_update_force_after_1day.sh
# Purpose : Notify the user of pending macOS updates. If the update has been
#           pending for >= DEFER_SECONDS (default 1 day), force-install it
#           after a short on-screen grace warning, regardless of user response.
# Platform: macOS
# Deploy  : Mosyle (runs as root; GUI dialogs shown in the console user's session)
# =============================================================================

set -uo pipefail

# ----------------------------- CONFIG ---------------------------------------
DEFER_SECONDS=86400          # 1 day grace period before forcing (86400 = 24h)
GRACE_SECONDS=300            # Warning dialog window before forced install kicks off (5 min)
DRY_RUN=false                # true = log every action, never actually install/reboot
STATE_FILE="/var/db/.cs_update_first_seen"
LOG_DIR="/var/log/composecure"
LOG_FILE="$LOG_DIR/mac_update_force.log"
# -----------------------------------------------------------------------------

mkdir -p "$LOG_DIR"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }

log "===== mac_update_force_after_1day.sh START ====="
log "Host: $(hostname)  DryRun: $DRY_RUN"

# -----------------------------------------------------------------------
# Detect console (GUI) user, if any. Forcing still proceeds without one.
# -----------------------------------------------------------------------
CURRENT_USER=$(stat -f "%Su" /dev/console 2>/dev/null || true)
USER_LOGGED_IN=false

if [ -n "$CURRENT_USER" ] && [ "$CURRENT_USER" != "root" ] && [ "$CURRENT_USER" != "loginwindow" ]; then
    USER_ID=$(id -u "$CURRENT_USER" 2>/dev/null || true)
    if [ -n "$USER_ID" ]; then
        USER_LOGGED_IN=true
        log "Console user: $CURRENT_USER (uid $USER_ID)"
    fi
fi
$USER_LOGGED_IN || log "No GUI user logged in — dialogs will be skipped; forcing (if due) proceeds silently."

run_in_user_session() {
    launchctl asuser "$USER_ID" sudo -u "$CURRENT_USER" "$@"
}

# -----------------------------------------------------------------------
# 1. Check for available updates
# -----------------------------------------------------------------------
log "Checking for available macOS software updates..."
SU_OUTPUT=$(softwareupdate -l 2>&1)
log "softwareupdate -l output:"
log "$SU_OUTPUT"

if echo "$SU_OUTPUT" | grep -qi "No new software available"; then
    log "No updates available."
    if [ -f "$STATE_FILE" ]; then
        log "Clearing stale state file (previous update cycle is resolved)."
        rm -f "$STATE_FILE"
    fi
    log "===== mac_update_force_after_1day.sh END ====="
    exit 0
fi

UPDATE_LIST=$(echo "$SU_OUTPUT" | grep -E '^\s*\*' | sed -E 's/^\s*\*\s*(Label|Title):?\s*//' | sed 's/^ *//;s/ *$//')
[ -z "$UPDATE_LIST" ] && UPDATE_LIST="one or more updates"
DIALOG_LIST=$(echo "$UPDATE_LIST" | head -5 | sed 's/"/\\"/g')

# -----------------------------------------------------------------------
# 2. Establish / read first-seen timestamp
# -----------------------------------------------------------------------
NOW=$(date +%s)

if [ ! -f "$STATE_FILE" ]; then
    echo "$NOW" > "$STATE_FILE"
    FIRST_SEEN="$NOW"
    log "First time these updates were observed. State file created."
else
    FIRST_SEEN=$(cat "$STATE_FILE" 2>/dev/null || echo "$NOW")
    case "$FIRST_SEEN" in
        ''|*[!0-9]*) FIRST_SEEN="$NOW"; echo "$NOW" > "$STATE_FILE" ;;
    esac
fi

ELAPSED=$((NOW - FIRST_SEEN))
DEADLINE_STR=$(date -r $((FIRST_SEEN + DEFER_SECONDS)) '+%A, %b %d at %I:%M %p' 2>/dev/null || echo "the deadline")

log "First seen : $(date -r "$FIRST_SEEN" '+%Y-%m-%d %H:%M:%S')"
log "Elapsed    : ${ELAPSED}s (defer threshold: ${DEFER_SECONDS}s)"

# =========================================================================
# CASE A: Still within the deferral window — soft reminder, defer allowed
# =========================================================================
if [ "$ELAPSED" -lt "$DEFER_SECONDS" ]; then
    log "Within deferral window. Showing soft reminder (if user present)."

    if $USER_LOGGED_IN; then
        DIALOG_TEXT="Your MacBook has software updates available:

${DIALOG_LIST}

Please install soon. If not installed manually, updates will be applied automatically after ${DEADLINE_STR}."

        BUTTON_RESULT=$(run_in_user_session osascript <<APPLESCRIPT
display dialog "$DIALOG_TEXT" ¬
    with title "macOS Update Available" ¬
    buttons {"Remind Me Later", "Open Software Update"} ¬
    default button "Open Software Update" ¬
    with icon caution ¬
    giving up after 120
return button returned of result
APPLESCRIPT
)
        log "User response: ${BUTTON_RESULT:-no response / timed out}"

        if echo "$BUTTON_RESULT" | grep -qi "Open Software Update"; then
            run_in_user_session open "x-apple.systempreferences:com.apple.preferences.softwareupdate"
            log "Opened Software Update pane for user."
        fi
    fi

    log "===== mac_update_force_after_1day.sh END ====="
    exit 0
fi

# =========================================================================
# CASE B: Deferral window expired — force the install
# =========================================================================
log "Deferral window EXPIRED (${ELAPSED}s >= ${DEFER_SECONDS}s). Forcing update."

if $USER_LOGGED_IN; then
    WARN_TEXT="Your MacBook is overdue for required security updates:

${DIALOG_LIST}

Installation will begin automatically in $((GRACE_SECONDS / 60)) minutes. Save your work now. Your Mac may restart when complete."

    log "Displaying non-deferrable grace warning (${GRACE_SECONDS}s) to $CURRENT_USER..."

    if ! $DRY_RUN; then
        run_in_user_session osascript <<APPLESCRIPT &
display dialog "$WARN_TEXT" ¬
    with title "macOS Update Starting Automatically" ¬
    buttons {"OK"} ¬
    default button "OK" ¬
    with icon caution ¬
    giving up after $GRACE_SECONDS
APPLESCRIPT
        DIALOG_PID=$!
    else
        log "[DRYRUN] Would display grace-warning dialog for ${GRACE_SECONDS}s."
    fi

    log "Waiting out grace period (${GRACE_SECONDS}s) before forcing install..."
    $DRY_RUN || sleep "$GRACE_SECONDS"
else
    log "No user logged in — skipping grace dialog, proceeding directly to forced install."
fi

# -----------------------------------------------------------------------
# 3. Force-install all available updates, in the background, with restart
#    if required. Backgrounded so this Mosyle script call returns promptly
#    even though the install/reboot cycle can take much longer.
# -----------------------------------------------------------------------
if $DRY_RUN; then
    log "[DRYRUN] Would run: softwareupdate --install --all --restart --agree-to-license"
    log "[DRYRUN] Would leave state file in place until updates report clean on next run."
else
    log "Launching forced install in background: softwareupdate --install --all --restart"
    nohup softwareupdate --install --all --restart --agree-to-license >> "$LOG_FILE" 2>&1 &
    disown
    log "Forced install launched (pid $!). Machine may restart automatically when complete."
    log "State file left in place; will self-clear once 'softwareupdate -l' reports no updates."
fi

log "===== mac_update_force_after_1day.sh END ====="
exit 0
