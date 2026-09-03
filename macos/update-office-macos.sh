#!/bin/bash
# =============================================================================
# update-office-macos.sh  (v2)
#
# Version-aware Microsoft Office updater for App Store-installed Office.
# Only quits and updates apps that are BEHIND the App Store's current build;
# leaves everything else running untouched. Safe to run fleet-wide via Mosyle.
#
# Usage:
#   ./update-office-macos.sh              # apply updates to outdated apps
#   ./update-office-macos.sh --dry-run    # report what WOULD happen, no changes
#   ./update-office-macos.sh --accurate   # slower, more precise mas outdated check
#
# v2 (requested follow-up to v1): v1 compared each app's installed version
# against a HARDCODED "TARGET_VERSION=16.107" -- "highest Fixed version
# across all Tenable Office findings," derived by hand from a Tenable export
# and requiring a human to re-derive and bump it every time Microsoft ships a
# new Office patch (monthly). That is the same class of problem the Windows
# scripts in this repo solve with aka.ms permalinks instead of a pinned
# version number. On macOS there is no such permalink for Office, but `mas`
# (the App Store CLI this script already depends on for the update step)
# can answer "is a newer build currently published in the Store" directly,
# via `mas outdated` -- so that replaces the hardcoded number entirely.
#   * TARGET_VERSION and the sort -V based version_lt() are both GONE.
#     (version_lt was also latently broken on stock macOS: /usr/bin/sort is
#     BSD sort, which has no -V flag at all -- that comparison would have
#     errored on any Mac without GNU coreutils from Homebrew.)
#   * `mas outdated` (unfiltered, then grepped locally for our five known
#     app IDs -- filtering by ID inside `mas outdated` itself is a newer mas
#     feature and this avoids depending on the fleet's mas version for it)
#     is now the sole source of truth for "is this app behind," both before
#     AND after the update (the post-update check no longer compares
#     version STRINGS; it just asks the Store again).
#   * Detection now needs `mas`, so ensuring it is installed moved earlier
#     and now also runs under --dry-run (a real behavior change from v1,
#     where dry-run needed nothing beyond `defaults read`). Installing the
#     `mas` tool itself is not a change to Office, so this stays within the
#     spirit of "dry-run changes nothing" -- but it is called out here
#     because it is the one part of a dry-run that touches the filesystem.
#   * `mas outdated`'s own exit code is treated as authoritative: a nonzero
#     exit (e.g. not signed into the App Store) is a hard failure, not
#     silently read as "nothing is outdated." Getting this wrong would be a
#     silent fail-open on a security remediation script.
#
# Notes:
#   - Targets the App Store Office suite (Word, Excel, PowerPoint, Outlook,
#     OneNote), which is how this fleet is provisioned. This app list is
#     deliberate fleet configuration, not something to auto-derive.
#   - Teams / OneDrive are MAU-managed and not flagged by Tenable, so they are
#     intentionally excluded. See the bottom of this file to add them if needed.
#   - mas requires the logged-in user to be signed into the App Store, for
#     BOTH the outdated check and the actual upgrade (v1 only needed this for
#     the upgrade step).
# =============================================================================

set -uo pipefail

# ---- Args ----
DRY_RUN=false
ACCURATE=false
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    --accurate) ACCURATE=true ;;
    *) echo "Unknown arg: $arg" ; exit 2 ;;
  esac
done

LOG_DIR="/var/log/composecure"
LOG_FILE="$LOG_DIR/office-update.log"
mkdir -p "$LOG_DIR"

log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOG_FILE"
}

# ---- Logged-in console user ----
CURRENT_USER=$(stat -f "%Su" /dev/console)
if [ -z "$CURRENT_USER" ] || [ "$CURRENT_USER" = "root" ]; then
  log "ERROR: Could not determine a logged-in user. Exiting."
  exit 1
fi
USER_HOME="/Users/$CURRENT_USER"

log "================================================================"
log "Office update run on $(hostname)"
log "User: $CURRENT_USER | Target: current App Store build (dynamic, via mas) | Dry run: $DRY_RUN | Accurate: $ACCURATE"
log "================================================================"

# ---- Run mas as the console user, with its App Store session ----
run_mas() {
  sudo -u "$CURRENT_USER" HOME="$USER_HOME" \
    PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin" \
    "$MAS_BIN" "$@"
}

# ---- Extract "<from>|<to>" for one app ID out of a captured `mas outdated`
#      listing, or fail (exit 1, nothing printed) if that ID is not present
#      (i.e. not outdated, or not recognized by mas as a Store-managed app).
#      mas outdated lines look like: " 663592361  DuckDuckGo   (1.169.0 -> 1.174.0)"
parse_outdated_line() {
  local id="$1"
  local line inner from to
  line=$(printf '%s\n' "$OUTDATED_RAW" | grep -E "^[[:space:]]*${id}[[:space:]]")
  [ -z "$line" ] && return 1
  inner=$(printf '%s\n' "$line" | grep -oE '\([^()]*\)' | tail -1 | sed -E 's/^\(//; s/\)$//')
  [ -z "$inner" ] && return 1
  from=$(printf '%s' "$inner" | awk -F'->' '{print $1}' | tr -d '[:space:]')
  to=$(printf '%s' "$inner" | awk -F'->' '{print $2}' | tr -d '[:space:]')
  [ -z "$from" ] || [ -z "$to" ] && return 1
  printf '%s|%s' "$from" "$to"
  return 0
}

# ---- App Store Office suite: "name|path|appstore_id" ----
APPS=(
  "Microsoft Word|/Applications/Microsoft Word.app|462054704"
  "Microsoft Excel|/Applications/Microsoft Excel.app|462058435"
  "Microsoft PowerPoint|/Applications/Microsoft PowerPoint.app|462062816"
  "Microsoft Outlook|/Applications/Microsoft Outlook.app|985367838"
  "Microsoft OneNote|/Applications/Microsoft OneNote.app|784801555"
)

# ---- Ensure mas is present. Detection needs it now, not just the update
#      step, so this runs even under --dry-run (see v2 note above). ----
MAS_BIN="/opt/homebrew/bin/mas"
if [ ! -x "$MAS_BIN" ]; then
  log "mas not found - installing via Homebrew as $CURRENT_USER..."
  sudo -u "$CURRENT_USER" HOME="$USER_HOME" \
    PATH="/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin:/bin" \
    /opt/homebrew/bin/brew install mas >>"$LOG_FILE" 2>&1
fi
if [ ! -x "$MAS_BIN" ]; then
  log "ERROR: mas still not available after install attempt. Exiting."
  exit 1
fi

# Diagnostic only -- does not gate anything. If nobody is signed into the App
# Store, the outdated/upgrade calls below will fail on their own with a
# clearer error at the point of actual use; this just gives an early hint.
ACCOUNT=$(run_mas account 2>&1)
if [ -z "$ACCOUNT" ]; then
  log "WARN: 'mas account' returned nothing -- $CURRENT_USER may not be signed into the App Store."
else
  log "App Store account: $ACCOUNT"
fi

# ---- Ask the Store, once, what's outdated. This IS the target version --
#      no hardcoded number anywhere in this script. ----
log ""
if $ACCURATE; then
  log "Querying the App Store for outdated apps (mas outdated --accurate)..."
  OUTDATED_RAW=$(run_mas outdated --accurate 2>&1)
else
  log "Querying the App Store for outdated apps (mas outdated)..."
  OUTDATED_RAW=$(run_mas outdated 2>&1)
fi
MAS_RC=$?
if [ "$MAS_RC" -ne 0 ]; then
  log "ERROR: 'mas outdated' exited $MAS_RC -- treating as a hard failure, not as"
  log "'nothing is outdated'. Raw output:"
  log "$OUTDATED_RAW"
  log "Common cause: $CURRENT_USER is not signed into the App Store. Sign in and re-run."
  exit 1
fi
log "mas outdated raw output:"
log "${OUTDATED_RAW:-<nothing outdated on this Mac>}"

# ---- Scan: decide which of OUR apps are outdated, per mas, not a fixed number ----
TO_UPDATE_NAMES=()
TO_UPDATE_IDS=()
TO_UPDATE_FROM=()
TO_UPDATE_TO=()

log ""
log "Scanning installed Office apps..."
for ENTRY in "${APPS[@]}"; do
  IFS='|' read -r NAME APP_PATH APP_ID <<< "$ENTRY"
  if [ ! -d "$APP_PATH" ]; then
    log "  $NAME: not installed - skip"
    continue
  fi
  LOCAL_VER=$(defaults read "$APP_PATH/Contents/Info" CFBundleShortVersionString 2>/dev/null)
  [ -z "$LOCAL_VER" ] && LOCAL_VER="unknown"

  if PAIR=$(parse_outdated_line "$APP_ID"); then
    FROM_VER="${PAIR%%|*}"
    TO_VER="${PAIR##*|}"
    log "  $NAME: $LOCAL_VER -> OUTDATED per App Store ($FROM_VER -> $TO_VER available) - will update"
    TO_UPDATE_NAMES+=("$NAME")
    TO_UPDATE_IDS+=("$APP_ID")
    TO_UPDATE_FROM+=("$FROM_VER")
    TO_UPDATE_TO+=("$TO_VER")
  else
    log "  $NAME: $LOCAL_VER -> current per App Store - leave running"
  fi
done

# ---- Nothing to do ----
if [ ${#TO_UPDATE_NAMES[@]} -eq 0 ]; then
  log ""
  log "All installed Office apps are current per the App Store. Nothing to do."
  exit 0
fi

log ""
log "Apps requiring update: ${TO_UPDATE_NAMES[*]}"

# ---- Dry run stops here ----
if $DRY_RUN; then
  log ""
  log "[DRY RUN] Would quit and update the apps listed above. No changes made"
  log "[DRY RUN] beyond ensuring mas itself is installed (see v2 note above)."
  exit 0
fi

# ---- Quit ONLY the outdated apps ----
log ""
log "Quitting outdated apps (others left running)..."
for NAME in "${TO_UPDATE_NAMES[@]}"; do
  if pgrep -x "$NAME" >/dev/null 2>&1; then
    log "  Quitting: $NAME"
    pkill -x "$NAME"
  else
    log "  Not running: $NAME"
  fi
done
sleep 3

# ---- Update ONLY the outdated apps ----
log ""
log "Updating outdated apps via mas..."
for i in "${!TO_UPDATE_NAMES[@]}"; do
  NAME="${TO_UPDATE_NAMES[$i]}"
  APP_ID="${TO_UPDATE_IDS[$i]}"
  log "  Upgrading: $NAME (App Store ID $APP_ID)"
  run_mas upgrade "$APP_ID" >>"$LOG_FILE" 2>&1 \
    || log "    Note: mas had nothing to upgrade (App Store may not have a newer build than installed yet)"
done

# ---- Re-check with the Store (not a version-string comparison) to confirm ----
sleep 3
log ""
log "Re-querying the App Store to confirm the update actually applied..."
if $ACCURATE; then
  RECHECK_RAW=$(run_mas outdated --accurate 2>&1)
else
  RECHECK_RAW=$(run_mas outdated 2>&1)
fi
RECHECK_RC=$?
# parse_outdated_line reads the global $OUTDATED_RAW -- point it at the
# re-check result once, here, rather than inside the loop below.
OUTDATED_RAW="$RECHECK_RAW"

log ""
log "Final status for updated apps:"
for i in "${!TO_UPDATE_NAMES[@]}"; do
  NAME="${TO_UPDATE_NAMES[$i]}"
  APP_ID="${TO_UPDATE_IDS[$i]}"
  for ENTRY in "${APPS[@]}"; do
    IFS='|' read -r N P ID <<< "$ENTRY"
    if [ "$N" = "$NAME" ] && [ -d "$P" ]; then
      VER=$(defaults read "$P/Contents/Info" CFBundleShortVersionString 2>/dev/null || echo "unknown")
      STATUS="OK"
      if [ "$RECHECK_RC" -eq 0 ]; then
        parse_outdated_line "$APP_ID" >/dev/null && STATUS="STILL OUTDATED (App Store may not have propagated the new build yet)"
      else
        STATUS="UNKNOWN (re-check of mas outdated failed, exit $RECHECK_RC)"
      fi
      log "  $NAME: $VER  [$STATUS]"
    fi
  done
done

log ""
log "Done."

# =============================================================================
# To also handle MAU-managed apps (Teams, OneDrive), msupdate is already
# version-aware - it only installs when an update exists. You could append:
#
#   MSUPDATE="/Library/Application Support/Microsoft/MAU2.0/Microsoft AutoUpdate.app/Contents/MacOS/msupdate"
#   [ -f "$MSUPDATE" ] && "$MSUPDATE" --install --apps TEAM01,ONDR01
#
# Left out by default since neither was flagged by Tenable in this scan.
# =============================================================================
