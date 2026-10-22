#!/bin/bash
# =============================================================================
# update-zoom.sh  (v2)
# Remediates : Zoom Workplace below the current release (plugins 334489
#              ZSB-26015 "< 7.0.6 / 7.1.0" and 334491 ZSB-26017
#              "< 7.0.6 / 7.1.5", csprmb-15-a 2026-10-19), and later Zoom
#              advisories of the same shape.
# Platform   : macOS (bash 3.2 compatible) | Deploy: Mosyle (runs as root)
#
# No pinned version. The target is whatever Zoom currently ships:
# https://zoom.us/client/latest/ZoomInstallerIT.pkg redirects to
# https://cdn.zoom.us/prod/<N.N.N.build>/ZoomInstallerIT.pkg, and the version
# is read from that URL. The IT package installs machine-wide into
# /Applications/zoom.us.app and is made for unattended root installs.
#
# Steps:
#   1. Inventory /Applications/zoom.us.app and per-user copies in
#      /Users/*/Applications (Zoom offers a no-admin install there; Tenable
#      reports those too and nothing updates them as root).
#   2. Nothing below the latest -> exit 0 without downloading.
#   3. A meeting in progress (CptHost / aomhost running) defers with exit 2
#      unless FORCE_CLOSE=1: closing Zoom would drop the call.
#   4. Download, check the package is signed with Zoom's Developer ID. If Zoom
#      is open, quit it (CLOSE_IDLE_ZOOM=1), then run `installer` with a
#      wall-clock limit and reopen Zoom for the user afterwards.
#   5. Re-read the app's version. The installer's exit code is not proof. On
#      failure, Zoom's own /Library/Logs/zoomusinstall.log is copied into ours.
#   6. Only after /Applications is verified current: remove per-user copies
#      that are older and not running (REMOVE_USER_COPIES=1).
#
# Why Zoom must be closed (v2, CSPRMB-15-A 2026-10-22): the IT package's
# preinstall does not install over a running zoom.us >= 6.6 from the command
# line. It copies the package to /Applications/.zoomusUpdateUseOnly for Zoom to
# apply itself, then exits 1 ("An error occurred while running scripts from
# the package"). v1 only waited for meetings, so an idle open Zoom never
# updated.
#
# CONFIG -- Mosyle passes no environment variables. Edit the block below
# before paste, or pass the same names from a terminal (DRY_RUN=1 ...).
# APP_DIR, USERS_DIR, LOG_DIR and WORK_DIR may be set for tests.
#
# Exit: 0 = every Zoom copy is current (or Zoom is not installed)
#       2 = deferred (meeting, or Zoom open and would not quit), not verified
#           after install, or a per-user copy is still old -- see the RESULT line
#       1 = could not run (no latest version, download / signature failed)
# =============================================================================

set -uo pipefail
HOME="${HOME:-/var/root}"
export HOME

# =============================================================================
CFG_DRY_RUN="0"
# Close Zoom even during a meeting. Off: a meeting defers to the next run.
CFG_FORCE_CLOSE="0"
# Quit an open Zoom that is not in a meeting, install, then reopen it. Zoom's
# installer will not update a running Zoom. "0" defers (exit 2) instead.
CFG_CLOSE_IDLE_ZOOM="1"
# Seconds to wait for Zoom to quit when asked, and again after a TERM.
CFG_QUIT_TIMEOUT="30"
# Remove older per-user copies (~/Applications/zoom.us.app) once the
# machine-wide copy is verified current. "0" only reports them.
CFG_REMOVE_USER_COPIES="1"
CFG_PKG_URL="https://zoom.us/client/latest/ZoomInstallerIT.pkg"
# Seconds allowed for the download and for the installer.
CFG_DOWNLOAD_TIMEOUT="900"
CFG_INSTALL_TIMEOUT="900"
# =============================================================================
DRY_RUN="${DRY_RUN:-$CFG_DRY_RUN}"
FORCE_CLOSE="${FORCE_CLOSE:-$CFG_FORCE_CLOSE}"
CLOSE_IDLE_ZOOM="${CLOSE_IDLE_ZOOM:-$CFG_CLOSE_IDLE_ZOOM}"
QUIT_TIMEOUT="${QUIT_TIMEOUT:-$CFG_QUIT_TIMEOUT}"
REMOVE_USER_COPIES="${REMOVE_USER_COPIES:-$CFG_REMOVE_USER_COPIES}"
PKG_URL="${PKG_URL:-$CFG_PKG_URL}"
DOWNLOAD_TIMEOUT="${DOWNLOAD_TIMEOUT:-$CFG_DOWNLOAD_TIMEOUT}"
INSTALL_TIMEOUT="${INSTALL_TIMEOUT:-$CFG_INSTALL_TIMEOUT}"

APP_DIR="${APP_DIR:-/Applications}"
USERS_DIR="${USERS_DIR:-/Users}"
LOG_DIR="${LOG_DIR:-/var/log/composecure}"
LOG_FILE="$LOG_DIR/zoom_update.log"
WORK_DIR="${WORK_DIR:-/var/tmp/zoom_update_$$}"
ZOOM_INSTALL_LOG="${ZOOM_INSTALL_LOG:-/Library/Logs/zoomusinstall.log}"
# Apple team ID, not the company name: Zoom's certificate changed from "Zoom
# Video Communications, Inc." to "Zoom Communications, Inc." (CSPRMB-15-A,
# 2026-10-22) with the same team ID.
ZOOM_TEAM_ID="BJ4HAAB9B3"
MEETING_PROCS="CptHost aomhost"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }

# "https://cdn.zoom.us/prod/7.2.2.88465/ZoomInstallerIT.pkg" -> 7.2.2.88465
version_from_url() {
    echo "$1" | sed -n 's#.*/prod/\([0-9][0-9]*\(\.[0-9][0-9]*\)\{2,3\}\)/[^/]*$#\1#p'
}

# Zoom's Info.plist: CFBundleVersion "7.1.5.70120", CFBundleShortVersionString
# "7.1.5 (70120)". Either -> 7.1.5.70120 (or 7.1.5 when no build is given).
normalize_zoom_version() {
    echo "$1" | sed -n 's/^[[:space:]]*\([0-9][0-9]*\(\.[0-9][0-9]*\)*\)[[:space:]]*\(([[:space:]]*\([0-9][0-9]*\)[[:space:]]*)\)\{0,1\}.*$/\1.\4/p' \
        | sed 's/\.$//'
}

is_full_version() { echo "$1" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?$'; }

# True when $1 >= $2. Only as many fields as both have are compared, so
# 7.1.5 (no build) is not judged older than 7.1.5.70120.
version_ge() {
    vg_n=$(echo "$1" | awk -F. '{print NF}')
    vg_m=$(echo "$2" | awk -F. '{print NF}')
    [ "$vg_m" -lt "$vg_n" ] && vg_n=$vg_m
    vg_a=$(echo "$1" | cut -d. -f1-"$vg_n")
    vg_b=$(echo "$2" | cut -d. -f1-"$vg_n")
    [ "$(printf '%s\n%s\n' "$vg_a" "$vg_b" | sort -V | tail -n 1)" = "$vg_a" ]
}

# `pkgutil --check-signature` output on stdin -> the leaf certificate's name
# (chain entry 1), e.g. "Developer ID Installer: Zoom Communications, Inc. (BJ4HAAB9B3)".
signer_from_pkgutil() {
    sed -n 's/^[[:space:]]*1\.[[:space:]]*//p' | head -n 1
}

# `pkgutil --check-signature` output on stdin -> 0 when Apple-issued and the
# leaf is a Developer ID Installer certificate for Zoom's team ID.
signature_is_zoom() {
    sz_out=$(cat)
    echo "$sz_out" | grep -q 'signed by a developer certificate issued by Apple' || return 1
    echo "$sz_out" | signer_from_pkgutil | grep -qE "^Developer ID Installer: .+ \\($ZOOM_TEAM_ID\\)[[:space:]]*\$" || return 1
}

# Zoom's /Library/Logs/zoomusinstall.log from a failed install on stdin -> why
# it failed, or nothing when the log does not say.
zoom_install_cause() {
    zc_out=$(cat)
    if echo "$zc_out" | grep -q 'Copied IT pkg to'; then
        echo "Zoom was open for the logged-in user: Zoom's preinstall copied the package to /Applications/.zoomusUpdateUseOnly for Zoom to apply itself and stopped the install (exit 1). Quit Zoom and re-run."
        return 0
    fi
    zc_line=$(echo "$zc_out" | grep -E 'sha256 (auth|verify) failed|codesign fail|daemon helper not exit|copyPlist' | head -n 1)
    [ -n "$zc_line" ] && echo "Zoom's postinstall rejected part of the package: $zc_line"
    return 0
}

descendants() (
    for d_child in $(pgrep -P "$1" 2>/dev/null); do
        descendants "$d_child"
        echo "$d_child"
    done
)

if [ "${ZOOM_UPDATE_SELFTEST:-0}" = "1" ]; then
    return 0 2>/dev/null || exit 0
fi

mkdir -p "$LOG_DIR"
cd /tmp || exit 1
ISSUES=""
add_issue() { ISSUES="${ISSUES}${ISSUES:+
}$1"; }
cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

app_version() {
    av_plist="$1/Contents/Info.plist"
    [ -f "$av_plist" ] || return 0
    for av_key in CFBundleVersion CFBundleShortVersionString; do
        av_v=$(normalize_zoom_version "$(defaults read "$av_plist" "$av_key" 2>/dev/null)")
        # A bare build number ("88465") would compare as newer than 7.2.2.
        if is_full_version "$av_v"; then echo "$av_v"; return 0; fi
    done
}

# Run "$@" with a wall-clock limit ($1 seconds); output to $STEP_LOG.
run_limited() {
    rl_limit="$1"; shift
    rl_start=$(date +%s)
    "$@" >>"$STEP_LOG" 2>&1 &
    rl_pid=$!
    while kill -0 "$rl_pid" 2>/dev/null; do
        sleep 1
        if [ $(( $(date +%s) - rl_start )) -ge "$rl_limit" ]; then
            rl_pids="$(descendants "$rl_pid") $rl_pid"
            log "  TIME LIMIT (${rl_limit}s) reached -- stopping $(basename "$1")."
            # shellcheck disable=SC2086
            kill $rl_pids 2>/dev/null; sleep 5
            # shellcheck disable=SC2086
            kill -9 $rl_pids 2>/dev/null
            wait "$rl_pid" 2>/dev/null
            return 124
        fi
    done
    wait "$rl_pid"
}

in_meeting() {
    for mp in $MEETING_PROCS; do
        pgrep -x "$mp" >/dev/null 2>&1 && { echo "$mp"; return 0; }
    done
    return 1
}

zoom_pids() { pgrep -x zoom.us 2>/dev/null; }

console_user() {
    cu_name=$(stat -f %Su /dev/console 2>/dev/null)
    case "$cu_name" in ""|root|loginwindow|_mbsetupuser) return 1 ;; esac
    echo "$cu_name"
}

as_user() {
    au_user="$1"; shift
    au_uid=$(id -u "$au_user" 2>/dev/null) || return 1
    launchctl asuser "$au_uid" sudo -u "$au_user" "$@"
}

wait_zoom_gone() {
    wz_end=$(( $(date +%s) + $1 ))
    while [ -n "$(zoom_pids)" ]; do
        [ "$(date +%s)" -ge "$wz_end" ] && return 1
        sleep 1
    done
    return 0
}

# Ask Zoom to quit as the logged-in user, then TERM what is left. 0 = gone.
quit_zoom() {
    if qz_user=$(console_user); then
        log "  Asking Zoom to quit (as $qz_user)."
        STEP_LOG="$LOG_DIR/zoom_update_quit.log"; : > "$STEP_LOG"
        run_limited 30 as_user "$qz_user" osascript -e 'tell application id "us.zoom.xos" to quit'
        wait_zoom_gone "$QUIT_TIMEOUT" && return 0
    fi
    qz_pids=$(zoom_pids | tr '\n' ' ')
    log "  Zoom still running (pid ${qz_pids% }) -- sending TERM."
    # shellcheck disable=SC2086
    kill $qz_pids 2>/dev/null
    wait_zoom_gone "$QUIT_TIMEOUT"
}

# Why the install has to wait, or nothing when it can go ahead.
install_blocker() {
    [ "$FORCE_CLOSE" = "1" ] && return 0
    if ib_mp=$(in_meeting); then
        echo "meeting in progress ($ib_mp); re-run later or set FORCE_CLOSE=1"
    elif [ -n "$(zoom_pids)" ] && [ "$CLOSE_IDLE_ZOOM" != "1" ]; then
        echo "Zoom is open (no meeting) and CLOSE_IDLE_ZOOM=0; Zoom's installer does not update a running Zoom -- re-run when it is closed"
    fi
    return 0
}

finish() {
    log ""
    log "================ SUMMARY ================"
    if [ -n "$ISSUES" ]; then
        log "Problems:"
        printf '%s\n' "$ISSUES" | while IFS= read -r l; do log "  - $l"; done
    fi
    log "RESULT: $2"
    log "===== END ====="
    exit "$1"
}

log "===== update-zoom.sh START ====="
log "Host: $(hostname -s 2>/dev/null || hostname)   macOS $(sw_vers -productVersion 2>/dev/null || echo '?')   arch $(uname -m)"
log "DryRun=$DRY_RUN  ForceClose=$FORCE_CLOSE  CloseIdleZoom=$CLOSE_IDLE_ZOOM  RemoveUserCopies=$REMOVE_USER_COPIES"

log ""
log "[1] Installed copies"
MAIN_APP="$APP_DIR/zoom.us.app"
MAIN_VER=$(app_version "$MAIN_APP")
if [ -n "$MAIN_VER" ]; then
    log "  $MAIN_APP  $MAIN_VER"
else
    log "  $MAIN_APP  not installed"
fi
USER_APPS=""
for ua in "$USERS_DIR"/*/Applications/zoom.us.app; do
    [ -d "$ua" ] || continue
    uv=$(app_version "$ua")
    log "  $ua  ${uv:-version unreadable}"
    USER_APPS="$USER_APPS
$ua|$uv"
done
if [ -z "$MAIN_VER" ] && [ -z "$USER_APPS" ]; then
    finish 0 "Zoom is not installed. Nothing to do."
fi
[ -d /opt/homebrew/Caskroom/zoom ] || [ -d /usr/local/Caskroom/zoom ] && \
    log "  (also a Homebrew cask record; brew's version will lag -- harmless, the cask auto-updates)"

log ""
log "[2] Latest release"
LATEST_URL=$(curl -sIL -o /dev/null -w '%{url_effective}' --max-time 60 "$PKG_URL" 2>/dev/null)
LATEST=$(version_from_url "$LATEST_URL")
if [ -z "$LATEST" ]; then
    add_issue "could not read the latest version from $PKG_URL (got '${LATEST_URL:-nothing}')"
    finish 1 "latest Zoom version unknown -- nothing changed."
fi
log "  $LATEST  ($LATEST_URL)"

need_main=0
if [ -n "$MAIN_VER" ]; then
    version_ge "$MAIN_VER" "$LATEST" || need_main=1
else
    need_main=1
fi
OLD_USER=""
if [ -n "$USER_APPS" ]; then
    while IFS='|' read -r ua uv; do
        [ -n "$ua" ] || continue
        if [ -z "$uv" ] || ! version_ge "$uv" "$LATEST"; then OLD_USER="$OLD_USER
$ua|$uv"; fi
    done <<EOF
$USER_APPS
EOF
fi
if [ "$need_main" -eq 0 ] && [ -z "$OLD_USER" ]; then
    finish 0 "Zoom $MAIN_VER is current (latest $LATEST)."
fi
# A per-user copy alone still gets the machine-wide install: removing the
# user's copy without a replacement would take Zoom away from them.
log "  Needs work: $( [ "$need_main" -eq 1 ] && echo "machine-wide copy" )$( [ -n "$OLD_USER" ] && echo " per-user copies" )"

if [ "$need_main" -eq 1 ]; then
    log ""
    log "[3] Running Zoom"
    if mp=$(in_meeting); then
        log "  A meeting is in progress ($mp)."
    elif [ -n "$(zoom_pids)" ]; then
        log "  Zoom is open, no meeting."
    else
        log "  Zoom is not running."
    fi
    blocker=$(install_blocker)
    if [ -n "$blocker" ]; then
        log "  Deferring: $blocker"
        add_issue "$blocker"
        finish 2 "deferred: Zoom ${MAIN_VER:-not installed} < $LATEST."
    fi
    [ -n "$(zoom_pids)" ] && log "  Zoom will be quit just before the install$( [ "$FORCE_CLOSE" = "1" ] && echo " (FORCE_CLOSE=1)" )."

    if [ "$DRY_RUN" = "1" ]; then
        log "  [DRY_RUN] would install $LATEST_URL"
        finish 2 "dry run: Zoom ${MAIN_VER:-not installed} < $LATEST."
    fi

    log ""
    log "[4] Download and install"
    mkdir -p "$WORK_DIR"
    PKG="$WORK_DIR/ZoomInstallerIT.pkg"
    STEP_LOG="$LOG_DIR/zoom_update_download.log"; : > "$STEP_LOG"
    if ! run_limited "$DOWNLOAD_TIMEOUT" curl -fsSL --retry 2 -o "$PKG" "$LATEST_URL" || [ ! -s "$PKG" ]; then
        add_issue "download failed -- $STEP_LOG"
        finish 1 "could not download $LATEST_URL."
    fi
    log "  Downloaded $(wc -c < "$PKG" | tr -d ' ') bytes."
    SIG_LOG="$LOG_DIR/zoom_update_signature.log"
    pkgutil --check-signature "$PKG" > "$SIG_LOG" 2>&1
    SIGNER=$(signer_from_pkgutil < "$SIG_LOG")
    if ! signature_is_zoom < "$SIG_LOG"; then
        log "  pkgutil --check-signature said:"
        while IFS= read -r l; do log "    $l"; done < "$SIG_LOG"
        add_issue "package is not signed by Zoom's Developer ID Installer (team $ZOOM_TEAM_ID); signer: ${SIGNER:-none}"
        finish 1 "refused to install an unverified package."
    fi
    log "  Signature: $SIGNER"

    # A meeting can start, or Zoom be opened, during a long download.
    blocker=$(install_blocker)
    if [ -n "$blocker" ]; then
        log "  Deferring: $blocker"
        add_issue "$blocker"
        finish 2 "deferred: Zoom ${MAIN_VER:-not installed} < $LATEST."
    fi
    REOPEN_USER=""
    if [ -n "$(zoom_pids)" ]; then
        REOPEN_USER=$(console_user) || REOPEN_USER=""
        if ! quit_zoom; then
            add_issue "Zoom would not quit (pid $(zoom_pids | tr '\n' ' ' | sed 's/ $//')); Zoom's installer does not update a running Zoom"
            finish 2 "deferred: Zoom ${MAIN_VER:-not installed} < $LATEST."
        fi
        log "  Zoom closed."
    fi

    STEP_LOG="$LOG_DIR/zoom_update_installer.log"; : > "$STEP_LOG"
    touch "$WORK_DIR/install.start"
    run_limited "$INSTALL_TIMEOUT" installer -pkg "$PKG" -target /
    irc=$?
    tail -n 15 "$STEP_LOG" | while IFS= read -r l; do log "    $l"; done
    log "  installer exit $irc"

    log ""
    log "[5] Verify"
    MAIN_VER=$(app_version "$MAIN_APP")
    if [ -n "$MAIN_VER" ] && version_ge "$MAIN_VER" "$LATEST"; then
        log "  $MAIN_APP  $MAIN_VER  OK"
    else
        add_issue "after install $MAIN_APP is ${MAIN_VER:-missing}, not $LATEST (installer exit $irc) -- $STEP_LOG"
        # Zoom's preinstall truncates its log, so a file not older than the
        # marker is this run's.
        if [ -f "$ZOOM_INSTALL_LOG" ] && ! [ "$ZOOM_INSTALL_LOG" -ot "$WORK_DIR/install.start" ]; then
            log "  Zoom's own log ($ZOOM_INSTALL_LOG), last 25 lines:"
            tail -n 25 "$ZOOM_INSTALL_LOG" | while IFS= read -r l; do log "    $l"; done
            cause=$(zoom_install_cause < "$ZOOM_INSTALL_LOG")
            [ -n "$cause" ] && add_issue "$cause"
        else
            log "  $ZOOM_INSTALL_LOG was not written by this install."
        fi
        finish 2 "Zoom not verified at $LATEST."
    fi
    if [ -n "$REOPEN_USER" ]; then
        STEP_LOG="$LOG_DIR/zoom_update_quit.log"
        if run_limited 30 as_user "$REOPEN_USER" open -a "$MAIN_APP"; then
            log "  Reopened Zoom for $REOPEN_USER."
        else
            log "  Could not reopen Zoom for $REOPEN_USER (not required for the fix)."
        fi
    fi
fi

if [ -n "$OLD_USER" ]; then
    log ""
    log "[6] Per-user copies"
    while IFS='|' read -r ua uv; do
        [ -n "$ua" ] || continue
        if [ "$REMOVE_USER_COPIES" != "1" ]; then
            log "  KEEP     $ua (${uv:-?}) -- REMOVE_USER_COPIES=0"
            add_issue "$ua is ${uv:-unreadable} (< $LATEST); remove it, $MAIN_APP is current"
        elif pgrep -f "$ua/Contents/MacOS/" >/dev/null 2>&1; then
            log "  KEEP     $ua (${uv:-?}) -- running; removed on a later run"
            add_issue "$ua is ${uv:-unreadable} and was running"
        elif [ "$DRY_RUN" = "1" ]; then
            log "  [DRY_RUN] would remove $ua (${uv:-?})"
            add_issue "dry run: $ua not removed"
        elif rm -rf "$ua" && [ ! -e "$ua" ]; then
            log "  REMOVED  $ua (${uv:-?}); $MAIN_APP $MAIN_VER is current"
        else
            log "  FAILED   could not remove $ua"
            add_issue "could not remove $ua"
        fi
    done <<EOF
$OLD_USER
EOF
fi

[ -n "$ISSUES" ] && finish 2 "Zoom ${MAIN_VER:-not installed}; the items above still need attention."
finish 0 "Zoom ${MAIN_VER} is current (latest $LATEST)."
