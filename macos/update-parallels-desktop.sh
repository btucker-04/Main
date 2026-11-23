#!/bin/bash
# =============================================================================
# update-parallels-desktop.sh  (v3)
# Remediates : Parallels Desktop below a fixed release (plugin 347968
#              "Parallels Desktop < 27.0.0 Local Privilege Escalation (macOS)",
#              CVE-2026-90894, armb-09 2026-11-23 with 19.3.0), and later
#              Parallels advisories of the same shape (raise MIN_VERSION).
# Platform   : macOS (bash 3.2 compatible) | Deploy: Mosyle (runs as root)
#
# No pinned build. Parallels publishes one update feed per major version, the
# feed the app itself checks:
#   https://update.parallels.com/desktop/v<major>/parallels/parallels_updates.xml
# Each names the newest build of that major and its DMG (27.1.0-58756 on
# 2026-11-23). Majors skip numbers (19, 20, 26, 27 exist; 22-25 and 28+ are
# 404; v21 serves the 20.2.1 feed and is skipped), so the installed major and
# every major up to a few past MIN_VERSION's are read.
# MIN_VERSION is the finding's fixed version: a floor, not the target.
#   - The installed major's newest build is >= MIN_VERSION: update within the
#     major (same license).
#   - Otherwise move to the newest major (ALLOW_MAJOR_UPGRADE=1). LICENSE: a
#     perpetual key for an older major does not activate a newer one; a
#     subscription (Standard / Pro / Business) does. The license is logged
#     before and after; VMs do not start until Parallels is licensed.
#
# Steps:
#   1. Inventory /Applications/Parallels Desktop.app (version and build).
#   2. Read the feeds and pick the target. Current -> exit 0, no download.
#   3. Parallels Desktop open or a VM running -> exit 2 unless FORCE_CLOSE=1,
#      which suspends each running VM as its owner (prlctl suspend) and quits
#      the app. A VM is never killed: one that will not suspend defers.
#   4. Download the DMG, mount it read-only, check the app's version and build,
#      codesign --verify --deep --strict, the Developer ID team 4C6364ACXT,
#      the CPU (27.x is Apple silicon only) and the minimum macOS.
#      The app is hidden on the DMG (UF_HIDDEN + com.apple.FinderInfo on the
#      bundle root), which codesign --strict rejects as "detritus" (armb-09,
#      macOS 27.2). It is copied to a staging folder and those two are cleared
#      on the bundle root only, as inittool does after its copy; the checks run
#      on that copy, and that copy is what gets installed.
#      If only --deep fails, the app is accepted when the top-level strict
#      verify passes and Gatekeeper (spctl) calls it a notarized Developer ID
#      app from team 4C6364ACXT. codesign's errors are copied into this log.
#   5. Install with Parallels' own tool, as its installer does:
#        inittool install -t "/Applications/Parallels Desktop.app" -b <staged app> -s
#      It stops the Parallels services and Mac VMs, deletes the old app, copies
#      the new one, sets owners and permissions, and starts the services. A
#      clone of the old app is kept until the new one reads the target, and is
#      put back if inittool leaves no app behind.
#   6. Re-read the version; log the license.
# inittool installs Rosetta on Apple silicon (softwareupdate --agree-to-license)
# as part of every Parallels install.
#
# CONFIG -- Mosyle passes no environment variables. Edit the block below
# before paste, or pass the same names from a terminal (DRY_RUN=1 ...).
# APP_DIR, LOG_DIR, WORK_DIR, BACKUP_DIR, OS_VERSION and HOST_ARCH may be set
# for tests.
#
# Exit: 0 = Parallels Desktop is current (or not installed)
#       2 = deferred (in use), reboot required, dry run, major upgrade not
#           allowed, or no fixed build runs on this Mac -- see the RESULT line
#       1 = could not run (feed, download, signature or install failed)
# =============================================================================

set -uo pipefail
HOME="${HOME:-/var/root}"
export HOME

# =============================================================================
CFG_DRY_RUN="0"
# Suspend running VMs (as their owner) and quit Parallels Desktop instead of
# deferring. A VM that will not suspend is left running and the run defers.
CFG_FORCE_CLOSE="0"
# Seconds to wait for the app to quit and the VMs to stop after suspend.
CFG_QUIT_TIMEOUT="60"
# Seconds allowed for one VM to suspend.
CFG_SUSPEND_TIMEOUT="300"
# The finding's fixed version. Builds below it are vulnerable.
CFG_MIN_VERSION="27.0.0"
# Allow moving to a newer major when the installed major has no fixed build.
# Needs a license that covers the new major (see LICENSE above).
CFG_ALLOW_MAJOR_UPGRADE="1"
CFG_FEED_BASE="https://update.parallels.com/desktop"
# Majors probed above max(installed major, MIN_VERSION's major).
CFG_MAJOR_LOOKAHEAD="6"
# Seconds allowed for the download (about 160 MB) and for inittool.
CFG_DOWNLOAD_TIMEOUT="1800"
CFG_INSTALL_TIMEOUT="1200"
# =============================================================================
DRY_RUN="${DRY_RUN:-$CFG_DRY_RUN}"
FORCE_CLOSE="${FORCE_CLOSE:-$CFG_FORCE_CLOSE}"
QUIT_TIMEOUT="${QUIT_TIMEOUT:-$CFG_QUIT_TIMEOUT}"
SUSPEND_TIMEOUT="${SUSPEND_TIMEOUT:-$CFG_SUSPEND_TIMEOUT}"
MIN_VERSION="${MIN_VERSION:-$CFG_MIN_VERSION}"
ALLOW_MAJOR_UPGRADE="${ALLOW_MAJOR_UPGRADE:-$CFG_ALLOW_MAJOR_UPGRADE}"
FEED_BASE="${FEED_BASE:-$CFG_FEED_BASE}"
MAJOR_LOOKAHEAD="${MAJOR_LOOKAHEAD:-$CFG_MAJOR_LOOKAHEAD}"
DOWNLOAD_TIMEOUT="${DOWNLOAD_TIMEOUT:-$CFG_DOWNLOAD_TIMEOUT}"
INSTALL_TIMEOUT="${INSTALL_TIMEOUT:-$CFG_INSTALL_TIMEOUT}"

APP_DIR="${APP_DIR:-/Applications}"
LOG_DIR="${LOG_DIR:-/var/log/composecure}"
LOG_FILE="$LOG_DIR/parallels_update.log"
WORK_DIR="${WORK_DIR:-/var/tmp/parallels_update_$$}"
BACKUP_DIR="${BACKUP_DIR:-/var/tmp/parallels_backup_$$}"
PD_TEAM_ID="4C6364ACXT"
PD_APP="$APP_DIR/Parallels Desktop.app"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }

is_version() { echo "$1" | grep -Eq '^[0-9]+\.[0-9]+(\.[0-9]+)*$'; }

# True when $1 >= $2, field by field; missing fields count as 0.
version_ge() {
    awk -v a="$1" -v b="$2" 'BEGIN {
        na = split(a, x, "."); nb = split(b, y, "."); n = (na > nb) ? na : nb
        for (i = 1; i <= n; i++) {
            if ((x[i] + 0) > (y[i] + 0)) exit 0
            if ((x[i] + 0) < (y[i] + 0)) exit 1
        }
        exit 0
    }'
}

# parallels_updates.xml on stdin -> version|build|url (27.1.0|58756|https://...).
# Nothing when the feed lacks any of them. <FileSize> is ignored: it reads
# 305626.0 in every feed, whatever the DMG's real size.
feed_item() {
    awk '
    function tag(t,   s) {
        if (!match($0, "<" t ">[^<]*</" t ">")) return ""
        s = substr($0, RSTART + length(t) + 2, RLENGTH - 2 * length(t) - 5)
        gsub(/^[ \t]+|[ \t]+$/, "", s)
        return s
    }
    ma == "" { ma = tag("Major") }
    mi == "" { mi = tag("Minor") }
    sm == "" { sm = tag("SubMinor") }
    bd == "" { bd = tag("SubSubMinor") }
    url == "" { url = tag("FilePath") }
    END {
        if (ma ~ /^[0-9]+$/ && mi ~ /^[0-9]+$/ && sm ~ /^[0-9]+$/ && bd ~ /^[0-9]+$/ && url != "")
            print ma "." mi "." sm "|" bd "|" url
    }'
}

# $1 = url, $2 = version, $3 = build. Only Parallels' own download host, and
# the file named for exactly this build.
dmg_url_ok() {
    case "$1" in
        https://download.parallels.com/*/ParallelsDesktop-"$2-$3".dmg) return 0 ;;
    esac
    return 1
}

# Feed lines on stdin (major|version|build|url); $1 = installed version (may
# be empty), $2 = MIN_VERSION, $3 = ALLOW_MAJOR_UPGRADE.
# Prints version|build|url. 1 = no feed has a build >= $2; 3 = only a newer
# major has one and $3 is not 1.
pick_target() {
    pt_major=""
    [ -n "$1" ] && pt_major="${1%%.*}"
    pt_same=""
    pt_new=""
    while IFS='|' read -r pt_m pt_v pt_b pt_u; do
        is_version "$pt_v" || continue
        pt_line="$pt_v|$pt_b|$pt_u"
        if [ -z "$pt_new" ] || version_ge "$pt_v" "${pt_new%%|*}"; then pt_new="$pt_line"; fi
        [ "$pt_m" = "$pt_major" ] && pt_same="$pt_line"
    done
    if [ -n "$pt_same" ] && version_ge "${pt_same%%|*}" "$2"; then echo "$pt_same"; return 0; fi
    [ -n "$pt_new" ] && version_ge "${pt_new%%|*}" "$2" || return 1
    if [ -n "$pt_major" ] && [ "${pt_new%%.*}" != "$pt_major" ] && [ "$3" != "1" ]; then return 3; fi
    echo "$pt_new"
}

# `ps -axo pid=,user=,command=` on stdin; $1 = the app bundle.
# -> pid|user|gui for the Parallels Desktop window, pid|user|vm for a running
# VM (Parallels VM.app / Parallels Mac VM.app). The services are not listed:
# inittool stops them itself.
busy_procs() {
    awk -v app="$1/Contents/MacOS/" '{
        pid = $1; usr = $2; cmd = $0
        sub(/^[ \t]*[0-9]+[ \t]+[^ \t]+[ \t]+/, "", cmd)
        if (index(cmd, app) != 1) next
        rest = substr(cmd, length(app) + 1)
        if (rest ~ /^prl_client_app( |$)/) print pid "|" usr "|gui"
        else if (rest ~ /^Parallels (Mac )?VM\.app\//) print pid "|" usr "|vm"
    }'
}

# `prlctl list --all --output uuid,status --no-header` on stdin -> the UUID
# of every VM that is running or paused (both hold a live VM process).
active_vms() {
    awk '{
        u = ""; s = ""
        for (i = 1; i <= NF; i++) {
            if ($i ~ /^\{[0-9A-Fa-f-]+\}$/) u = $i
            else if ($i == "running" || $i == "paused") s = $i
        }
        if (u != "" && s != "") print u
    }'
}

# `codesign -dv --verbose=2` output on stdin -> 0 when it is a Developer ID
# Application signature for Parallels' team ID.
signature_is_parallels() {
    sp_out=$(cat)
    echo "$sp_out" | grep -q "^TeamIdentifier=$PD_TEAM_ID\$" || return 1
    echo "$sp_out" | grep -qE "^Authority=Developer ID Application: .+ \\($PD_TEAM_ID\\)\$" || return 1
}

# `spctl --assess --type execute -vv` output on stdin -> 0 when Gatekeeper
# accepts it as a notarized Developer ID app from Parallels' team.
gatekeeper_accepts() {
    ga_out=$(cat)
    echo "$ga_out" | grep -qE ': accepted$' || return 1
    echo "$ga_out" | grep -qE '^source=Notarized Developer ID$' || return 1
    echo "$ga_out" | grep -qE "^origin=Developer ID Application: .+ \\($PD_TEAM_ID\\)\$" || return 1
}

# `file -b` output for a Mach-O on stdin -> its architectures, space separated.
# /usr/bin/lipo is a Command Line Tools stub, so `file` is used instead.
macho_archs() {
    grep -oE '(arm64e?|x86_64)' | sed 's/^arm64e$/arm64/' | sort -u | tr '\n' ' ' | sed 's/ $//'
}

# $1 = architectures ("arm64 x86_64"), $2 = this Mac's (arm64 | x86_64).
archs_include() { case " $1 " in *" $2 "*) return 0 ;; esac; return 1; }

inittool_rc_text() {
    case "$1" in
        0) echo "ok" ;;
        1) echo "broken installation" ;;
        2) echo "superuser required" ;;
        3) echo "incorrect command line" ;;
        4) echo "path does not exist" ;;
        6) echo "could not remove the previous version" ;;
        8) echo "macOS too old or a system tool is missing" ;;
        9) echo "not enough disk space" ;;
        10) echo "another account has UID 0" ;;
        11) echo "installed; reboot required (the old services would not stop)" ;;
        124) echo "time limit reached" ;;
        *) echo "exit $1" ;;
    esac
}

# License keys and serials out of `prlsrvctl info --license` before logging.
mask_license() {
    sed -E -e 's/((key|serial)[=:] *"?)[^" ]+/\1<masked>/g' \
        -e 's/[A-Z0-9]{6}(-[A-Z0-9]{6}){4}/<masked>/g' | LC_ALL=C tr -cd '\11\12\40-\176'
}

descendants() (
    for d_child in $(pgrep -P "$1" 2>/dev/null); do
        descendants "$d_child"
        echo "$d_child"
    done
)

if [ "${PARALLELS_UPDATE_SELFTEST:-0}" = "1" ]; then
    return 0 2>/dev/null || exit 0
fi

mkdir -p "$LOG_DIR"
cd /tmp || exit 1
ISSUES=""
add_issue() { ISSUES="${ISSUES}${ISSUES:+
}$1"; }
NOTES=""
add_note() { NOTES="${NOTES}${NOTES:+
}$1"; }
MOUNTED=""
CAF_PID=""
BACKUP_APP=""
cleanup() {
    [ -n "$MOUNTED" ] && hdiutil detach -force "$MOUNTED" >/dev/null 2>&1
    [ -n "$CAF_PID" ] && kill "$CAF_PID" 2>/dev/null
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

plist_value() {
    pv_plist="$1/Contents/Info.plist"
    [ -f "$pv_plist" ] || return 0
    defaults read "$pv_plist" "$2" 2>/dev/null
    return 0
}
app_version() {
    av_v=$(plist_value "$1" CFBundleShortVersionString)
    is_version "$av_v" && echo "$av_v"
    return 0
}
app_build() {
    ab_b=$(plist_value "$1" CFBundleVersion)
    echo "$ab_b" | grep -Eq '^[0-9]+$' && echo "$ab_b"
    return 0
}

# Run "$@" with a wall-clock limit ($1 seconds); output to $STEP_LOG.
run_limited() {
    rl_limit="$1"; shift
    rl_start=$(date +%s)
    "$@" >>"$STEP_LOG" 2>&1 </dev/null &
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

# Last lines of $1 into the main log, ASCII only.
log_tail() {
    LC_ALL=C tr -cd '\11\12\40-\176' < "$1" | grep -v '^[[:space:]]*$' | tail -n "$2" | while IFS= read -r lt_l; do
        log "    | $lt_l"
    done
}

current_busy() {
    ps -axo pid=,user=,command= 2>/dev/null | busy_procs "$PD_APP"
}

describe_busy() {
    db_gui=$(printf '%s\n' "$1" | grep -c '|gui$')
    db_vm=$(printf '%s\n' "$1" | grep -c '|vm$')
    db_users=$(printf '%s\n' "$1" | cut -d'|' -f2 | grep . | sort -u | tr '\n' ' ' | sed 's/ $//')
    echo "app open: $db_gui, VM processes: $db_vm (user: ${db_users:-?})"
}

log_license() {
    ll_bin="$PD_APP/Contents/MacOS/prlsrvctl"
    [ -x "$ll_bin" ] || { log "  License: prlsrvctl not found"; return 0; }
    STEP_LOG="$LOG_DIR/parallels_update_license_$1.log"; : > "$STEP_LOG"
    run_limited 60 "$ll_bin" info --license
    ll_rc=$?
    ll_out="$WORK_DIR/license_$1.txt"
    mask_license < "$STEP_LOG" > "$ll_out"
    : > "$STEP_LOG"
    cat "$ll_out" >> "$STEP_LOG"
    if [ "$ll_rc" -ne 0 ] || ! grep -q . "$ll_out"; then
        log "  License ($1): not readable (prlsrvctl exit $ll_rc)"
        return 0
    fi
    head -n 6 "$ll_out" | while IFS= read -r ll_l; do log "  License ($1): $ll_l"; done
}

# Suspend every running VM of each user in $1 and quit the app. 0 = nothing of
# Parallels Desktop is running any more.
close_parallels() {
    cp_prlctl="$PD_APP/Contents/MacOS/prlctl"
    for cp_user in $(printf '%s\n' "$1" | cut -d'|' -f2 | grep . | sort -u); do
        STEP_LOG="$LOG_DIR/parallels_update_vms.log"; : > "$STEP_LOG"
        if ! run_limited 60 sudo -u "$cp_user" -H "$cp_prlctl" list --all --output uuid,status --no-header; then
            add_issue "could not list $cp_user's VMs -- $STEP_LOG"
            continue
        fi
        for cp_vm in $(active_vms < "$STEP_LOG"); do
            log "  Suspending VM $cp_vm ($cp_user) -- FORCE_CLOSE=1."
            STEP_LOG="$LOG_DIR/parallels_update_suspend.log"
            if ! run_limited "$SUSPEND_TIMEOUT" sudo -u "$cp_user" -H "$cp_prlctl" suspend "$cp_vm"; then
                add_issue "VM $cp_vm ($cp_user) did not suspend -- $STEP_LOG"
            fi
        done
    done
    cp_gui=$(current_busy | grep '|gui$' | cut -d'|' -f1 | tr '\n' ' ' | sed 's/ $//')
    if [ -n "$cp_gui" ]; then
        log "  Quitting Parallels Desktop (pid $cp_gui)."
        # shellcheck disable=SC2086
        kill $cp_gui 2>/dev/null
    fi
    cp_end=$(( $(date +%s) + QUIT_TIMEOUT ))
    while [ -n "$(current_busy)" ] && [ "$(date +%s)" -lt "$cp_end" ]; do sleep 1; done
    cp_gui=$(current_busy | grep '|gui$' | cut -d'|' -f1 | tr '\n' ' ' | sed 's/ $//')
    if [ -n "$cp_gui" ] && [ -z "$(current_busy | grep '|vm$')" ]; then
        log "  Parallels Desktop did not quit; KILL (no VM is running)."
        # shellcheck disable=SC2086
        kill -9 $cp_gui 2>/dev/null
        sleep 2
    fi
    [ -z "$(current_busy)" ]
}

# Keep the old app for rollback: an APFS clone when possible, else a copy.
backup_app() {
    rm -rf "$BACKUP_DIR"
    mkdir -p "$BACKUP_DIR" || return 1
    STEP_LOG="$LOG_DIR/parallels_update_backup.log"; : > "$STEP_LOG"
    if run_limited 120 cp -Rpc "$PD_APP" "$BACKUP_DIR/"; then
        BACKUP_APP="$BACKUP_DIR/Parallels Desktop.app"
        return 0
    fi
    rm -rf "$BACKUP_DIR"; mkdir -p "$BACKUP_DIR"
    if run_limited 900 ditto "$PD_APP" "$BACKUP_DIR/Parallels Desktop.app"; then
        BACKUP_APP="$BACKUP_DIR/Parallels Desktop.app"
        return 0
    fi
    rm -rf "$BACKUP_DIR"
    return 1
}
drop_backup() { [ -n "$BACKUP_APP" ] && rm -rf "$BACKUP_DIR"; BACKUP_APP=""; }

finish() {
    log ""
    log "================ SUMMARY ================"
    if [ -n "$ISSUES" ]; then
        log "Problems:"
        printf '%s\n' "$ISSUES" | while IFS= read -r l; do log "  - $l"; done
    fi
    if [ -n "$NOTES" ]; then
        log "Notes:"
        printf '%s\n' "$NOTES" | while IFS= read -r l; do log "  - $l"; done
    fi
    log "RESULT: $2"
    log "===== END ====="
    exit "$1"
}

OS_VERSION="${OS_VERSION:-$(sw_vers -productVersion 2>/dev/null)}"
if [ -z "${HOST_ARCH:-}" ]; then
    if [ "$(sysctl -n hw.optional.arm64 2>/dev/null)" = "1" ]; then HOST_ARCH=arm64; else HOST_ARCH=x86_64; fi
fi
log "===== update-parallels-desktop.sh START ====="
log "Host: $(hostname -s 2>/dev/null || hostname)   macOS ${OS_VERSION:-?}   $HOST_ARCH"
log "DryRun=$DRY_RUN  ForceClose=$FORCE_CLOSE  MinVersion=$MIN_VERSION  AllowMajorUpgrade=$ALLOW_MAJOR_UPGRADE"

if ! is_version "$MIN_VERSION"; then
    finish 1 "MIN_VERSION '$MIN_VERSION' is not a version."
fi
if command -v caffeinate >/dev/null 2>&1; then
    caffeinate -i -s -w $$ >/dev/null 2>&1 &
    CAF_PID=$!
    # Without disown, bash prints "Terminated: 15 caffeinate" when cleanup kills it.
    disown "$CAF_PID" 2>/dev/null
fi

log ""
log "[1] Installed"
if [ ! -d "$PD_APP" ]; then
    finish 0 "Parallels Desktop is not installed ($PD_APP). Nothing to do."
fi
IV=$(app_version "$PD_APP")
IB=$(app_build "$PD_APP")
log "  $PD_APP  ${IV:-version unreadable}${IB:+ (build $IB)}"
VULNERABLE=1
if [ -n "$IV" ] && version_ge "$IV" "$MIN_VERSION"; then VULNERABLE=0; fi

log ""
log "[2] Latest builds"
mkdir -p "$WORK_DIR"
MIN_MAJOR="${MIN_VERSION%%.*}"
LO="${IV%%.*}"
[ -n "$LO" ] || LO="$MIN_MAJOR"
HI="$LO"
[ "$MIN_MAJOR" -gt "$HI" ] && HI="$MIN_MAJOR"
HI=$(( HI + MAJOR_LOOKAHEAD ))
FEEDS=""
FEED_FAIL=""
STEP_LOG="$LOG_DIR/parallels_update_feed.log"; : > "$STEP_LOG"
m="$LO"
while [ "$m" -le "$HI" ]; do
    f="$WORK_DIR/feed_v$m.xml"
    # curl's own limits: up to 20 small requests, and run_limited polls per second.
    curl -fsS --retry 1 --connect-timeout 15 --max-time 60 -o "$f" \
        "$FEED_BASE/v$m/parallels/parallels_updates.xml" >>"$STEP_LOG" 2>&1 </dev/null
    rc=$?
    if [ "$rc" -eq 0 ]; then
        item=$(feed_item < "$f")
        if [ -n "$item" ] && [ "${item%%.*}" = "$m" ]; then
            log "  feed v$m: ${item%%|*} build $(echo "$item" | cut -d'|' -f2)"
            FEEDS="$FEEDS
$m|$item"
        elif [ -n "$item" ]; then
            # v21's URL serves the 20.2.1 feed (2026-11-23).
            log "  feed v$m: serves ${item%%|*} (another major's feed); skipped"
        else
            FEED_FAIL="$FEED_FAIL v$m(unreadable)"
        fi
    elif [ "$rc" -ne 22 ]; then
        FEED_FAIL="$FEED_FAIL v$m(curl $rc)"
    fi
    m=$(( m + 1 ))
done
if [ -n "$FEED_FAIL" ]; then
    add_issue "could not read the update feeds:$FEED_FAIL (offline or a proxy block page?) -- $STEP_LOG"
    finish 1 "latest Parallels Desktop build unknown -- nothing changed."
fi
if [ -z "$FEEDS" ]; then
    add_issue "no update feed between v$LO and v$HI under $FEED_BASE"
    finish 1 "latest Parallels Desktop build unknown -- nothing changed."
fi

PICK=$(printf '%s\n' "$FEEDS" | grep . | pick_target "$IV" "$MIN_VERSION" "$ALLOW_MAJOR_UPGRADE")
prc=$?
if [ "$prc" -eq 3 ]; then
    add_issue "Parallels Desktop ${IV%%.*} has no build >= $MIN_VERSION; only a newer major does, and ALLOW_MAJOR_UPGRADE=0 (check the license covers it, then set 1)"
    finish 2 "Parallels Desktop $IV not updated: needs a major upgrade."
fi
if [ "$prc" -ne 0 ] || [ -z "$PICK" ]; then
    add_issue "no Parallels Desktop build >= $MIN_VERSION in the feeds v$LO..v$HI"
    finish 2 "Parallels Desktop ${IV:-?} not updated: no fixed build is published."
fi
IFS='|' read -r TARGET T_BUILD T_URL <<EOF
$PICK
EOF
log "  Target: $TARGET build $T_BUILD  ($T_URL)"
if ! dmg_url_ok "$T_URL" "$TARGET" "$T_BUILD"; then
    add_issue "the feed's DMG URL $T_URL is not ParallelsDesktop-$TARGET-$T_BUILD.dmg on download.parallels.com"
    finish 1 "refused an unexpected download location -- nothing changed."
fi
if [ -n "$IV" ] && [ -n "$IB" ] && version_ge "$IV.$IB" "$TARGET.$T_BUILD"; then
    finish 0 "Parallels Desktop is current ($IV build $IB)."
fi
MAJOR_CHANGE=0
[ "${TARGET%%.*}" != "${IV%%.*}" ] && MAJOR_CHANGE=1
if [ "$MAJOR_CHANGE" = "1" ]; then
    log "  Major upgrade: ${IV:-?} -> $TARGET (no build of ${IV%%.*} is >= $MIN_VERSION)."
fi
[ "$VULNERABLE" = "0" ] && log "  $IV is not below $MIN_VERSION; updating to the newer build $TARGET-$T_BUILD."
log_license before

log ""
log "[3] In use"
BUSY=$(current_busy)
if [ -n "$BUSY" ]; then
    log "  Parallels Desktop is in use: $(describe_busy "$BUSY")."
    if [ "$FORCE_CLOSE" != "1" ]; then
        if [ "$VULNERABLE" = "0" ]; then
            add_note "newer build $TARGET-$T_BUILD available; not installed while Parallels Desktop is in use"
            finish 0 "Parallels Desktop $IV is not below $MIN_VERSION; the newer build waits until it is closed."
        fi
        add_issue "Parallels Desktop ${IV:-?} is in use ($(describe_busy "$BUSY")); re-run when it is closed, or set FORCE_CLOSE=1 (VMs are suspended, not stopped)"
        finish 2 "deferred: Parallels Desktop is in use; nothing changed."
    fi
    log "  FORCE_CLOSE=1: running VMs will be suspended after the download checks."
else
    log "  Not running."
fi
if [ "$DRY_RUN" = "1" ]; then
    log "  [DRY_RUN] would install $TARGET-$T_BUILD over ${IV:-?}${IB:+-$IB} with inittool."
    add_issue "dry run: nothing changed"
    finish 2 "dry run: target $TARGET-$T_BUILD."
fi

log ""
log "[4] Download and check"
DMG="$WORK_DIR/ParallelsDesktop.dmg"
STEP_LOG="$LOG_DIR/parallels_update_download.log"; : > "$STEP_LOG"
if ! run_limited "$DOWNLOAD_TIMEOUT" curl -fsSL --retry 2 -o "$DMG" "$T_URL" || [ ! -s "$DMG" ]; then
    add_issue "download failed -- $STEP_LOG"
    finish 1 "could not download $T_URL."
fi
log "  Downloaded $(wc -c < "$DMG" | tr -d ' ') bytes."
if [ "$(tail -c 512 "$DMG" | head -c 4)" != "koly" ]; then
    add_issue "the download is not a disk image (no UDIF trailer; proxy block page or truncated)"
    finish 1 "refused to install an unverified download."
fi
MNT="$WORK_DIR/mnt"
mkdir -p "$MNT"
STEP_LOG="$LOG_DIR/parallels_update_mount.log"; : > "$STEP_LOG"
if ! run_limited 300 hdiutil attach -nobrowse -readonly -noautoopen -mountpoint "$MNT" "$DMG"; then
    add_issue "hdiutil could not mount the DMG (checksum failure?) -- $STEP_LOG"
    finish 1 "could not open the Parallels Desktop DMG."
fi
MOUNTED="$MNT"
SRC_APP="$MNT/Parallels Desktop.app"
SRC_VER=$(app_version "$SRC_APP")
SRC_BUILD=$(app_build "$SRC_APP")
if [ "$SRC_VER" != "$TARGET" ] || [ "$SRC_BUILD" != "$T_BUILD" ]; then
    add_issue "the DMG's Parallels Desktop.app is ${SRC_VER:-missing}${SRC_BUILD:+-$SRC_BUILD}, not $TARGET-$T_BUILD"
    finish 1 "refused to install: the DMG does not hold $TARGET-$T_BUILD."
fi
# Parallels hides the app on its DMG so only Install.app shows: UF_HIDDEN and
# com.apple.FinderInfo on the bundle root. codesign --strict rejects that as
# "resource fork, Finder information, or similar detritus not allowed"
# (armb-09, 27.1.0). inittool clears exactly these two after its own copy, so
# do the same on a staged copy, verify the copy, and install from it.
STAGE_APP="$WORK_DIR/stage/Parallels Desktop.app"
mkdir -p "$WORK_DIR/stage"
STEP_LOG="$LOG_DIR/parallels_update_stage.log"; : > "$STEP_LOG"
if ! run_limited 900 ditto --noqtn "$SRC_APP" "$STAGE_APP"; then
    add_issue "could not copy the DMG's app to $STAGE_APP -- $STEP_LOG"
    finish 1 "could not stage Parallels Desktop $TARGET."
fi
chflags nohidden "$STAGE_APP" >>"$STEP_LOG" 2>&1
xattr -d com.apple.FinderInfo "$STAGE_APP" >>"$STEP_LOG" 2>&1
SRC_APP="$STAGE_APP"
log "  Staged the app at $STAGE_APP (bundle root unhidden, as inittool does)."
STEP_LOG="$LOG_DIR/parallels_update_signature.log"; : > "$STEP_LOG"
if run_limited 900 codesign --verify --deep --strict "$SRC_APP"; then
    log "  codesign --verify --deep --strict: ok"
else
    log "  codesign --verify --deep --strict failed:"
    log_tail "$STEP_LOG" 8
    STEP_LOG="$LOG_DIR/parallels_update_gatekeeper.log"; : > "$STEP_LOG"
    if run_limited 300 codesign --verify --strict "$SRC_APP" &&
       run_limited 300 spctl --assess --type execute -vv "$SRC_APP" &&
       gatekeeper_accepts < "$STEP_LOG"; then
        log "  Top-level strict verify ok; Gatekeeper: notarized Developer ID, team $PD_TEAM_ID."
        add_note "codesign --deep --strict failed (lines above); installed on the top-level strict verify plus Gatekeeper's notarization check"
    else
        log "  Top-level verify / Gatekeeper:"
        log_tail "$STEP_LOG" 8
        add_issue "the DMG's Parallels Desktop.app fails codesign --deep --strict and is not accepted by the top-level verify plus Gatekeeper -- $LOG_DIR/parallels_update_signature.log, $STEP_LOG"
        finish 1 "refused to install an app whose signature does not verify."
    fi
fi
SIG_INFO="$WORK_DIR/codesign.txt"
codesign -dv --verbose=2 "$SRC_APP" > "$SIG_INFO" 2>&1
if ! signature_is_parallels < "$SIG_INFO"; then
    while IFS= read -r l; do log "    $l"; done < "$SIG_INFO"
    add_issue "Parallels Desktop.app is not signed with Parallels' Developer ID (team $PD_TEAM_ID)"
    finish 1 "refused to install an unverified app."
fi
log "  Signature: $(sed -n 's/^Authority=\(Developer ID Application:.*\)$/\1/p' "$SIG_INFO" | head -n 1)"
SRC_ARCHS=$(file -b "$SRC_APP/Contents/MacOS/prl_client_app" 2>/dev/null | macho_archs)
log "  Built for: ${SRC_ARCHS:-unknown}"
if [ -n "$SRC_ARCHS" ] && ! archs_include "$SRC_ARCHS" "$HOST_ARCH"; then
    add_issue "Parallels Desktop $TARGET runs on $SRC_ARCHS only and this Mac is $HOST_ARCH: no fixed build runs here. Remove Parallels Desktop or replace the Mac"
    finish 2 "Parallels Desktop ${IV:-?} not updated: $TARGET does not run on $HOST_ARCH."
fi
SRC_MINOS=$(plist_value "$SRC_APP" LSMinimumSystemVersion)
if is_version "$SRC_MINOS" && [ -n "$OS_VERSION" ] && ! version_ge "$OS_VERSION" "$SRC_MINOS"; then
    add_issue "Parallels Desktop $TARGET needs macOS $SRC_MINOS or later; this Mac runs $OS_VERSION. Upgrade macOS, then re-run"
    finish 2 "Parallels Desktop ${IV:-?} not updated: macOS $OS_VERSION is too old for $TARGET."
fi
log "  Needs macOS ${SRC_MINOS:-?}; this Mac runs ${OS_VERSION:-?}."

log ""
log "[5] Install"
BUSY=$(current_busy)
if [ -n "$BUSY" ]; then
    if [ "$FORCE_CLOSE" != "1" ]; then
        add_issue "Parallels Desktop was opened during the download ($(describe_busy "$BUSY")); re-run when it is closed"
        finish 2 "deferred: Parallels Desktop is in use; nothing changed."
    fi
    if ! close_parallels "$BUSY"; then
        add_issue "Parallels Desktop is still in use after suspend and quit ($(describe_busy "$(current_busy)")); nothing changed"
        finish 2 "deferred: a VM would not suspend; nothing changed."
    fi
    log "  Parallels Desktop closed; VMs suspended."
fi
if backup_app; then
    log "  Kept the old app at $BACKUP_APP until the new one is verified."
else
    log "  Could not keep a copy of the old app -- $STEP_LOG (continuing; inittool replaces it in place)."
fi
STEP_LOG="$LOG_DIR/parallels_update_install.log"; : > "$STEP_LOG"
log "  inittool install -t \"$PD_APP\" -b \"$SRC_APP\" -s"
run_limited "$INSTALL_TIMEOUT" "$SRC_APP/Contents/MacOS/inittool" install -t "$PD_APP" -b "$SRC_APP" -s
IRC=$?
log "  inittool: $(inittool_rc_text "$IRC") (exit $IRC) -- $STEP_LOG"
[ "$IRC" -ne 0 ] && log_tail "$STEP_LOG" 15

log ""
log "[6] Verify"
NV=$(app_version "$PD_APP")
NB=$(app_build "$PD_APP")
if [ ! -d "$PD_APP" ] || [ -z "$NV" ]; then
    if [ -n "$BACKUP_APP" ] && [ -d "$BACKUP_APP" ]; then
        rm -rf "$PD_APP"
        if mv "$BACKUP_APP" "$PD_APP"; then
            rm -rf "$BACKUP_DIR"; BACKUP_APP=""
            add_issue "inittool ($(inittool_rc_text "$IRC")) left no usable app; the old ${IV:-?} was put back. Reboot, then re-run -- $LOG_DIR/parallels_update_install.log"
            finish 1 "Parallels Desktop not updated; the old version was restored."
        fi
        add_issue "inittool left no usable app and the old one could not be moved back; it is at $BACKUP_APP"
        finish 1 "Parallels Desktop is not installed after a failed update."
    fi
    add_issue "inittool ($(inittool_rc_text "$IRC")) left no usable app at $PD_APP and there is no copy to put back; reinstall Parallels Desktop"
    finish 1 "Parallels Desktop is not installed after a failed update."
fi
drop_backup
if ! version_ge "$NV.${NB:-0}" "$TARGET.$T_BUILD"; then
    log "  $PD_APP  $NV${NB:+ build $NB}  NOT CURRENT"
    add_issue "$PD_APP reads $NV${NB:+-$NB} after inittool ($(inittool_rc_text "$IRC")), not $TARGET-$T_BUILD -- $LOG_DIR/parallels_update_install.log"
    finish 1 "Parallels Desktop not updated."
fi
log "  $PD_APP  $NV build $NB  OK"
log_license after
if [ "$MAJOR_CHANGE" = "1" ]; then
    add_note "moved from Parallels Desktop ${IV%%.*} to ${TARGET%%.*}. A perpetual ${IV%%.*} key does not activate ${TARGET%%.*}; if the license lines above are not valid, VMs will not start until a ${TARGET%%.*} or subscription key is entered"
fi
if [ "$IRC" -eq 11 ]; then
    add_issue "the old Parallels services would not stop; reboot to finish (the new app is in place)"
    finish 2 "Parallels Desktop $NV-$NB installed; reboot required."
fi
if [ "$IRC" -ne 0 ]; then
    add_issue "inittool reported $(inittool_rc_text "$IRC") although the app reads $NV-$NB; open Parallels Desktop once to finish setup -- $LOG_DIR/parallels_update_install.log"
    finish 2 "Parallels Desktop $NV-$NB installed; setup not confirmed."
fi
finish 0 "Parallels Desktop is current ($NV build $NB)."
