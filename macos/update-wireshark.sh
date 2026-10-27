#!/bin/bash
# =============================================================================
# update-wireshark.sh  (v1)
# Remediates : Wireshark below the latest release of its branch (plugin
#              349570 "Wireshark 4.6.x < 4.6.9 Multiple Vulnerabilities
#              (macOS)", csmb-059 2026-10-27), and later Wireshark advisories
#              of the same shape.
# Platform   : macOS (bash 3.2 compatible) | Deploy: Mosyle (runs as root)
#
# No pinned version. The target comes from Wireshark's own update feed (the
# Sparkle appcast the app checks):
#   https://www.wireshark.org/update/0/Wireshark/<ver>/macOS/<arm64|x86-64>/en-US/stable.xml
# It lists the latest release of each supported branch (4.6.9 and 4.4.19 on
# 2026-10-27) with the DMG URL, its size, its SHA-256 and the minimum macOS.
# A copy is raised to the latest release of its own branch. If that branch is
# no longer in the feed, to the newest release this macOS can run.
#
# Steps:
#   1. Inventory /Applications/Wireshark.app and per-user copies in
#      /Users/*/Applications (Tenable reports both). Spotlight copies anywhere
#      else are reported, not changed.
#   2. Nothing below the target -> exit 0 without downloading.
#   3. A copy with anything running from it (Wireshark, dumpcap, tshark)
#      defers with exit 2 unless FORCE_CLOSE=1: quitting can lose an unsaved
#      capture, and Wireshark asks before quitting, so an AppleScript quit
#      would just hang.
#   4. Download the DMG; check size and SHA-256 against the feed, mount it
#      read-only, and check Wireshark.app's signature (Developer ID, team
#      7Z6EMTD2C6) and version.
#   5. Replace each old copy: copy the new app beside it, swap, keep the old
#      owner, delete the old app only after the new one is in place.
#   6. Re-read every copy's version. ChmodBPF and the system-path helper are
#      separate packages and are left alone.
#
# CONFIG -- Mosyle passes no environment variables. Edit the block below
# before paste, or pass the same names from a terminal (DRY_RUN=1 ...).
# APP_DIR, USERS_DIR, LOG_DIR, WORK_DIR, OS_VERSION and FEED_ARCH may be set
# for tests.
#
# Exit: 0 = every Wireshark copy is current (or Wireshark is not installed)
#       2 = deferred (Wireshark running), not verified, or a copy outside the
#           updated locations is still old -- see the RESULT line
#       1 = could not run (feed, download, checksum or signature failed)
# =============================================================================

set -uo pipefail
HOME="${HOME:-/var/root}"
export HOME

# =============================================================================
CFG_DRY_RUN="0"
# Stop Wireshark / dumpcap / tshark running from a copy that needs the update.
# Unsaved captures are lost. Off: that copy defers to the next run (exit 2).
CFG_FORCE_CLOSE="0"
# Seconds to wait after TERM before KILL when FORCE_CLOSE=1.
CFG_QUIT_TIMEOUT="20"
# Also update older ~/Applications/Wireshark.app copies in place.
CFG_UPDATE_USER_COPIES="1"
CFG_FEED_BASE="https://www.wireshark.org/update/0/Wireshark"
# Seconds allowed for the download and for copying the app into place.
CFG_DOWNLOAD_TIMEOUT="900"
CFG_COPY_TIMEOUT="600"
# =============================================================================
DRY_RUN="${DRY_RUN:-$CFG_DRY_RUN}"
FORCE_CLOSE="${FORCE_CLOSE:-$CFG_FORCE_CLOSE}"
QUIT_TIMEOUT="${QUIT_TIMEOUT:-$CFG_QUIT_TIMEOUT}"
UPDATE_USER_COPIES="${UPDATE_USER_COPIES:-$CFG_UPDATE_USER_COPIES}"
FEED_BASE="${FEED_BASE:-$CFG_FEED_BASE}"
DOWNLOAD_TIMEOUT="${DOWNLOAD_TIMEOUT:-$CFG_DOWNLOAD_TIMEOUT}"
COPY_TIMEOUT="${COPY_TIMEOUT:-$CFG_COPY_TIMEOUT}"

APP_DIR="${APP_DIR:-/Applications}"
USERS_DIR="${USERS_DIR:-/Users}"
LOG_DIR="${LOG_DIR:-/var/log/composecure}"
LOG_FILE="$LOG_DIR/wireshark_update.log"
WORK_DIR="${WORK_DIR:-/var/tmp/wireshark_update_$$}"
WS_TEAM_ID="7Z6EMTD2C6"
WS_BUNDLE_ID="org.wireshark.Wireshark"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }

is_version() { echo "$1" | grep -Eq '^[0-9]+\.[0-9]+(\.[0-9]+)*$'; }

# True when $1 >= $2, field by field; missing fields count as 0, so macOS
# "12.0" meets the feed's "12.0.0" (sort -V puts 12.0 below 12.0.0).
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

# 4.6.3 -> 4.6
branch_of() { echo "$1" | cut -d. -f1-2; }

# Appcast XML on stdin -> one line per release: version|minOS|url|sha256|length
appcast_items() {
    awk '
    /<item>/ { v = ""; m = ""; u = ""; s = ""; l = ""; on = 1 }
    on {
        if (match($0, /<sparkle:minimumSystemVersion>[^<]*</)) m = substr($0, RSTART + 30, RLENGTH - 31)
        if (match($0, /url="[^"]*"/)) u = substr($0, RSTART + 5, RLENGTH - 6)
        if (match($0, /sparkle:version="[^"]*"/)) v = substr($0, RSTART + 17, RLENGTH - 18)
        if (match($0, /length="[0-9]*"/)) l = substr($0, RSTART + 8, RLENGTH - 9)
        if (match($0, /SHA256: [0-9a-fA-F]+/)) s = tolower(substr($0, RSTART + 8, RLENGTH - 8))
    }
    /<\/item>/ { if (v != "" && u != "") print v "|" m "|" u "|" s "|" l; on = 0 }
    '
}

# Items on stdin; $1 = installed version (may be empty), $2 = macOS version.
# Prints the item to install: newest of the installed branch that this macOS
# can run, else the newest this macOS can run. Nothing when none qualifies.
pick_target() {
    pt_branch=""
    [ -n "$1" ] && pt_branch=$(branch_of "$1")
    pt_best=""
    pt_any=""
    while IFS='|' read -r pt_v pt_m pt_u pt_s pt_l; do
        is_version "$pt_v" || continue
        if [ -n "$pt_m" ] && ! version_ge "$2" "$pt_m"; then continue; fi
        pt_line="$pt_v|$pt_m|$pt_u|$pt_s|$pt_l"
        if [ -z "$pt_any" ] || version_ge "$pt_v" "${pt_any%%|*}"; then pt_any="$pt_line"; fi
        if [ -n "$pt_branch" ] && [ "$(branch_of "$pt_v")" = "$pt_branch" ]; then
            if [ -z "$pt_best" ] || version_ge "$pt_v" "${pt_best%%|*}"; then pt_best="$pt_line"; fi
        fi
    done
    if [ -n "$pt_best" ]; then echo "$pt_best"; return 0; fi
    if [ -n "$pt_any" ]; then echo "$pt_any"; return 0; fi
    return 1
}

# `codesign -dv --verbose=2` output on stdin -> 0 when it is a Developer ID
# Application signature for Wireshark's team ID.
signature_is_wireshark() {
    sw_out=$(cat)
    echo "$sw_out" | grep -q "^TeamIdentifier=$WS_TEAM_ID\$" || return 1
    echo "$sw_out" | grep -qE "^Authority=Developer ID Application: .+ \\($WS_TEAM_ID\\)\$" || return 1
}

feed_arch() {
    if [ "$(sysctl -n hw.optional.arm64 2>/dev/null)" = "1" ]; then echo arm64; else echo x86-64; fi
}

descendants() (
    for d_child in $(pgrep -P "$1" 2>/dev/null); do
        descendants "$d_child"
        echo "$d_child"
    done
)

if [ "${WIRESHARK_UPDATE_SELFTEST:-0}" = "1" ]; then
    return 0 2>/dev/null || exit 0
fi

mkdir -p "$LOG_DIR"
cd /tmp || exit 1
ISSUES=""
add_issue() { ISSUES="${ISSUES}${ISSUES:+
}$1"; }
MOUNTED=""
cleanup() {
    [ -n "$MOUNTED" ] && hdiutil detach -force "$MOUNTED" >/dev/null 2>&1
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

app_version() {
    av_plist="$1/Contents/Info.plist"
    [ -f "$av_plist" ] || return 0
    av_v=$(defaults read "$av_plist" CFBundleShortVersionString 2>/dev/null)
    is_version "$av_v" && echo "$av_v"
    return 0
}

owner_of() { stat -f '%Su:%Sg' "$1" 2>/dev/null; }

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

# Processes running from inside a copy: Wireshark, dumpcap, tshark, ...
copy_pids() { pgrep -f "$1/Contents/MacOS/" 2>/dev/null | tr '\n' ' ' | sed 's/ $//'; }

stop_copy() {
    sc_pids=$(copy_pids "$1")
    [ -n "$sc_pids" ] || return 0
    log "  Stopping processes from $1 (pid $sc_pids) -- FORCE_CLOSE=1."
    # shellcheck disable=SC2086
    kill $sc_pids 2>/dev/null
    sc_end=$(( $(date +%s) + QUIT_TIMEOUT ))
    while [ -n "$(copy_pids "$1")" ] && [ "$(date +%s)" -lt "$sc_end" ]; do sleep 1; done
    sc_pids=$(copy_pids "$1")
    if [ -n "$sc_pids" ]; then
        # shellcheck disable=SC2086
        kill -9 $sc_pids 2>/dev/null
        sleep 2
    fi
    [ -z "$(copy_pids "$1")" ]
}

# Swap $1 (an installed Wireshark.app) for $SRC_APP. 0 = new app in place.
replace_app() {
    ra_dst="$1"
    ra_new="$ra_dst.new.$$"
    ra_old="$ra_dst.old.$$"
    ra_owner=$(owner_of "$ra_dst")
    rm -rf "$ra_new"
    STEP_LOG="$LOG_DIR/wireshark_update_copy.log"
    if ! run_limited "$COPY_TIMEOUT" ditto "$SRC_APP" "$ra_new"; then
        rm -rf "$ra_new"
        add_issue "could not copy the new app to $ra_new -- $STEP_LOG"
        return 1
    fi
    [ -n "$ra_owner" ] && chown -R "$ra_owner" "$ra_new"
    ra_ver=$(app_version "$ra_new")
    if [ "$ra_ver" != "$TARGET" ]; then
        rm -rf "$ra_new"
        add_issue "the copied app at $ra_new reads ${ra_ver:-no version}, not $TARGET; $ra_dst left as it was"
        return 1
    fi
    if ! mv "$ra_dst" "$ra_old"; then
        rm -rf "$ra_new"
        add_issue "could not move $ra_dst aside; left as it was"
        return 1
    fi
    if ! mv "$ra_new" "$ra_dst"; then
        mv "$ra_old" "$ra_dst"
        rm -rf "$ra_new"
        add_issue "could not move the new app into $ra_dst; the old one was put back"
        return 1
    fi
    rm -rf "$ra_old"
    log "  Replaced $ra_dst (owner ${ra_owner:-unchanged})."
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

OS_VERSION="${OS_VERSION:-$(sw_vers -productVersion 2>/dev/null)}"
FEED_ARCH="${FEED_ARCH:-$(feed_arch)}"
log "===== update-wireshark.sh START ====="
log "Host: $(hostname -s 2>/dev/null || hostname)   macOS ${OS_VERSION:-?}   feed arch $FEED_ARCH"
log "DryRun=$DRY_RUN  ForceClose=$FORCE_CLOSE  UpdateUserCopies=$UPDATE_USER_COPIES"

log ""
log "[1] Installed copies"
MAIN_APP="$APP_DIR/Wireshark.app"
COPIES=""
if [ -d "$MAIN_APP" ]; then
    mv_ver=$(app_version "$MAIN_APP")
    log "  $MAIN_APP  ${mv_ver:-version unreadable}"
    COPIES="$MAIN_APP|$mv_ver|main"
fi
for ua in "$USERS_DIR"/*/Applications/Wireshark.app; do
    [ -d "$ua" ] || continue
    uv=$(app_version "$ua")
    log "  $ua  ${uv:-version unreadable}"
    COPIES="$COPIES
$ua|$uv|user"
done
OTHERS=""
if command -v mdfind >/dev/null 2>&1; then
    STEP_LOG="$LOG_DIR/wireshark_update_mdfind.log"; : > "$STEP_LOG"
    run_limited 60 mdfind "kMDItemCFBundleIdentifier == '$WS_BUNDLE_ID'"
    while IFS= read -r op; do
        [ -d "$op" ] || continue
        case "$op" in
            "$MAIN_APP"|"$USERS_DIR"/*/Applications/Wireshark.app|/Volumes/*|"$APP_DIR"/Wireshark.app.*) continue ;;
        esac
        ov=$(app_version "$op")
        log "  $op  ${ov:-version unreadable}  (found by Spotlight; reported only)"
        OTHERS="$OTHERS
$op|$ov"
    done < "$STEP_LOG"
fi
for bp in /opt/homebrew /usr/local; do
    for ck in wireshark-app wireshark; do
        [ -d "$bp/Caskroom/$ck" ] && log "  (Homebrew cask $ck record in $bp; its version will lag until brew upgrades it -- Tenable reads the app)"
    done
    for kg in "$bp"/Cellar/wireshark/*; do
        [ -d "$kg" ] && log "  (Homebrew formula wireshark $(basename "$kg") in $bp -- command-line tools, not this finding; update-homebrew.sh upgrades it)"
    done
done
if [ -z "$COPIES" ] && [ -z "$OTHERS" ]; then
    finish 0 "Wireshark is not installed. Nothing to do."
fi

log ""
log "[2] Latest release"
FEED_VER=$(printf '%s\n' "$COPIES" | sed -n 's/^[^|]*|\([0-9][0-9.]*\)|.*$/\1/p' | head -n 1)
FEED_URL="$FEED_BASE/${FEED_VER:-4.6.0}/macOS/$FEED_ARCH/en-US/stable.xml"
mkdir -p "$WORK_DIR"
FEED="$WORK_DIR/stable.xml"
STEP_LOG="$LOG_DIR/wireshark_update_feed.log"; : > "$STEP_LOG"
if ! run_limited 60 curl -fsSL --retry 2 -o "$FEED" "$FEED_URL" || ! grep -q '<enclosure' "$FEED" 2>/dev/null; then
    add_issue "could not read the update feed $FEED_URL (proxy block page?) -- $STEP_LOG"
    finish 1 "latest Wireshark version unknown -- nothing changed."
fi
ITEMS=$(appcast_items < "$FEED")
printf '%s\n' "$ITEMS" | while IFS="|" read -r iv im iu _; do
    [ -n "$iv" ] && log "  feed: $iv  (macOS $im+)  $iu"
done

# One target for every copy: the main copy's branch, else the first user copy's.
PICK=$(printf '%s\n' "$ITEMS" | pick_target "$FEED_VER" "${OS_VERSION:-0}") || PICK=""
if [ -z "$PICK" ]; then
    add_issue "no release in the feed runs on macOS ${OS_VERSION:-?}"
    finish 2 "Wireshark not updated: macOS ${OS_VERSION:-?} is too old for every release in the feed."
fi
IFS='|' read -r TARGET _ T_URL T_SHA T_LEN <<EOF
$PICK
EOF
log "  Target: $TARGET  ($T_URL)"
if [ -n "$FEED_VER" ] && [ "$(branch_of "$TARGET")" != "$(branch_of "$FEED_VER")" ]; then
    log "  Branch $(branch_of "$FEED_VER") is not in the feed any more (or needs a newer macOS); moving to $(branch_of "$TARGET")."
fi

TODO=""
while IFS='|' read -r cp cv ck; do
    [ -n "$cp" ] || continue
    if [ -n "$cv" ] && version_ge "$cv" "$TARGET"; then
        log "  OK       $cp $cv"
    elif [ "$ck" = "user" ] && [ "$UPDATE_USER_COPIES" != "1" ]; then
        log "  KEEP     $cp ${cv:-?} -- UPDATE_USER_COPIES=0"
        add_issue "$cp is ${cv:-unreadable} (< $TARGET); UPDATE_USER_COPIES=0"
    else
        log "  UPDATE   $cp ${cv:-?} -> $TARGET"
        TODO="$TODO
$cp|$cv"
    fi
done <<EOF
$COPIES
EOF
while IFS='|' read -r op ov; do
    [ -n "$op" ] || continue
    if [ -z "$ov" ] || ! version_ge "$ov" "$TARGET"; then
        add_issue "$op is ${ov:-unreadable} (< $TARGET) and is not in /Applications or ~/Applications; delete it or move it there"
    fi
done <<EOF
$OTHERS
EOF
if [ -z "$TODO" ]; then
    [ -n "$ISSUES" ] && finish 2 "Wireshark copies that this script updates are current ($TARGET); the items above still need attention."
    finish 0 "Wireshark is current ($TARGET)."
fi

log ""
log "[3] Running Wireshark"
READY=""
while IFS='|' read -r cp cv; do
    [ -n "$cp" ] || continue
    rp=$(copy_pids "$cp")
    if [ -z "$rp" ]; then
        READY="$READY
$cp|$cv"
    elif [ "$FORCE_CLOSE" = "1" ]; then
        log "  $cp is running (pid $rp); will be stopped before the swap."
        READY="$READY
$cp|$cv"
    else
        log "  $cp is running (pid $rp) -- deferring this copy."
        add_issue "$cp ${cv:-?} is in use (pid $rp); re-run when Wireshark is closed, or set FORCE_CLOSE=1 (unsaved captures are lost)"
    fi
done <<EOF
$TODO
EOF
if [ -z "$READY" ]; then
    finish 2 "deferred: Wireshark is running; nothing updated."
fi
if [ "$DRY_RUN" = "1" ]; then
    printf '%s\n' "$READY" | while IFS='|' read -r cp cv; do [ -n "$cp" ] && log "  [DRY_RUN] would replace $cp (${cv:-?}) with $TARGET"; done
    add_issue "dry run: nothing changed"
    finish 2 "dry run: target $TARGET."
fi

log ""
log "[4] Download and check"
DMG="$WORK_DIR/Wireshark.dmg"
STEP_LOG="$LOG_DIR/wireshark_update_download.log"; : > "$STEP_LOG"
if ! run_limited "$DOWNLOAD_TIMEOUT" curl -fsSL --retry 2 -o "$DMG" "$T_URL" || [ ! -s "$DMG" ]; then
    add_issue "download failed -- $STEP_LOG"
    finish 1 "could not download $T_URL."
fi
D_LEN=$(wc -c < "$DMG" | tr -d ' ')
log "  Downloaded $D_LEN bytes."
if [ -n "$T_LEN" ] && [ "$D_LEN" != "$T_LEN" ]; then
    add_issue "download is $D_LEN bytes, the feed says $T_LEN (proxy block page or truncated)"
    finish 1 "refused to install an unverified download."
fi
if [ -n "$T_SHA" ]; then
    D_SHA=$(shasum -a 256 "$DMG" 2>/dev/null | awk '{print tolower($1)}')
    if [ "$D_SHA" != "$T_SHA" ]; then
        add_issue "SHA-256 ${D_SHA:-unreadable} does not match the feed's $T_SHA"
        finish 1 "refused to install an unverified download."
    fi
    log "  SHA-256 matches the feed."
else
    log "  The feed gives no SHA-256 for $TARGET; relying on the code signature."
fi
MNT="$WORK_DIR/mnt"
mkdir -p "$MNT"
STEP_LOG="$LOG_DIR/wireshark_update_mount.log"; : > "$STEP_LOG"
if ! run_limited 120 hdiutil attach -nobrowse -readonly -noautoopen -mountpoint "$MNT" "$DMG"; then
    add_issue "hdiutil could not mount the DMG -- $STEP_LOG"
    finish 1 "could not open the Wireshark DMG."
fi
MOUNTED="$MNT"
SRC_APP="$MNT/Wireshark.app"
SRC_VER=$(app_version "$SRC_APP")
if [ "$SRC_VER" != "$TARGET" ]; then
    add_issue "the DMG's Wireshark.app is ${SRC_VER:-missing}, not $TARGET"
    finish 1 "refused to install: the DMG does not hold $TARGET."
fi
STEP_LOG="$LOG_DIR/wireshark_update_signature.log"; : > "$STEP_LOG"
if ! run_limited 300 codesign --verify --deep --strict "$SRC_APP"; then
    add_issue "codesign --verify failed for the DMG's Wireshark.app -- $STEP_LOG"
    finish 1 "refused to install an app whose signature does not verify."
fi
SIG_INFO="$WORK_DIR/codesign.txt"
codesign -dv --verbose=2 "$SRC_APP" > "$SIG_INFO" 2>&1
if ! signature_is_wireshark < "$SIG_INFO"; then
    while IFS= read -r l; do log "    $l"; done < "$SIG_INFO"
    add_issue "Wireshark.app is not signed with Wireshark's Developer ID (team $WS_TEAM_ID)"
    finish 1 "refused to install an unverified app."
fi
log "  Signature: $(sed -n 's/^Authority=\(Developer ID Application:.*\)$/\1/p' "$SIG_INFO" | head -n 1)"

log ""
log "[5] Replace"
while IFS='|' read -r cp cv; do
    [ -n "$cp" ] || continue
    if [ -n "$(copy_pids "$cp")" ]; then
        if [ "$FORCE_CLOSE" = "1" ]; then
            if ! stop_copy "$cp"; then
                add_issue "$cp is still running after TERM and KILL; not replaced"
                continue
            fi
        else
            add_issue "$cp ${cv:-?} was opened during the download; re-run when Wireshark is closed"
            continue
        fi
    fi
    replace_app "$cp"
done <<EOF
$READY
EOF

log ""
log "[6] Verify"
while IFS='|' read -r cp cv; do
    [ -n "$cp" ] || continue
    nv=$(app_version "$cp")
    if [ -n "$nv" ] && version_ge "$nv" "$TARGET"; then
        log "  $cp  $nv  OK"
    else
        log "  $cp  ${nv:-missing}  NOT CURRENT"
        add_issue "$cp is ${nv:-missing} after the update, not $TARGET"
    fi
done <<EOF
$READY
EOF

[ -n "$ISSUES" ] && finish 2 "Wireshark $TARGET installed where possible; the items above still need attention."
finish 0 "Wireshark is current ($TARGET)."
