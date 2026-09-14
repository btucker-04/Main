#!/bin/bash
# =============================================================================
# update-adobe-rum.sh  (v6)
# Generic Adobe updater via Remote Update Manager (RUM).
# Platform : macOS (bash 3.2 compatible) | Deploy: Mosyle (runs as root)
#
# Supersedes the single-product update-photoshop-306395.sh: this handles any
# Adobe product Tenable flags, with no per-plugin script needed.
#
# HOW IT VERIFIES -- this is the important design choice. RUM's exit code is not
# evidence: RC 1 is a GENERIC error per Adobe, and RUM can exit 0 while leaving
# apps on their old version. So the script inventories EVERY Adobe app's
# CFBundleShortVersionString before and after, and reports what actually moved.
# No target version is required for that; targets are optional and only decide
# pass/fail.
#
# WHY IT RUNS UNFILTERED BY DEFAULT: --productVersions is a long-standing source
# of an immediate Return Code (1) on some RUM builds (reproduced on CSPRMB-12-A,
# 2026-08-07, running as root). Unfiltered is the reliable path. Set SAP_CODES to
# target specific products; if that call fails the script falls back to
# unfiltered unless NO_FALLBACK=1.
#
# v6 (from the 2026-09-14 ARMB-08 run):
#   * A live RemoteUpdateManager that has been running for STALE_RUM_SECONDS
#     (default 10 min) is treated as hung, not as a concurrent Mosyle/manual
#     job. The script waits WAIT_FOR_RUM_SECONDS (default 120s), then if
#     KILL_STALE_RUM=1 (default) sends SIGTERM, then SIGKILL, and retries
#     install once. Younger processes still defer (exit 2) so we do not
#     interrupt a download that started seconds ago. Killing a mid-download
#     RUM can leave partial HD media (Adobe 118/129/102 on this host) -- the
#     age gate is the guard. A lock with NO process is still reboot-only;
#     there is no version-stable lock file to delete.
#   * Contention is resolved BEFORE --action=list so the advisory call does
#     not slam into an already-running instance (ARMB-08: list and install
#     both RC 1 in ~1s while pid 66008 was live).
#   * Lock-message deferral only applies when install actually failed
#     (RUM_OK=0). A successful retry after a first-attempt lock must not
#     be overturned by the still-recent log line from that first attempt.
#
# v5 (from the 2026-08-19 CSPRMB-12-A run):
#   * v4's lock detection was DEAD CODE. It checked $LAST_RUM_OUT (RUM's
#     stdout, captured via command substitution), but empirically -- across
#     two real runs on two machines -- RUM writes 'Another instance ... is
#     already running' ONLY to its own persistent log file, never to stdout.
#     stdout only ever showed 'Starting the RemoteUpdateManager... / exiting
#     with Return Code (1)'. So the v4 check could never fire.
#   * Detection is now done by reading the actual log file(s) and checking
#     for a lock message with a RECENT timestamp (within 90s of now), using
#     BSD 'date -j -f' to parse RUM's 'MM/DD/YY HH:MM:SS:mmm' format. This
#     matters because the log accumulates entries across weeks and multiple
#     users/homes (this run alone had relevant entries in BOTH
#     /var/root/Library/Logs/... from 08/07 and /Users/jomara/Library/Logs/...
#     from today) -- an unscoped grep for the message text would match a
#     three-week-old, already-irrelevant entry as if it were live. Verified
#     the recency window against both a stale (08/07) and a fresh (this run's
#     own timestamp) entry from the real log.
#   * Also surfaces 'Signature MISMATCH' download-segment errors explicitly.
#     This run showed several, immediately preceding the Fatal Error 113
#     crash, in both the 08/06 and 08/19 log entries -- a content-hash
#     validation failure on a segmented download is a sharper signal than
#     'download failed', and is consistent with an SSL-inspecting proxy
#     altering bytes in transit (the same class of issue documented
#     elsewhere in this fleet for other vendors' CDNs).
#
# v4 (from the 2026-08-19 CSMB-053 run):
#   * Distinguishes a REAL lock from a STALE one. RUM's log showed a crash 11
#     days earlier ('session '' not found', error 102) that left an orphaned
#     lock: every run since -- including this one -- failed in under a second
#     with 'Another instance of RemoteUpdateManager is already running',
#     even though no such process existed. Retrying does nothing for this;
#     the lock is not a live process. There is no documented, version-stable
#     CLI or file path to clear it, so this script does not guess at one --
#     it checks pgrep for a genuine running instance:
#       - a real process exists  -> legitimate lock, defer (exit 2), do not
#         touch it, this may be a concurrent manual/other invocation.
#       - no process exists      -> STALE lock from a crashed prior run.
#         Reported explicitly (exit 2) with the fix that reliably clears
#         orphaned process/session state: a reboot. No blind retry loop.
#
# v3 (from the 2026-08-19 CSPRMB-12-A run):
#   * dump_rum_log() printed the SAME log file twice. When running as root,
#     $HOME resolves to /var/root, so '/var/root/Library/Logs/...' and
#     '$HOME/Library/Logs/...' are literally the same path after expansion.
#     Candidates are now de-duplicated before reading.
#   * The tail was 'tail -40' of the raw log, which is dominated by HTTP
#     response-header noise (X-Cache, x-ffc-env, x-request-id, full header
#     dumps) with the one useful line -- a [FATAL] entry -- buried in the
#     middle. It is now filtered to FATAL/ERROR/failure/return-code lines
#     only, which is a handful of lines instead of ~40 of mostly headers.
#
# v2 (from the 2026-08-17 CSMB-053 run):
#   * Running-app detection is summarised PER APP BUNDLE instead of dumping
#     `pgrep -fl` output. Acrobat's CEF helpers carry base64 GPU-preference
#     blobs hundreds of characters long, which made the log unreadable.
#   * MAIN app processes are now distinguished from BACKGROUND HELPERS.
#     AdobeResourceSynchronizer and Adobe Crash Processor run from login whether
#     or not the app is open, so treating any Adobe process as "app running"
#     blocked the script permanently on every Mac with Acrobat installed. Only a
#     main app process aborts the run; helpers are noted and ignored. Set
#     IGNORE_HELPERS=0 to restore the strict behaviour.
#   * FORCE_CLOSE now asks main apps to quit via AppleScript before killing.
#
# v2 (from the 2026-08-17 CSMB-053 run):
#   * BLOCKED ON BACKGROUND HELPERS. v1 matched any process under
#     /Applications/Adobe, which includes AdobeResourceSynchronizer, Adobe Crash
#     Processor, AcroCEF renderers and XPC services. Those run persistently on
#     any Mac with Acrobat installed, so the script would have refused to update
#     essentially every host. It now blocks only on MAIN application binaries --
#     path of the form <App>.app/Contents/MacOS/<binary> with no nested .app --
#     which on CSMB-053 correctly identifies AdobeAcrobat alone out of 13 matches.
#   * UNREADABLE OUTPUT. pgrep -fl printed full command lines including
#     multi-kilobyte base64 GPU-preference blobs. It now reads the executable
#     path via 'ps -axo comm=' and reports one line per app bundle.
#
# ENVIRONMENT (all optional -- Mosyle passes values this way):
#   TARGETS="Photoshop=27.5;Illustrator=30.1"
#        Semicolon-separated NamePattern=MinVersion. The pattern is matched as a
#        substring of the .app bundle name, so Tenable output maps directly:
#        "Adobe Photoshop 27.x < 27.5"  ->  TARGETS="Photoshop=27.5"
#        Any listed app still below its minimum makes the run fail (exit 1).
#   SAP_CODES="PHSP,ILST"   target RUM at specific products (see note above)
#   FORCE_CLOSE=1           quit running Adobe apps instead of aborting
#   KILL_STALE_RUM=1        terminate RemoteUpdateManager if still running
#                           after WAIT_FOR_RUM_SECONDS AND elapsed age
#                           >= STALE_RUM_SECONDS (default on)
#   WAIT_FOR_RUM_SECONDS=120  how long to wait for an existing RUM to finish
#   STALE_RUM_SECONDS=600     elapsed age (from ps etime) before a live RUM
#                             is treated as hung rather than concurrent
#   NO_FALLBACK=1           do not retry unfiltered if a targeted call fails
#   DRY_RUN=1               inventory + RUM list only; install nothing
#                             (never kills RUM)
#
# Exit: 0 = nothing needed, or everything that was asked for reached its target
#       2 = skipped (Adobe apps running), or apps updated but no TARGETS given
#           to judge against, or RUM failed while nothing needed updating
#       1 = a TARGETS entry is still below its minimum, or RUM failed outright
# =============================================================================

set -uo pipefail
HOME="${HOME:-/var/root}"
export HOME

RUM="/usr/local/bin/RemoteUpdateManager"

# CONFIG -- Mosyle cannot pass env at deploy; edit these. A terminal-set
# environment variable still wins over the matching CFG_ default.
CFG_FORCE_CLOSE="${CFG_FORCE_CLOSE:-0}"
CFG_KILL_STALE_RUM="${CFG_KILL_STALE_RUM:-1}"
CFG_WAIT_FOR_RUM_SECONDS="${CFG_WAIT_FOR_RUM_SECONDS:-120}"
CFG_STALE_RUM_SECONDS="${CFG_STALE_RUM_SECONDS:-600}"
CFG_NO_FALLBACK="${CFG_NO_FALLBACK:-0}"
CFG_DRY_RUN="${CFG_DRY_RUN:-0}"
CFG_IGNORE_HELPERS="${CFG_IGNORE_HELPERS:-1}"

TARGETS="${TARGETS:-}"
SAP_CODES="${SAP_CODES:-}"
FORCE_CLOSE="${FORCE_CLOSE:-$CFG_FORCE_CLOSE}"
KILL_STALE_RUM="${KILL_STALE_RUM:-$CFG_KILL_STALE_RUM}"
WAIT_FOR_RUM_SECONDS="${WAIT_FOR_RUM_SECONDS:-$CFG_WAIT_FOR_RUM_SECONDS}"
STALE_RUM_SECONDS="${STALE_RUM_SECONDS:-$CFG_STALE_RUM_SECONDS}"
NO_FALLBACK="${NO_FALLBACK:-$CFG_NO_FALLBACK}"
DRY_RUN="${DRY_RUN:-$CFG_DRY_RUN}"
IGNORE_HELPERS="${IGNORE_HELPERS:-$CFG_IGNORE_HELPERS}"

LOG_DIR="/var/log/composecure"
LOG_FILE="$LOG_DIR/adobe_rum_update.log"
WORK="/tmp/adobe_rum_$$"
mkdir -p "$LOG_DIR" "$WORK"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }

CAFFEINATE_PID=""
cleanup() {
    [ -n "$CAFFEINATE_PID" ] && kill "$CAFFEINATE_PID" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

# First ".app" component of a path is the top-level bundle:
#   /Applications/Adobe Acrobat DC/Adobe Acrobat.app/Contents/Helpers/... ->
#   /Applications/Adobe Acrobat DC/Adobe Acrobat.app
top_bundle() { echo "$1" | sed -nE 's|^(/Applications/[^/]+/[^/]+\.app).*|\1|p'; }

# A MAIN process runs directly from <bundle>/Contents/MacOS/. Anything under
# Helpers/, Frameworks/, XPCServices/ or a nested .app is a background helper.
is_main_process() {
    exe="$1"; bundle="$2"
    [ -z "$bundle" ] && return 1
    rest="${exe#$bundle}"
    case "$rest" in
        /Contents/MacOS/*)
            case "$rest" in *.app/*) return 1 ;; esac
            return 0 ;;
    esac
    return 1
}

# Adobe processes, by EXECUTABLE PATH (not command line -- avoids the base64
# --gpu-preferences blobs that made v1's output unreadable).
adobe_procs() { ps -axo pid=,comm= 2>/dev/null | grep -i '/Applications/Adobe' || true; }

# A MAIN application binary looks like  <App>.app/Contents/MacOS/<binary>
# with exactly one ".app/" in the path. Everything else -- Contents/Helpers/*.app,
# Contents/Frameworks/*.app, *.xpc/Contents/MacOS -- is a helper or XPC service
# and must NOT block an update: several of them run permanently.
is_main_app() {
    case "$1" in
        *.app/Contents/MacOS/*) : ;;
        *) return 1 ;;
    esac
    n=$(printf '%s' "$1" | grep -o '\.app/' | wc -l | tr -d ' ')
    [ "$n" -eq 1 ]
}

# "/Applications/Adobe Photoshop 2025/Adobe Photoshop 2025.app/..." -> bundle name
app_bundle_of() { echo "$1" | sed -nE 's|.*/([^/]+\.app)/Contents/MacOS/.*|\1|p'; }

version_ge() { [ "$(printf '%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

# ---- inventory every Adobe .app into "path|version" lines --------------------
inventory() {
    outfile="$1"
    : > "$outfile"
    while IFS= read -r app; do
        [ -d "$app" ] || continue
        v=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" \
              "$app/Contents/Info.plist" 2>/dev/null || true)
        [ -z "$v" ] && v="unknown"
        echo "$app|$v" >> "$outfile"
    done < <(find /Applications -maxdepth 2 -type d -name '*.app' -path '*Adobe*' 2>/dev/null | sort)
}

lookup_version() {  # $1 = inventory file, $2 = app path
    grep -F "$2|" "$1" 2>/dev/null | head -1 | sed 's/.*|//'
}

# Signal-only filter: FATAL/ERROR/failure/return-code lines. Cuts a ~40-line
# tail dominated by HTTP header noise (X-Cache, x-ffc-env, x-request-id, full
# response-header blocks) down to the handful of lines that are ever actually
# useful for diagnosing a RUM failure.
RUM_LOG_SIGNAL='FATAL|ERROR|Fatal Error|Failed to [Dd]ownload|failed to [Dd]ownload|Return Code|exiting with'

dump_rum_log() {
    log "  --- relevant lines from Adobe RemoteUpdateManager log(s) ---"
    log "  (filtered to FATAL/ERROR/failure/return-code lines; full log is at the"
    log "   path(s) below if more detail is needed)"
    found=0
    SEEN_LOGS=""
    for cand in /var/root/Library/Logs/RemoteUpdateManager.log \
                /Library/Logs/Adobe/RemoteUpdateManager.log \
                "$HOME/Library/Logs/RemoteUpdateManager.log"; do
        [ -f "$cand" ] || continue
        case " $SEEN_LOGS " in
            *" $cand "*) continue ;;
        esac
        SEEN_LOGS="$SEEN_LOGS $cand"
        found=1; log "  == $cand =="
        hits=$(grep -E "$RUM_LOG_SIGNAL" "$cand" 2>/dev/null | tail -15)
        if [ -n "$hits" ]; then
            echo "$hits" | while IFS= read -r l; do [ -n "$l" ] && log "    $l"; done
        else
            log "    (no FATAL/ERROR/failure lines matched; tailing last 5 raw lines)"
            tail -5 "$cand" 2>/dev/null | while IFS= read -r l; do [ -n "$l" ] && log "    $l"; done
        fi
    done
    for udir in /Users/*; do
        cand="$udir/Library/Logs/RemoteUpdateManager.log"
        [ -f "$cand" ] || continue
        case " $SEEN_LOGS " in
            *" $cand "*) continue ;;
        esac
        SEEN_LOGS="$SEEN_LOGS $cand"
        found=1; log "  == $cand =="
        hits=$(grep -E "$RUM_LOG_SIGNAL" "$cand" 2>/dev/null | tail -15)
        if [ -n "$hits" ]; then
            echo "$hits" | while IFS= read -r l; do [ -n "$l" ] && log "    $l"; done
        fi
    done
    [ "$found" -eq 0 ] && log "  (no RemoteUpdateManager.log found)"
}

# 'Another instance of RemoteUpdateManager is already running' is written by
# RUM to its own log file, NEVER to stdout (verified empirically -- v4 checked
# stdout and never fired). The log accumulates entries across weeks and
# multiple user homes, so an unscoped text match would trigger on a stale
# entry from an unrelated past incident. This checks for the message with a
# RECENT timestamp instead, using BSD date -j -f to parse RUM's
# 'MM/DD/YY HH:MM:SS:mmm' log format (macOS only -- this script is macOS-only
# throughout).
recent_lock_message() {
    # NOTE: matches are read via a heredoc (<<EOF2), not piped into the while
    # loop. Piping into 'while read' runs the loop in a SUBSHELL in bash, so a
    # 'return' inside it cannot propagate out of this function -- the first
    # candidate file checked would always end the search, match or not, which
    # is exactly the bug this replaced (it stopped at root's log, which only
    # had stale Aug-7 entries, and never reached the user's log with the
    # actual fresh one). The heredoc form runs in the current shell instead.
    window_secs=90
    now_epoch=$(date "+%s")
    for cand in /var/root/Library/Logs/RemoteUpdateManager.log \
                /Library/Logs/Adobe/RemoteUpdateManager.log \
                "$HOME/Library/Logs/RemoteUpdateManager.log" \
                /Users/*/Library/Logs/RemoteUpdateManager.log; do
        [ -f "$cand" ] || continue
        matches=$(grep -i "Another instance of RemoteUpdateManager is already running" "$cand" 2>/dev/null | tail -5)
        [ -z "$matches" ] && continue
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            ts=$(echo "$line" | awk '{print $1, $2}' | sed -E 's/:[0-9]{3}$//')
            epoch=$(date -j -f "%m/%d/%y %H:%M:%S" "$ts" "+%s" 2>/dev/null)
            [ -z "$epoch" ] && continue
            diff=$((now_epoch - epoch))
            if [ "$diff" -ge -5 ] && [ "$diff" -le "$window_secs" ]; then
                echo "$cand: $line"
                return 0
            fi
        done <<EOF2
$matches
EOF2
    done
    return 1
}

# BSD / POSIX ps etime: [[DD-]HH:]MM:SS (leading zeros). Strip them so bash
# arithmetic does not treat 08 as octal.
_etime_field_dec() {
    n="${1:-0}"
    n=$(printf '%s' "$n" | sed 's/^0*\([0-9]\)/\1/; s/^0*$/0/')
    printf '%s' "$n"
}

etime_to_seconds() {
    raw="${1:-}"
    raw=$(printf '%s' "$raw" | tr -d '[:space:]')
    [ -n "$raw" ] || { echo 0; return 1; }
    days=0
    rest="$raw"
    case "$raw" in
        *-*)
            days=$(_etime_field_dec "${raw%%-*}")
            rest="${raw#*-}"
            ;;
    esac
    ncolon=$(printf '%s' "$rest" | tr -cd ':' | wc -c | tr -d ' ')
    h=0
    m=0
    s=0
    case "$ncolon" in
        0)
            s=$(_etime_field_dec "$rest")
            ;;
        1)
            m=$(_etime_field_dec "${rest%%:*}")
            s=$(_etime_field_dec "${rest#*:}")
            ;;
        2)
            h=$(_etime_field_dec "${rest%%:*}")
            rest="${rest#*:}"
            m=$(_etime_field_dec "${rest%%:*}")
            s=$(_etime_field_dec "${rest#*:}")
            ;;
        *)
            echo 0
            return 1
            ;;
    esac
    echo $((days * 86400 + h * 3600 + m * 60 + s))
}

rum_live_pids() {
    pgrep -x RemoteUpdateManager 2>/dev/null || true
}

rum_pid_elapsed_seconds() {
    pid="$1"
    et=$(ps -o etime= -p "$pid" 2>/dev/null | head -1)
    [ -n "$et" ] || { echo 0; return 1; }
    etime_to_seconds "$et"
}

# Oldest (largest elapsed) live RUM, or 0 if none.
rum_oldest_elapsed_seconds() {
    oldest=0
    for pid in $(rum_live_pids); do
        [ -n "$pid" ] || continue
        age=$(rum_pid_elapsed_seconds "$pid")
        [ "$age" -gt "$oldest" ] && oldest="$age"
    done
    echo "$oldest"
}

wait_for_rum_exit() {
    timeout_s="${1:-0}"
    [ "$timeout_s" -gt 0 ] || return 0
    elapsed=0
    while [ "$elapsed" -lt "$timeout_s" ]; do
        pids=$(rum_live_pids)
        [ -z "$pids" ] && return 0
        sleep 5
        elapsed=$((elapsed + 5))
    done
    pids=$(rum_live_pids)
    [ -z "$pids" ]
}

terminate_rum_processes() {
    pids=$(rum_live_pids)
    [ -n "$pids" ] || return 0
    log "  Sending SIGTERM to RemoteUpdateManager pid(s): $(echo "$pids" | tr '\n' ' ')"
    for pid in $pids; do
        kill -TERM "$pid" 2>/dev/null || true
    done
    wait_secs=15
    waited=0
    while [ "$waited" -lt "$wait_secs" ]; do
        [ -z "$(rum_live_pids)" ] && return 0
        sleep 1
        waited=$((waited + 1))
    done
    pids=$(rum_live_pids)
    [ -n "$pids" ] || return 0
    log "  Still alive after SIGTERM; sending SIGKILL to pid(s): $(echo "$pids" | tr '\n' ' ')"
    for pid in $pids; do
        kill -KILL "$pid" 2>/dev/null || true
    done
    sleep 3
    [ -z "$(rum_live_pids)" ]
}

# 0 = no live RUM (safe to invoke); 1 = still occupied, caller should defer.
resolve_rum_contention() {
    pids=$(rum_live_pids)
    if [ -z "$pids" ]; then
        return 0
    fi
    age=$(rum_oldest_elapsed_seconds)
    log "  RemoteUpdateManager already running (pid(s): $(echo "$pids" | tr '\n' ' ') oldest elapsed ${age}s)."
    if [ "$WAIT_FOR_RUM_SECONDS" -gt 0 ]; then
        log "  Waiting up to ${WAIT_FOR_RUM_SECONDS}s for it to finish..."
        wait_for_rum_exit "$WAIT_FOR_RUM_SECONDS" || true
        pids=$(rum_live_pids)
        if [ -z "$pids" ]; then
            log "  Prior RUM exited. Continuing."
            return 0
        fi
        age=$(rum_oldest_elapsed_seconds)
        log "  Still running after wait (oldest elapsed ${age}s)."
    fi
    if [ "$DRY_RUN" = "1" ]; then
        log "  DRY_RUN=1 -- not killing RUM. Deferring."
        return 1
    fi
    if [ "$KILL_STALE_RUM" = "1" ] && [ "$age" -ge "$STALE_RUM_SECONDS" ]; then
        log "  Treating as STALE (elapsed ${age}s >= STALE_RUM_SECONDS=${STALE_RUM_SECONDS})."
        log "  WARNING: stopping a mid-download RUM can leave partial Adobe HD media"
        log "  (errors 118/129/102). The age gate is the guard against killing a"
        log "  young concurrent job."
        if terminate_rum_processes; then
            log "  Stale RUM terminated. Continuing."
            return 0
        fi
        log "  RUM survived SIGKILL. Deferring."
        return 1
    fi
    log "  Concurrent/young RUM (elapsed ${age}s < STALE_RUM_SECONDS=${STALE_RUM_SECONDS}"
    log "  or KILL_STALE_RUM=${KILL_STALE_RUM}). Not interrupting. Re-run later."
    return 1
}

handle_rum_lock_failure() {
    LOCK_HIT=$(recent_lock_message)
    [ -n "$LOCK_HIT" ] || return 0
    log "  Found a RECENT lock message in RUM's own log: $LOCK_HIT"
    REAL_PROC=$(rum_live_pids)
    if [ -n "$REAL_PROC" ]; then
        if resolve_rum_contention; then
            log "  Retrying install once after clearing the live RUM instance..."
            rum_install_once
            if [ "$RUM_OK" -eq 1 ]; then
                return 0
            fi
            LOCK_HIT=$(recent_lock_message)
            REAL_PROC=$(rum_live_pids)
            if [ "$RUM_OK" -eq 0 ] && [ -n "$LOCK_HIT" ] && [ -n "$REAL_PROC" ]; then
                log "  A RemoteUpdateManager process is still running (pid: $(echo "$REAL_PROC" | tr '\n' ' '))."
                log "  Deferring rather than looping. Re-run later."
                log "===== END (deferred: real RUM instance in progress) ====="
                exit 2
            fi
            if [ "$RUM_OK" -eq 0 ] && [ -n "$LOCK_HIT" ] && [ -z "$REAL_PROC" ]; then
                log "  RUM reported another instance running moments ago, but NO such process"
                log "  exists now (checked: pgrep -x RemoteUpdateManager). This is a STALE LOCK"
                log "  left by a crashed/killed run, not a live conflict."
                log "  There is no documented, version-stable file to delete for this --"
                log "  guessing at one risks touching the wrong thing. The fix that reliably"
                log "  clears orphaned process/session state is a REBOOT. Retrying this script"
                log "  without one will keep failing identically."
                report_signature_mismatches
                log "===== END (stale RUM lock -- reboot required) ====="
                exit 2
            fi
            return 0
        fi
        log "  A RemoteUpdateManager process IS genuinely running (pid: $(echo "$REAL_PROC" | tr '\n' ' '))."
        log "  This is a real lock, not stale -- deferring rather than interfering with"
        log "  it (concurrent manual run or another deployment?). Re-run later."
        log "===== END (deferred: real RUM instance in progress) ====="
        exit 2
    fi
    log "  RUM reported another instance running moments ago, but NO such process"
    log "  exists now (checked: pgrep -x RemoteUpdateManager). This is a STALE LOCK"
    log "  left by a crashed/killed run, not a live conflict."
    log "  There is no documented, version-stable file to delete for this --"
    log "  guessing at one risks touching the wrong thing. The fix that reliably"
    log "  clears orphaned process/session state is a REBOOT. Retrying this script"
    log "  without one will keep failing identically."
    report_signature_mismatches
    log "===== END (stale RUM lock -- reboot required) ====="
    exit 2
}

# Surfaced as its own signal: content-signature validation failures on a
# segmented download are a sharper diagnosis than a generic download failure,
# and match an SSL-inspecting proxy altering bytes in transit.
report_signature_mismatches() {
    for cand in /var/root/Library/Logs/RemoteUpdateManager.log \
                "$HOME/Library/Logs/RemoteUpdateManager.log" \
                /Users/*/Library/Logs/RemoteUpdateManager.log; do
        [ -f "$cand" ] || continue
        hits=$(grep -c "Signature MISMATCH" "$cand" 2>/dev/null)
        if [ -n "$hits" ] && [ "$hits" -gt 0 ]; then
            log "  NOTE: $cand contains $hits 'Signature MISMATCH' entries (may include"
            log "  older ones). A content-hash mismatch on a downloaded segment is"
            log "  consistent with an SSL-inspecting proxy altering bytes in transit,"
            log "  not a transient network blip. If this recurs, check whether Adobe's"
            log "  CDN (cdn-ffc.oobesaas.adobe.com and related) is being SSL-inspected."
        fi
    done
}

run_rum() {
    desc="$1"; shift
    log "  RUM $desc: $RUM $*"
    out=$("$RUM" "$@" 2>&1); rc=$?
    LAST_RUM_OUT="$out"
    echo "$out" | while IFS= read -r l; do [ -n "$l" ] && log "    $l"; done
    log "    return code: $rc"
    return $rc
}

rum_install_once() {
    RUM_OK=0
    if [ -n "$SAP_CODES" ]; then
        if run_rum "install ($SAP_CODES)" --productVersions="$SAP_CODES" --action=install; then
            RUM_OK=1
        else
            log "  Targeted install failed. --productVersions is a known cause of an"
            log "  immediate RC 1 on some RUM builds."
            dump_rum_log
            if [ "$NO_FALLBACK" = "1" ]; then
                log "  NO_FALLBACK=1 -- not retrying unfiltered."
            else
                log "  Retrying unfiltered. NOTE: this updates EVERY Adobe product here."
                run_rum "install (all products)" --action=install && RUM_OK=1
            fi
        fi
    else
        run_rum "install (all products)" --action=install && RUM_OK=1
    fi
}

if [ "${RUM_SELFTEST:-0}" = "1" ] || [ "${RUM_SELFTEST:-0}" = "kill" ]; then
    fail=0
    got=$(etime_to_seconds '01:02')
    [ "$got" = "62" ] || { echo "etime_to_seconds '01:02' => $got (want 62)" >&2; fail=1; }
    got=$(etime_to_seconds '08:09')
    [ "$got" = "489" ] || { echo "etime_to_seconds '08:09' => $got (want 489)" >&2; fail=1; }
    got=$(etime_to_seconds '01:02:03')
    [ "$got" = "3723" ] || { echo "etime_to_seconds '01:02:03' => $got (want 3723)" >&2; fail=1; }
    got=$(etime_to_seconds '1-02:03:04')
    [ "$got" = "93784" ] || { echo "etime_to_seconds '1-02:03:04' => $got (want 93784)" >&2; fail=1; }
    got=$(etime_to_seconds '  02:00  ')
    [ "$got" = "120" ] || { echo "etime_to_seconds '  02:00  ' => $got (want 120)" >&2; fail=1; }
    if [ "${RUM_SELFTEST:-0}" != "kill" ]; then
        exit "$fail"
    fi
    if [ "$fail" -ne 0 ]; then
        exit "$fail"
    fi
    WAIT_FOR_RUM_SECONDS=0
    STALE_RUM_SECONDS=0
    KILL_STALE_RUM=1
    DRY_RUN=0
    fake="$WORK/RemoteUpdateManager"
    cp /bin/sleep "$fake"
    chmod +x "$fake"
    "$fake" 120 &
    fpid=$!
    sleep 1
    if [ -z "$(rum_live_pids)" ]; then
        echo "pgrep -x RemoteUpdateManager did not see fake pid $fpid (expected on Linux 15-char comm; macOS should match)." >&2
        age=$(rum_pid_elapsed_seconds "$fpid")
        echo "rum_pid_elapsed_seconds($fpid)=$age (ps etime parse)"
        if [ "$age" -lt 0 ] || [ "$age" -gt 30 ]; then
            echo "unexpected elapsed $age for fake pid" >&2
            kill -KILL "$fpid" 2>/dev/null || true
            exit 1
        fi
        kill -KILL "$fpid" 2>/dev/null || true
        wait "$fpid" 2>/dev/null || true
        if terminate_rum_processes; then
            echo "etime+ps-elapsed selftest ok (no pgrep match on this OS)"
            exit 0
        fi
        exit 1
    fi
    if ! resolve_rum_contention; then
        echo "resolve_rum_contention failed to clear fake RUM pid $fpid" >&2
        kill -KILL "$fpid" 2>/dev/null || true
        exit 1
    fi
    if [ -n "$(rum_live_pids)" ]; then
        echo "fake RUM still running after resolve" >&2
        exit 1
    fi
    echo "kill-stale selftest ok"
    exit 0
fi

log "===== update-adobe-rum.sh START ====="
log "Host: $(hostname -s)"
log "TARGETS=${TARGETS:-<none>}  SAP_CODES=${SAP_CODES:-<none, unfiltered>}  DRY_RUN=$DRY_RUN"
log "FORCE_CLOSE=$FORCE_CLOSE  KILL_STALE_RUM=$KILL_STALE_RUM  WAIT_FOR_RUM_SECONDS=$WAIT_FOR_RUM_SECONDS  STALE_RUM_SECONDS=$STALE_RUM_SECONDS"

# -----------------------------------------------------------------------
# 1. Inventory before
# -----------------------------------------------------------------------
log ""
log "[1] Adobe applications installed (before)..."
inventory "$WORK/before"
if [ ! -s "$WORK/before" ]; then
    log "  No Adobe applications found under /Applications. Nothing to do."
    log "===== END ====="
    exit 0
fi
while IFS='|' read -r app v; do log "  $v   $app"; done < "$WORK/before"

# -----------------------------------------------------------------------
# 2. Is anything already below a stated target?
# -----------------------------------------------------------------------
NEEDED=0
if [ -n "$TARGETS" ]; then
    log ""
    log "[2] Evaluating TARGETS..."
    echo "$TARGETS" | tr ';' '\n' | while IFS= read -r spec; do
        [ -z "$spec" ] && continue
        pat=$(echo "$spec" | cut -d= -f1)
        min=$(echo "$spec" | cut -d= -f2)
        hit=0
        while IFS='|' read -r app v; do
            case "$app" in
                *"$pat"*)
                    hit=1
                    if version_ge "$v" "$min"; then
                        log "  $pat: $v >= $min  [OK]"
                    else
                        log "  $pat: $v < $min  [NEEDS UPDATE]"
                        echo x >> "$WORK/needed"
                    fi
                    ;;
            esac
        done < "$WORK/before"
        [ "$hit" -eq 0 ] && log "  $pat: not installed on this host"
    done
    [ -f "$WORK/needed" ] && NEEDED=1
    if [ "$NEEDED" -eq 0 ]; then
        log "  Every TARGETS entry already meets its minimum. Nothing to do."
        log "===== END ====="
        exit 0
    fi
else
    log ""
    log "[2] No TARGETS given -- will update whatever RUM offers and report deltas."
fi

# -----------------------------------------------------------------------
# 3. RUM present?
# -----------------------------------------------------------------------
log ""
log "[3] Remote Update Manager..."
if [ ! -x "$RUM" ]; then
    log "  ERROR: RUM not found at $RUM. It ships with Adobe enterprise packages"
    log "         when 'enable RUM' is selected in the Admin Console."
    exit 1
fi
log "  Found: $RUM"
[ "$(id -u)" -ne 0 ] && log "  WARNING: not root. RUM requires admin privileges and will return 1."

# -----------------------------------------------------------------------
# 4. Running Adobe apps
# -----------------------------------------------------------------------
log ""
log "[4] Running Adobe applications..."
: > "$WORK/mainapps"
: > "$WORK/helpers"
adobe_procs | while IFS= read -r line; do
    pid=$(echo "$line" | awk '{print $1}')
    exe=$(echo "$line" | sed -E 's|^[[:space:]]*[0-9]+[[:space:]]+||')
    case "$exe" in *RemoteUpdateManager*) continue ;; esac
    if is_main_app "$exe"; then
        echo "$(app_bundle_of "$exe")|$pid" >> "$WORK/mainapps"
    else
        echo "$exe" >> "$WORK/helpers"
    fi
done

HELPER_COUNT=0
[ -f "$WORK/helpers" ] && HELPER_COUNT=$(wc -l < "$WORK/helpers" | tr -d ' ')

if [ -s "$WORK/mainapps" ]; then
    log "  Open Adobe applications:"
    cut -d'|' -f1 "$WORK/mainapps" | sort -u | while IFS= read -r appname; do
        pids=$(grep -F "$appname|" "$WORK/mainapps" | cut -d'|' -f2 | tr '\n' ' ')
        log "    $appname  (pid(s): $pids)"
    done
    log "  Plus $HELPER_COUNT background helper/XPC process(es) -- these do not block."
    if [ "$FORCE_CLOSE" != "1" ]; then
        log "  Updating in place risks unsaved work. Skipping."
        log "  Re-run when closed, or set FORCE_CLOSE=1."
        log "===== END (deferred) ====="
        exit 2
    fi
    log "  FORCE_CLOSE=1: quitting the applications above..."
    cut -d'|' -f2 "$WORK/mainapps" | while IFS= read -r p; do kill "$p" 2>/dev/null || true; done
    sleep 6
    # then clear any Adobe process still holding files
    adobe_procs | awk '{print $1}' | while IFS= read -r p; do kill -9 "$p" 2>/dev/null || true; done
    sleep 2
else
    log "  No Adobe application is open."
    log "  ($HELPER_COUNT background helper/XPC process(es) present -- e.g."
    log "   AdobeResourceSynchronizer and Adobe Crash Processor run persistently"
    log "   whenever Acrobat is installed. They are not treated as blockers.)"
fi

# -----------------------------------------------------------------------
# 5. What does RUM see (advisory only)
# -----------------------------------------------------------------------
log ""
log "[5] RUM list (advisory -- the authority is the version diff in [7])..."
if ! resolve_rum_contention; then
    log "===== END (deferred: RemoteUpdateManager already running) ====="
    exit 2
fi
if [ -n "$SAP_CODES" ]; then
    run_rum "list ($SAP_CODES)" --productVersions="$SAP_CODES" --action=list || \
        run_rum "list (all products)" --action=list || true
else
    run_rum "list (all products)" --action=list || true
fi

if [ "$DRY_RUN" = "1" ]; then
    log ""
    log "DRY_RUN=1 -- stopping before install."
    log "===== END (dry run) ====="
    exit 0
fi

# -----------------------------------------------------------------------
# 6. Install
# -----------------------------------------------------------------------
log ""
log "[6] Installing updates (machine kept awake)..."
{ caffeinate -dimu & } 2>/dev/null
CAFFEINATE_PID=$!
disown "$CAFFEINATE_PID" 2>/dev/null || true

rum_install_once
[ "$RUM_OK" -eq 0 ] && dump_rum_log

if [ "$RUM_OK" -eq 0 ]; then
    handle_rum_lock_failure
fi
kill "$CAFFEINATE_PID" 2>/dev/null; CAFFEINATE_PID=""
report_signature_mismatches

# -----------------------------------------------------------------------
# 7. Inventory after -- the authority
# -----------------------------------------------------------------------
log ""
log "[7] Version diff (RUM's exit code is not evidence)..."
inventory "$WORK/after"
MOVED=0
while IFS='|' read -r app v; do
    newv=$(lookup_version "$WORK/after" "$app")
    [ -z "$newv" ] && newv="(removed)"
    if [ "$newv" != "$v" ]; then
        log "  UPDATED  $app: $v -> $newv"
        MOVED=1
    else
        log "  same     $app: $v"
    fi
done < "$WORK/before"
# apps that appeared (a major-version install creates a new bundle)
while IFS='|' read -r app v; do
    if ! grep -qF "$app|" "$WORK/before"; then
        log "  NEW      $app: $v"
        MOVED=1
    fi
done < "$WORK/after"

# -----------------------------------------------------------------------
# 8. Verdict
# -----------------------------------------------------------------------
log ""
FAILED=0
if [ -n "$TARGETS" ]; then
    log "Re-checking TARGETS against the post-update inventory:"
    echo "$TARGETS" | tr ';' '\n' | while IFS= read -r spec; do
        [ -z "$spec" ] && continue
        pat=$(echo "$spec" | cut -d= -f1)
        min=$(echo "$spec" | cut -d= -f2)
        while IFS='|' read -r app v; do
            case "$app" in
                *"$pat"*)
                    if version_ge "$v" "$min"; then
                        log "  $pat: $v >= $min  [OK]"
                    else
                        log "  $pat: $v < $min  [STILL BELOW]"
                        echo x >> "$WORK/failed"
                    fi
                    ;;
            esac
        done < "$WORK/after"
    done
    [ -f "$WORK/failed" ] && FAILED=1
fi

log ""
if [ "$FAILED" -eq 1 ]; then
    log "RESULT: at least one target is still below its minimum."
    if [ "$RUM_OK" -eq 0 ]; then
        log "        RUM itself failed -- the Adobe log tail above is the real reason"
        log "        (RC 1 is generic)."
    else
        log "        RUM reported success but the version did not move, which points at"
        log "        the deployment package rather than RUM."
    fi
    log "        Ranked causes: updates DISABLED in the Admin Console package (most"
    log "        common, and unfixable by script -- the package must be rebuilt with"
    log "        updates enabled); AUSST not synced; update server unreachable; or"
    log "        the build not published for this base version."
    log "===== END (not remediated) ====="
    exit 1
fi
if [ "$MOVED" -eq 1 ]; then
    if [ -n "$TARGETS" ]; then
        log "RESULT: updates applied and all targets met."
    else
        log "RESULT: updates applied. No TARGETS given, so nothing to judge against --"
        log "        compare the diff above with the Tenable finding. Exit 2 to flag"
        log "        that this run was not verified against a required version."
        log "===== END (applied, unverified) ====="
        exit 2
    fi
else
    log "RESULT: no application version changed."
    if [ "$RUM_OK" -eq 0 ]; then
        log "        RUM also failed. See the Adobe log tail above."
        log "===== END (failed) ====="
        exit 1
    fi
    log "        RUM reported success with nothing to apply -- likely already current"
    log "        from RUM's point of view, which is itself a finding if Tenable"
    log "        disagrees (suspect a package built with updates disabled)."
    log "===== END (nothing applied) ====="
    exit 2
fi
log "Re-run a Nessus scan to confirm the relevant plugin clears."
log "===== update-adobe-rum.sh END ====="
exit 0
