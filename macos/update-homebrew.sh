#!/bin/bash
# =============================================================================
# update-homebrew.sh  (v2)
# Weekly Homebrew maintenance: update brew, upgrade every outdated formula and
# cask, then remove superseded kegs.
# Platform : macOS (bash 3.2 compatible) | Deploy: Mosyle (runs as root)
#
# Why one job instead of per-finding scripts: most of the Mac findings handled
# so far were outdated Homebrew packages, and in several of them the PATCHED
# version was already installed:
#   * gstreamer (326245/326246), jriegel-mac: Tenable keys on the Cellar
#     version directory, and `brew upgrade` leaves the old keg beside the new
#     one until `brew cleanup` runs.
#   * rexml / net-imap (265895, 321503, 313278), CSMB-017 / ARMB-02 / ARMB-09:
#     vulnerable specs sat in old Cellar/ruby/<ver> kegs and superseded
#     portable-ruby trees -- both are removed by `brew cleanup`.
#   * node / go / git etc.: plain `brew upgrade`.
# So the order here is upgrade THEN cleanup, every week.
#
# Step 5b then handles the gems that ship inside Homebrew Ruby (net-imap,
# rexml -- CFG_RUBY_GEMS). brew never updates those: the copy in the Ruby keg
# is whatever that Ruby release bundled, and lib/ruby/gems/<abi> is not
# brew's at all, so they came back every scan cycle. For each Homebrew Ruby
# the step installs the newest gem release and deletes older copies, and it
# clears gem dirs whose Ruby is gone. It needs no fixed-version list, so
# new advisories for the same gems are covered without editing the script.
#
# Not covered (keep using the dedicated scripts): official .pkg installs
# outside Homebrew (update-nodejs.sh, update-golang.sh), per-user Ruby/Node
# managers (rbenv, asdf, nvm), macOS system Ruby (/Library/Ruby), and apps
# that are not Homebrew casks.
#
# Lessons carried over from the other brew scripts:
#   * brew refuses to run as root -> every brew call runs as the user who OWNS
#     that Homebrew prefix (owner of <prefix>/bin/brew), not the console user.
#   * brew output goes to a per-step file, not $(...) -- a Mosyle timeout kill
#     otherwise discards everything (jriegel-mac 2026-09-14). Each step has a
#     wall-clock limit; once one step hits it the remaining brew steps are
#     skipped so the job ends on our terms with a meaningful exit code.
#   * brew's download bars and new/deleted formula catalogs are dropped from
#     the summary log (CSMB-036).
#   * Apple Silicon Macs that still carry an Intel /usr/local Homebrew get
#     BOTH prefixes maintained; the Intel one runs under Rosetta.
#
# v2, from the first fleet runs (2026-10-07..14):
#   * [0] accepts an unaccepted Xcode license and installs a pending Command
#     Line Tools update before brew runs (both made brew fail or rebuild
#     from source for hours).
#   * Time limits are wall-clock and stop brew's whole process tree; a whole-
#     run budget (RUN_BUDGET) ends the job before Mosyle cuts the log off.
#   * A step that fails on a network error is retried once.
#   * Failed update / formula upgrade / cleanup / gem install, timeouts and
#     Xcode / CLT problems are listed under "Problems" and exit 2 -- a failed
#     brew update used to end in "all current".
#   * `brew cleanup` no longer autoremoves unless AUTOREMOVE=1.
#   * Root-owned gem dirs are handed back to the brew user before gem install.
#
# Casks are upgraded ONE AT A TIME so one broken cask cannot stop the rest and
# the log names exactly which ones failed. Casks that ship a .pkg installer
# call sudo, which has no password to give in an unattended run. Those fail
# and are listed; CASK_SUDO=1 grants the brew user passwordless sudo for the
# duration of the run only (sudoers drop-in, removed on exit, and removed at
# the start of the next run if a kill ever left it behind).
#
# CONFIG -- Mosyle passes no environment variables. Edit the block below
# before paste, or pass the same names from a terminal (DRY_RUN=1 ...).
# BREW_PREFIXES, LOG_DIR and SUDOERS_FILE may be set for tests.
#
# Exit: 0 = everything current
#       2 = ran, but something is still outdated (failed / pinned / skipped
#           cask or formula) or a step failed / timed out -- see "Problems"
#       1 = brew could not be run at all (no owning user, Rosetta missing)
# =============================================================================

set -uo pipefail
HOME="${HOME:-/var/root}"
export HOME

# =============================================================================
CFG_DRY_RUN="0"
# Also upgrade casks that update themselves (Chrome, Slack, Zoom, ...). Off:
# those apps keep themselves current and rarely show up in Tenable; brew
# skips them by default. Set "1" to force them too.
CFG_GREEDY="0"
# Grant the brew user passwordless sudo while this script runs, so casks with
# .pkg installers can upgrade unattended. See the header before enabling.
CFG_CASK_SUDO="0"
# Uninstall formulae that were only installed as dependencies and are no
# longer needed by anything (old python@3.x, openssl@1.1 ...).
CFG_AUTOREMOVE="0"
# Space-separated names to leave alone, e.g. "docker postgresql@14".
CFG_SKIP_FORMULAE=""
CFG_SKIP_CASKS=""
# Per-brew-step wall-clock limit, seconds. 0 = no limit.
CFG_BREW_TIMEOUT="3600"
CFG_CASK_TIMEOUT="900"
# Wall-clock budget for the whole run, seconds. Keep it below Mosyle's own
# limit for the command so the job stops itself and still writes a SUMMARY
# (CSPRMB-21-A's log just ended mid-run). 0 = no budget.
CFG_RUN_BUDGET="6600"
# Full Xcode installed but its license never accepted: every brew command
# fails ("You have not agreed to the Xcode license", ARMB-09, CSPRMB-28).
# "1" accepts it as root (xcodebuild -license accept); "0" only reports it.
CFG_ACCEPT_XCODE_LICENSE="1"
# Install a pending Command Line Tools update from softwareupdate before brew
# runs. Outdated CLT make brew rebuild formulae from source or refuse to
# (CSPRMB-21-A, CSPRMB-28, CSMB-017). "0" only reports it.
CFG_UPDATE_CLT="1"
# A cask whose installed app brew can no longer find ("App source ... is not
# there", kitty on ARMB-02) fails every week. "1" force-uninstalls brew's
# record and installs the cask again; "0" only reports it.
CFG_REPAIR_CASKS="1"
# Gems bundled with Homebrew Ruby that Tenable keeps reporting. For each
# Homebrew Ruby: install the newest release, then delete older copies of the
# gem wherever that Ruby loads from (its keg and lib/ruby/gems/<abi>), plus
# copies in gem dirs whose Ruby is gone. ":branch" = keep the newest of EACH
# installed major.minor (net-imap backports fixes to 0.4 / 0.5 / 0.6);
# ":latest" = keep only the newest (rexml fixes ship on 3.4 only).
# Empty = skip this step. macOS system Ruby (/Library/Ruby) is never touched.
CFG_RUBY_GEMS="net-imap:branch rexml:latest"
# =============================================================================
DRY_RUN="${DRY_RUN:-$CFG_DRY_RUN}"
GREEDY="${GREEDY:-$CFG_GREEDY}"
CASK_SUDO="${CASK_SUDO:-$CFG_CASK_SUDO}"
AUTOREMOVE="${AUTOREMOVE:-$CFG_AUTOREMOVE}"
SKIP_FORMULAE="${SKIP_FORMULAE:-$CFG_SKIP_FORMULAE}"
SKIP_CASKS="${SKIP_CASKS:-$CFG_SKIP_CASKS}"
BREW_TIMEOUT="${BREW_TIMEOUT:-$CFG_BREW_TIMEOUT}"
CASK_TIMEOUT="${CASK_TIMEOUT:-$CFG_CASK_TIMEOUT}"
RUN_BUDGET="${RUN_BUDGET:-$CFG_RUN_BUDGET}"
ACCEPT_XCODE_LICENSE="${ACCEPT_XCODE_LICENSE:-$CFG_ACCEPT_XCODE_LICENSE}"
UPDATE_CLT="${UPDATE_CLT:-$CFG_UPDATE_CLT}"
REPAIR_CASKS="${REPAIR_CASKS:-$CFG_REPAIR_CASKS}"
RUBY_GEMS="${RUBY_GEMS-$CFG_RUBY_GEMS}"
# Seconds before a step that failed on a network error is retried once.
RETRY_DELAY="${RETRY_DELAY:-60}"

LOG_DIR="${LOG_DIR:-/var/log/composecure}"
LOG_FILE="$LOG_DIR/homebrew_update.log"
SUDOERS_FILE="${SUDOERS_FILE:-/etc/sudoers.d/zz-composecure-brew}"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }

filter_brew_output() {
    skip=0
    noted=0
    while IFS= read -r line || [ -n "$line" ]; do
        [ -n "$line" ] || continue
        case "$line" in
            "==> New Formulae"*|"==> New Casks"*|"==> Deleted Formulae"*|"==> Deleted Casks"*|"==> Renamed Formulae"*|"==> Renamed Casks"*)
                skip=1
                if [ "$noted" -eq 0 ]; then
                    echo "(omitted brew catalog: new, renamed and deleted formulae/casks)"
                    noted=1
                fi
                continue
                ;;
            "==>"*)
                skip=0
                ;;
        esac
        [ "$skip" -eq 1 ] && continue
        if printf '%s\n' "$line" | grep -qE '^[#=O. -]*[0-9]+([.][0-9]+)?%$'; then
            continue
        fi
        if printf '%s\n' "$line" | grep -qE '^[#=O. -]+$'; then
            continue
        fi
        printf '%s\n' "$line" | to_ascii
    done
}

# Mosyle shows multi-byte characters (brew's beer mug) as "????".
to_ascii() { LC_ALL=C tr -cd '\11\12\40-\176'; }

# A failure worth one retry: DNS, reset or timed-out connections (brew update
# on CSMB-026 "Could not resolve host: github.com", reset cask downloads).
is_transient_failure() {
    grep -qiE 'Could not resolve host|Connection reset by peer|Failed to connect to|Operation timed out|Connection timed out|Empty reply from server|SSL_ERROR_SYSCALL|unexpected disconnect|early EOF|curl: \((6|7|28|35|52|56)\)' "$1" 2>/dev/null
}

# Distinct "Error:" / "fatal:" lines of a step log that fall outside the
# $2-line tail already copied to the main log, at most 5. Brew reports the
# formula that broke a batch upgrade near the top, not at the end.
step_error_lines() {
    se_total=$(wc -l < "$1" 2>/dev/null | tr -d ' ')
    awk -v stop=$(( ${se_total:-0} - $2 )) 'NR <= stop && /^(Error|fatal):/ && !seen[$0]++' "$1" 2>/dev/null \
        | head -n 5 | to_ascii
}

xcode_license_blocked() {
    grep -qiE 'agreed to the Xcode license|Xcode license agreement|xcodebuild -license' "$1" 2>/dev/null
}

clt_outdated() {
    grep -qiE 'Command Line Tools( \(CLT\))? (are|is) (too )?outdated|update your Command Line Tools|CLT are too outdated' "$1" 2>/dev/null
}

# Newest "Command Line Tools for Xcode-NN" label in `softwareupdate --list`.
clt_update_label() {
    sed -n 's/^[*[:space:]]*Label:[[:space:]]*\(Command Line Tools.*[^[:space:]]\)[[:space:]]*$/\1/p' \
        | sort -V | tail -n 1
}

# PIDs below $1, children before their parents. A subshell, so the
# recursion cannot clobber the caller's loop variable.
descendants() (
    for d_child in $(pgrep -P "$1" 2>/dev/null); do
        descendants "$d_child"
        echo "$d_child"
    done
)

# Words of $1 that are not in $2 (both space/newline separated), in order.
list_minus() {
    for w in $1; do
        case " $(echo $2) " in *" $w "*) ;; *) printf '%s\n' "$w" ;; esac
    done
}

# Words of $1 that ARE in $2.
list_and() {
    for w in $1; do
        case " $(echo $2) " in *" $w "*) printf '%s\n' "$w" ;; esac
    done
}

valid_macos_user() {
    case "$1" in
        ""|root|loginwindow|_mbsetupuser) return 1 ;;
    esac
    echo "$1" | grep -Eq '^[A-Za-z0-9._-]+$' || return 1
    return 0
}

# Classify a failed cask's output so the summary says what to do about it.
cask_failure_reason() {
    if grep -qiE 'a terminal is required|a password is required|no tty present|askpass' "$1" 2>/dev/null; then
        echo "needs sudo (.pkg installer) -- set CASK_SUDO=1"
    elif cask_app_missing "$1"; then
        echo "brew's installed copy of the app is missing -- reinstall the cask (REPAIR_CASKS=1)"
    elif grep -qiE 'It seems there is already an App|already exists' "$1" 2>/dev/null; then
        echo "app on disk does not match brew's record -- reinstall the cask by hand"
    elif grep -qiE 'Operation not permitted|Permission denied' "$1" 2>/dev/null; then
        echo "permission denied (app owned by another user, or App Management privacy block)"
    elif grep -qiE 'SHA256 mismatch|Download failed|Failed to download|curl: \([0-9]+\)' "$1" 2>/dev/null; then
        echo "download failed -- usually transient, next week's run retries"
    else
        echo "see the cask log"
    fi
}

cask_app_missing() { grep -qiE 'App source .* is not there' "$1" 2>/dev/null; }

sudoers_line() { printf '%s ALL=(ALL) NOPASSWD: ALL\n' "$1"; }

# $1 = a Ruby's ABI (3.4.0), rest = its gem path entries -> entries that
# belong to that ABI. Every Ruby gem dir ends in it (keg, lib/ruby/gems/<abi>,
# ~/.local/share/gem/ruby/<abi>); one that does not is another Ruby's.
gem_dirs_for_abi() {
    ga_abi="$1"; shift
    for ga_dir in "$@"; do
        case "$ga_dir" in */"$ga_abi") printf '%s\n' "$ga_dir" ;; esac
    done
}

# --- Ruby gem helpers (step 5b) ---------------------------------------------
# "net-imap:branch" -> branch, anything else -> latest.
gem_mode() { case "$1" in *:branch) echo branch ;; *) echo latest ;; esac; }

# Release versions from one `gem list NAME --exact --local` line, e.g.
# "net-imap (0.6.7, default: 0.4.9.1)" -> 0.6.7 / 0.4.9.1. Prereleases dropped.
gem_list_versions() {
    echo "$1" | sed -n 's/^[^(]*(\(.*\))[[:space:]]*$/\1/p' | tr ',' '\n' \
        | sed 's/default://; s/^[[:space:]]*//; s/[[:space:]]*$//' \
        | grep -E '^[0-9]+(\.[0-9]+)*$' || true
}

# $1 = gem name, $2 = path to NAME-VERSION.gemspec -> VERSION (release only).
gem_spec_version() {
    basename "$2" | sed -n "s/^$1-\([0-9][0-9.]*[0-9]\)\.gemspec$/\1/p"
}

# Requirements to `gem install`, one per line. branch: newest of each
# installed major.minor ("~> 0.4.0" = newest 0.4.x), because net-imap ships
# fixes on every maintained branch and an app pinned to 0.4 cannot use 0.6.
# latest: one empty line = plain `gem install` (newest release).
gem_install_requirements() {
    if [ "$1" = "branch" ]; then
        printf '%s\n' $2 | cut -d. -f1,2 | sort -u | sed 's/^\(.*\)$/~> \1.0/'
    else
        echo ""
    fi
}

# Version that should remain for a spec at $3, given installed versions $2.
gem_keep_version() {
    if [ "$1" = "branch" ]; then
        br=$(echo "$3" | cut -d. -f1,2)
        printf '%s\n' $2 | awk -F. -v b="$br" '($1"."$2)==b' | sort -V | tail -n 1
    else
        printf '%s\n' $2 | sort -V | tail -n 1
    fi
}

# Stop $1 and everything it started. Killing only sudo left brew's ruby and
# curl children running past the limit, so the tree is collected first
# (killing a parent reparents its children to launchd).
kill_tree() {
    kt_pids="$(descendants "$1") $1"
    # shellcheck disable=SC2086
    kill $kt_pids 2>/dev/null || true
    sleep 5
    kt_pids="$kt_pids $(descendants "$1")"
    # shellcheck disable=SC2086
    kill -9 $kt_pids 2>/dev/null || true
}

if [ "${HOMEBREW_UPDATE_SELFTEST:-0}" = "1" ]; then
    return 0 2>/dev/null || exit 0
fi

mkdir -p "$LOG_DIR"
cd /tmp || exit 1

REMAINING=""
FAILED=""
NEEDS_HUMAN=0
FATAL=0
TIMED_OUT=0
BUDGET_SPENT=0
GEMS_REMOVED=0
SAW_XCODE_LICENSE=0
SAW_OLD_CLT=0
SCRIPT_START=$(date +%s)
# One line per problem; any of them makes the run exit 2 and is listed in
# the SUMMARY, so a failed update or cleanup can no longer end in "current".
ISSUES=""
add_issue() { ISSUES="${ISSUES}${ISSUES:+
}$1"; }

remove_sudoers() {
    if [ -f "$SUDOERS_FILE" ]; then
        rm -f "$SUDOERS_FILE" && log "Removed temporary sudoers grant $SUDOERS_FILE"
    fi
}
trap remove_sudoers EXIT
trap 'remove_sudoers; exit 1' INT TERM HUP

log "===== update-homebrew.sh START ====="
log "Host: $(hostname -s 2>/dev/null || hostname)   macOS $(sw_vers -productVersion 2>/dev/null || echo '?')   arch $(uname -m)"
log "DryRun=$DRY_RUN  Greedy=$GREEDY  CaskSudo=$CASK_SUDO  Autoremove=$AUTOREMOVE"
[ -n "$SKIP_FORMULAE" ] && log "Skipping formulae: $SKIP_FORMULAE"
[ -n "$SKIP_CASKS" ] && log "Skipping casks: $SKIP_CASKS"

if [ -f "$SUDOERS_FILE" ]; then
    log "WARNING: a sudoers grant from an earlier, interrupted run was still present."
    remove_sudoers
fi

PREFIXES=""
for p in ${BREW_PREFIXES:-/opt/homebrew /usr/local}; do
    [ -x "$p/bin/brew" ] && PREFIXES="$PREFIXES $p"
done
if [ -z "$PREFIXES" ]; then
    log "Homebrew not installed (checked /opt/homebrew and /usr/local). Nothing to do."
    log "===== END ====="
    exit 0
fi

TAIL_LINES=40

# Run one command with a wall-clock limit. $1 = limit seconds, rest = the
# command; $STEP_TOOL names it in messages. Output streams to $STEP_LOG (appended); the
# filtered tail is copied into the main log. Returns 124 on a time limit.
# Elapsed time comes from the clock, not from counting sleeps: background
# timers stretch while a Mac idles, and a 900s cask limit let sage run 2304s.
run_limited() {
    limit="$1"; shift
    if [ "$TIMED_OUT" -eq 1 ] || [ "$BUDGET_SPENT" -eq 1 ]; then
        log "    skipped (an earlier step hit its time limit)"
        return 124
    fi
    if [ "${RUN_BUDGET:-0}" -gt 0 ]; then
        left=$(( RUN_BUDGET - ($(date +%s) - SCRIPT_START) ))
        if [ "$left" -le 0 ]; then
            BUDGET_SPENT=1
            log "    skipped (RUN_BUDGET of ${RUN_BUDGET}s used up)"
            return 124
        fi
        if [ "$limit" -le 0 ] || [ "$limit" -gt "$left" ]; then
            limit=$left
            limit_is_budget=1
        else
            limit_is_budget=0
        fi
    else
        limit_is_budget=0
    fi
    start=$(date +%s)
    next_beat=$((start + 300))
    "$@" >>"$STEP_LOG" 2>&1 &
    pid=$!
    hit_limit=0
    now=$start
    while kill -0 "$pid" 2>/dev/null; do
        if [ $((now - start)) -lt 5 ]; then sleep 0.2; else sleep 2; fi
        now=$(date +%s)
        if [ "$now" -ge "$next_beat" ]; then
            log "    ...still running ($((now - start))s): $(tail -n 1 "$STEP_LOG" 2>/dev/null | to_ascii)"
            next_beat=$((now + 300))
        fi
        if [ "$limit" -gt 0 ] && [ $((now - start)) -ge "$limit" ]; then
            if [ "$limit_is_budget" -eq 1 ]; then
                log "    RUN_BUDGET (${RUN_BUDGET}s) used up -- stopping $STEP_TOOL and skipping the remaining steps."
                BUDGET_SPENT=1
            else
                log "    TIME LIMIT (${limit}s) reached -- stopping $STEP_TOOL."
                add_issue "$STEP_TOOL hit its ${limit}s time limit -- $STEP_LOG"
            fi
            kill_tree "$pid"
            hit_limit=1
            break
        fi
    done
    wait "$pid" 2>/dev/null
    rc=$?
    if [ "$hit_limit" -eq 1 ]; then
        TIMED_OUT=1
        rc=124
    fi
    tail -n "$TAIL_LINES" "$STEP_LOG" 2>/dev/null | filter_brew_output | while IFS= read -r l; do
        log "    $l"
    done
    if [ "$rc" -ne 0 ]; then
        step_error_lines "$STEP_LOG" "$TAIL_LINES" | while IFS= read -r l; do
            log "    (earlier) $l"
        done
    fi
    log "    exit $rc after $(( $(date +%s) - start ))s"
    return "$rc"
}

# Run a Homebrew tool (brew, or a Homebrew Ruby's gem) as the prefix owner.
# $1 = step label, $2 = timeout seconds, $3 = binary, rest = arguments.
# A failure caused by the network is retried once after RETRY_DELAY.
run_step() {
    rs_step="$1"; rs_limit="$2"; rs_bin="$3"; shift 3
    STEP_LOG="$LOG_DIR/homebrew_${PREFIX_TAG}_${rs_step}.log"
    : > "$STEP_LOG"
    STEP_TOOL=$(basename "$rs_bin")
    log "  $STEP_TOOL $*"
    attempt=1
    while :; do
        # The redirect is the root shell's on purpose: root owns $LOG_DIR.
        # HOMEBREW_NO_AUTOREMOVE: `brew cleanup` autoremoves by default, which
        # uninstalled openssl@3 on CSMB-026 with AUTOREMOVE=0.
        # shellcheck disable=SC2086
        run_limited "$rs_limit" sudo -u "$BREW_USER" \
            HOME="$BREW_HOME" \
            PATH="$PREFIX/bin:$PREFIX/sbin:/usr/bin:/bin:/usr/sbin:/sbin" \
            LANG=en_US.UTF-8 \
            NONINTERACTIVE=1 \
            HOMEBREW_NO_AUTO_UPDATE=1 \
            HOMEBREW_NO_ANALYTICS=1 \
            HOMEBREW_NO_ENV_HINTS=1 \
            HOMEBREW_NO_EMOJI=1 \
            HOMEBREW_NO_INSTALL_CLEANUP=1 \
            $NO_AUTOREMOVE_ENV \
            $ARCH_CMD "$rs_bin" "$@"
        rs_rc=$?
        xcode_license_blocked "$STEP_LOG" && SAW_XCODE_LICENSE=1
        clt_outdated "$STEP_LOG" && SAW_OLD_CLT=1
        if [ "$rs_rc" -eq 0 ] || [ "$rs_rc" -eq 124 ] || [ "$attempt" -ge 2 ] || ! is_transient_failure "$STEP_LOG"; then
            return "$rs_rc"
        fi
        log "    network error -- retrying once in ${RETRY_DELAY}s"
        sleep "$RETRY_DELAY"
        echo "----- retry -----" >> "$STEP_LOG"
        attempt=2
    done
}

# Run a root command (xcodebuild, softwareupdate) through the same limits.
run_root_step() {
    step="$1"; limit="$2"; shift 2
    STEP_LOG="$LOG_DIR/homebrew_system_${step}.log"
    : > "$STEP_LOG"
    STEP_TOOL=$(basename "$1")
    log "  $*"
    run_limited "$limit" "$@"
}

run_brew() {
    step="$1"; limit="$2"; shift 2
    run_step "$step" "$limit" "$PREFIX/bin/brew" "$@"
}

# Quiet query (no step log): prints the tool's stdout. $1 = binary.
tool_query() {
    qbin="$1"; shift
    sudo -u "$BREW_USER" \
        HOME="$BREW_HOME" \
        PATH="$(dirname "$qbin"):$PREFIX/bin:$PREFIX/sbin:/usr/bin:/bin:/usr/sbin:/sbin" \
        NONINTERACTIVE=1 HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 HOMEBREW_NO_ENV_HINTS=1 \
        $ARCH_CMD "$qbin" "$@" 2>/dev/null
}
brew_query() { tool_query "$PREFIX/bin/brew" "$@"; }

# Delete a gemspec and its unpacked payload (root; Cellar kegs are user-owned).
remove_gem_spec() {
    rs_spec="$1"; rs_gem="$2"; rs_ver="$3"; rs_why="$4"
    log "  REMOVE   $rs_spec  ($rs_why)"
    if rm -f "$rs_spec"; then
        rs_payload="$(dirname "$(dirname "$rs_spec")")/gems/${rs_gem}-${rs_ver}"
        [ -d "$rs_payload" ] && rm -rf "$rs_payload"
        GEMS_REMOVED=$((GEMS_REMOVED + 1))
    else
        log "           rm failed -- leaving it."
        NEEDS_HUMAN=1
    fi
}

# Gem dirs inside $PREFIX must belong to the brew user, or `gem install`
# stops with Gem::FilePermissionError (rexml-3.4.4.gemspec on ARMB-02 /
# ARMB-09, left root-owned by an earlier gem run as root). $1 = gem path.
# Dirs outside the prefix (the user's home) are not touched.
repair_gem_dirs() {
    OLDIFS=$IFS; IFS=':'
    for rg_dir in $1; do
        IFS=$OLDIFS
        case "$rg_dir" in "$PREFIX"/*) ;; *) continue ;; esac
        [ -d "$rg_dir" ] || continue
        for rg_bad in "$rg_dir"/specifications/*.gemspec; do
            [ -d "$rg_bad" ] || continue
            if [ "$DRY_RUN" = "1" ]; then
                log "  [DRY_RUN] would remove $rg_bad (a directory, not a gemspec)"
            else
                rm -rf "$rg_bad" && log "  FIXED    removed $rg_bad (a directory where gem writes a gemspec)"
            fi
        done
        rg_n=$(find "$rg_dir" ! -user "$BREW_USER" 2>/dev/null | wc -l | tr -d ' ')
        [ "${rg_n:-0}" -gt 0 ] || continue
        if [ "$DRY_RUN" = "1" ]; then
            log "  [DRY_RUN] would chown $rg_n entries in $rg_dir to $BREW_USER"
        elif chown -R "$BREW_USER" "$rg_dir" 2>/dev/null; then
            log "  FIXED    $rg_n entries in $rg_dir were not owned by $BREW_USER -- chowned"
        else
            log "  WARNING: could not chown $rg_dir to $BREW_USER"
            add_issue "$rg_dir is not owned by $BREW_USER and chown failed (gem install will hit FilePermissionError)"
        fi
    done
    IFS=$OLDIFS
}

# Ruby gems that ship INSIDE Homebrew's Ruby (net-imap, rexml, ...). brew
# upgrades the interpreter, but the copy bundled in the keg is whatever that
# Ruby release shipped, and gems in <prefix>/lib/ruby/gems/<abi> are never
# touched by brew at all. Tenable reads every .gemspec on disk, so a stale
# copy anywhere a Ruby can load from re-raises the finding (CSPRMB-28,
# ARMB-02, ARMB-09, CSPRMB-21-A).
maintain_ruby_gems() {
    [ -n "$RUBY_GEMS" ] || return 0
    log ""
    log "[5b] Ruby gems bundled with Homebrew Ruby: $RUBY_GEMS"
    found_ruby=0
    for gembin in "$PREFIX"/opt/ruby/bin/gem "$PREFIX"/opt/ruby@*/bin/gem; do
        [ -x "$gembin" ] || continue
        found_ruby=1
        rlabel=$(basename "$(dirname "$(dirname "$gembin")")")
        gpath=$(tool_query "$gembin" environment gempath)
        rbin="$(dirname "$gembin")/ruby"
        abi=""
        [ -x "$rbin" ] && abi=$(tool_query "$rbin" -e 'print RbConfig::CONFIG["ruby_version"]')
        log "  $rlabel  ruby ABI ${abi:-?}  gem path: $gpath"
        if [ -n "$abi" ]; then
            OLDIFS=$IFS; IFS=':'
            # shellcheck disable=SC2086
            own=$(gem_dirs_for_abi "$abi" $gpath | tr '\n' ':' | sed 's/:$//')
            IFS=$OLDIFS
            if [ -z "$own" ]; then
                log "  WARNING: $rlabel's gem reports another Ruby's gem dirs -- skipping it."
                add_issue "$rlabel: 'gem environment gempath' has no $abi dir ($gpath); check that $gembin runs $rbin"
                continue
            fi
            gpath=$own
        fi
        repair_gem_dirs "$gpath"
        for entry in $RUBY_GEMS; do
            g="${entry%%:*}"
            mode=$(gem_mode "$entry")
            vers=$(gem_list_versions "$(tool_query "$gembin" list "$g" --exact --local)")
            if [ -z "$vers" ]; then
                log "  $rlabel  $g: not installed"
                continue
            fi
            log "  $rlabel  $g: $(echo $vers) (mode: $mode)"
            if [ "$DRY_RUN" = "1" ]; then
                log "  [DRY_RUN] would install the newest $g $( [ "$mode" = branch ] && echo 'per branch') and remove older specs"
                continue
            fi
            while IFS= read -r req; do
                if [ -n "$req" ]; then
                    run_step "gem_${rlabel}_${g}" "$CASK_TIMEOUT" "$gembin" install "$g" -v "$req" --no-document
                else
                    run_step "gem_${rlabel}_${g}" "$CASK_TIMEOUT" "$gembin" install "$g" --no-document
                fi
                gi_rc=$?
                [ "$gi_rc" -ne 0 ] && add_issue "$rlabel: gem install $g ${req:+($req) }failed, exit $gi_rc -- $STEP_LOG"
                TIMED_OUT=0
            done <<EOF
$(gem_install_requirements "$mode" "$vers")
EOF
            vers=$(gem_list_versions "$(tool_query "$gembin" list "$g" --exact --local)")
            OLDIFS=$IFS; IFS=':'
            for gdir in $gpath; do
                IFS=$OLDIFS
                for spec in "$gdir"/specifications/"$g"-*.gemspec "$gdir"/specifications/default/"$g"-*.gemspec; do
                    [ -f "$spec" ] || continue
                    v=$(gem_spec_version "$g" "$spec")
                    [ -n "$v" ] || continue
                    keep=$(gem_keep_version "$mode" "$vers" "$v")
                    [ "$v" = "$keep" ] && continue
                    [ -n "$keep" ] || continue
                    case "$spec" in
                        */specifications/default/*)
                            log "  DEFAULT  $spec ($v; $keep installed) -- ships with $rlabel, never deleted."
                            log "           Fixed only by a newer Ruby; brew upgrade already ran."
                            continue ;;
                    esac
                    remove_gem_spec "$spec" "$g" "$v" "$keep installed in $rlabel"
                done
            done
            IFS=$OLDIFS
        done
    done
    [ "$found_ruby" -eq 0 ] && log "  No Homebrew Ruby (opt/ruby, opt/ruby@*) in $PREFIX."

    # Gem dirs left by a Ruby that brew has since upgraded away (ARMB-09):
    # no interpreter can load them, and gem install never writes there again.
    for adir in "$PREFIX"/lib/ruby/gems/*; do
        [ -d "$adir/specifications" ] || continue
        abi=$(basename "$adir")
        live=0
        for k in "$PREFIX"/Cellar/ruby*/*/lib/ruby/"$abi"; do [ -d "$k" ] && live=1 && break; done
        [ "$live" -eq 1 ] && continue
        for entry in $RUBY_GEMS; do
            g="${entry%%:*}"
            for spec in "$adir"/specifications/"$g"-*.gemspec; do
                [ -f "$spec" ] || continue
                v=$(gem_spec_version "$g" "$spec")
                [ -n "$v" ] || continue
                if [ "$DRY_RUN" = "1" ]; then
                    log "  [DRY_RUN] would remove orphaned $spec (no Ruby $abi left)"
                    continue
                fi
                remove_gem_spec "$spec" "$g" "$v" "orphaned: no Homebrew Ruby with ABI $abi"
            done
        done
    done
}

# Full Xcode with an unaccepted license blocks every brew call; the CLT-only
# developer dir has no license to accept.
check_xcode_license() {
    xdev=$(xcode-select -p 2>/dev/null) || return 0
    case "$xdev" in *.app/Contents/Developer) ;; *) return 0 ;; esac
    xcodebuild -license check >/dev/null 2>&1 && return 0
    if [ "$DRY_RUN" = "1" ]; then
        log "  [DRY_RUN] Xcode license not accepted ($xdev) -- would accept it"
    elif [ "$ACCEPT_XCODE_LICENSE" = "1" ]; then
        if run_root_step xcode_license 120 xcodebuild -license accept; then
            log "  Xcode license accepted ($xdev)."
            return 0
        fi
        add_issue "Xcode license not accepted and 'xcodebuild -license accept' failed -- brew cannot build or clean up"
    else
        add_issue "Xcode license not accepted ($xdev) -- run 'sudo xcodebuild -license accept' or set ACCEPT_XCODE_LICENSE=1"
    fi
}

update_command_line_tools() {
    pkgutil --pkg-info=com.apple.pkg.CLTools_Executables >/dev/null 2>&1 || return 0
    if ! run_root_step clt_list 600 softwareupdate --list; then
        log "  softwareupdate --list failed -- Command Line Tools not checked."
        return 0
    fi
    clt_label=$(clt_update_label < "$STEP_LOG")
    if [ -z "$clt_label" ]; then
        log "  Command Line Tools are current."
        return 0
    fi
    if [ "$DRY_RUN" = "1" ]; then
        log "  [DRY_RUN] would install $clt_label"
    elif [ "$UPDATE_CLT" = "1" ]; then
        if run_root_step clt_install "$BREW_TIMEOUT" softwareupdate --install "$clt_label" --verbose; then
            log "  Installed $clt_label."
            return 0
        fi
        TIMED_OUT=0
        add_issue "Command Line Tools update '$clt_label' failed to install -- $STEP_LOG"
    else
        add_issue "Command Line Tools update pending: softwareupdate --install '$clt_label' (or set UPDATE_CLT=1)"
    fi
}

log ""
log "[0] Xcode license and Command Line Tools"
check_xcode_license
update_command_line_tools
TIMED_OUT=0

NO_AUTOREMOVE_ENV="HOMEBREW_NO_AUTOREMOVE=1"
[ "$AUTOREMOVE" = "1" ] && NO_AUTOREMOVE_ENV=""

GREEDY_FLAG=""
[ "$GREEDY" = "1" ] && GREEDY_FLAG="--greedy"

for PREFIX in $PREFIXES; do
    PREFIX_TAG=$(echo "$PREFIX" | tr '/' '_' | sed 's/^_//')
    log ""
    log "################ $PREFIX ################"

    BREW_USER=$(stat -f "%Su" "$PREFIX/bin/brew" 2>/dev/null || true)
    if ! valid_macos_user "$BREW_USER"; then
        BREW_USER=$(stat -f "%Su" "$PREFIX/Cellar" 2>/dev/null || true)
    fi
    if ! valid_macos_user "$BREW_USER"; then
        log "ERROR: no non-root owner for $PREFIX (brew will not run as root). Skipping."
        FATAL=1
        continue
    fi
    BREW_HOME=$(dscl . -read "/Users/$BREW_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
    [ -n "$BREW_HOME" ] || BREW_HOME="/Users/$BREW_USER"
    log "Brew user: $BREW_USER (owner of $PREFIX/bin/brew)"

    ARCH_CMD=""
    if [ "$PREFIX" = "/usr/local" ] && [ "$(uname -m)" = "arm64" ]; then
        if arch -x86_64 /usr/bin/true 2>/dev/null; then
            ARCH_CMD="arch -x86_64"
            log "Intel Homebrew on Apple Silicon -- running under Rosetta."
        else
            log "ERROR: Intel Homebrew at /usr/local but Rosetta is not installed. Skipping."
            log "       Install Rosetta (softwareupdate --install-rosetta --agree-to-license)"
            log "       or migrate this prefix's packages to /opt/homebrew and remove it."
            FATAL=1
            continue
        fi
    fi

    log ""
    log "[1] brew update"
    if ! run_brew update "$BREW_TIMEOUT" update; then
        log "  WARNING: brew update failed -- upgrading against the existing catalog."
        add_issue "$PREFIX: brew update failed, so newer versions may be missing from the outdated list -- $STEP_LOG"
    fi

    log ""
    log "[2] Outdated"
    OUT_F=$(brew_query outdated --formula --quiet)
    OUT_C=$(brew_query outdated --cask --quiet $GREEDY_FLAG)
    PINNED=$(brew_query list --pinned)
    brew_query outdated --formula --verbose | while IFS= read -r l; do [ -n "$l" ] && log "  formula  $l"; done
    brew_query outdated --cask --verbose $GREEDY_FLAG | while IFS= read -r l; do [ -n "$l" ] && log "  cask     $l"; done
    [ -z "$OUT_F$OUT_C" ] && log "  Everything is current."

    PINNED_OUT=$(list_and "$OUT_F" "$PINNED")
    SKIPPED_F=$(list_and "$OUT_F" "$SKIP_FORMULAE")
    SKIPPED_C=$(list_and "$OUT_C" "$SKIP_CASKS")
    DO_F=$(list_minus "$(list_minus "$OUT_F" "$PINNED")" "$SKIP_FORMULAE")
    DO_C=$(list_minus "$OUT_C" "$SKIP_CASKS")
    for n in $PINNED_OUT; do log "  PINNED   $n -- 'brew unpin $n' to let this job upgrade it"; REMAINING="$REMAINING $n"; done
    for n in $SKIPPED_F $SKIPPED_C; do log "  SKIP     $n (in SKIP list)"; REMAINING="$REMAINING $n"; done

    if [ "$DRY_RUN" = "1" ]; then
        log ""
        log "[DRY_RUN] Would upgrade formulae: $(echo $DO_F)"
        log "[DRY_RUN] Would upgrade casks:    $(echo $DO_C)"
        log "[DRY_RUN] Would run brew cleanup"
        maintain_ruby_gems
        REMAINING="$REMAINING $(echo $DO_F $DO_C)"
        continue
    fi

    log ""
    log "[3] Formulae"
    if [ -n "$DO_F" ]; then
        # One call, so brew orders dependencies itself.
        # shellcheck disable=SC2086
        if ! run_brew formulae "$BREW_TIMEOUT" upgrade --formula $DO_F; then
            log "  WARNING: formula upgrade reported errors (the Error lines above; what is left is listed in [6])."
            first_err=$(grep -m1 -E '^Error:' "$STEP_LOG" 2>/dev/null | to_ascii)
            add_issue "$PREFIX: brew upgrade --formula failed${first_err:+: $first_err} -- $STEP_LOG"
        fi
    else
        log "  Nothing to upgrade."
    fi

    log ""
    log "[4] Casks (one at a time)"
    if [ -n "$DO_C" ] && [ "$TIMED_OUT" -eq 1 ]; then
        log "  Skipped (an earlier step hit its time limit): $(echo $DO_C)"
    elif [ -n "$DO_C" ]; then
        if [ "$CASK_SUDO" = "1" ]; then
            sudoers_line "$BREW_USER" > "$SUDOERS_FILE.tmp"
            chmod 440 "$SUDOERS_FILE.tmp"
            if visudo -cf "$SUDOERS_FILE.tmp" >/dev/null 2>&1; then
                mv -f "$SUDOERS_FILE.tmp" "$SUDOERS_FILE"
                log "  Temporary passwordless sudo granted to $BREW_USER (removed on exit)."
            else
                rm -f "$SUDOERS_FILE.tmp"
                log "  WARNING: sudoers drop-in failed validation -- not granting sudo."
            fi
        fi
        for c in $DO_C; do
            # shellcheck disable=SC2086
            if run_brew "cask_$c" "$CASK_TIMEOUT" upgrade --cask $GREEDY_FLAG "$c"; then
                log "  OK       $c"
            elif [ "$REPAIR_CASKS" = "1" ] && cask_app_missing "$STEP_LOG" \
                && run_brew "cask_${c}_uninstall" "$CASK_TIMEOUT" uninstall --cask --force "$c" \
                && run_brew "cask_${c}_install" "$CASK_TIMEOUT" install --cask "$c"; then
                log "  REPAIRED $c (brew's copy of the app was missing; reinstalled)"
            else
                reason=$(cask_failure_reason "$STEP_LOG")
                log "  FAILED   $c -- $reason"
                FAILED="$FAILED $c"
            fi
            # One slow cask should not cost the rest of the list.
            TIMED_OUT=0
        done
        remove_sudoers
    else
        log "  Nothing to upgrade."
    fi

    if [ "$AUTOREMOVE" = "1" ]; then
        log ""
        log "[5a] brew autoremove (unused dependencies)"
        run_brew autoremove "$BREW_TIMEOUT" autoremove || true
    fi

    log ""
    log "[5] brew cleanup (superseded kegs, old portable-ruby, download cache)"
    # Old Cellar/<formula>/<version> kegs are what Tenable keeps reporting
    # after an upgrade; this is the step that clears them.
    if run_brew cleanup "$BREW_TIMEOUT" cleanup --prune=all; then
        for f in $(brew_query list --formula); do
            n=$(find "$PREFIX/Cellar/$f" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
            [ "${n:-0}" -gt 1 ] && log "  NOTE     $f still has $n kegs in $PREFIX/Cellar (pinned, or in use by a dependent)"
        done
    else
        log "  WARNING: cleanup reported errors -- superseded kegs may still be on disk."
        add_issue "$PREFIX: brew cleanup failed, so old kegs Tenable reports may remain -- $STEP_LOG"
    fi

    maintain_ruby_gems

    log ""
    log "[6] Still outdated"
    LEFT=$(printf '%s\n%s\n' "$(brew_query outdated --formula --quiet)" "$(brew_query outdated --cask --quiet $GREEDY_FLAG)")
    LEFT=$(echo $LEFT)
    if [ -n "$LEFT" ]; then
        for n in $LEFT; do log "  $n"; done
        REMAINING="$REMAINING $LEFT"
    else
        log "  None."
    fi
done

REMAINING=$(printf '%s\n' $REMAINING | sort -u | tr '\n' ' ' | sed 's/ $//')
FAILED=$(echo $FAILED)

[ "$SAW_XCODE_LICENSE" -eq 1 ] && add_issue "brew output says the Xcode license is not accepted -- run 'sudo xcodebuild -license accept'"
[ "$SAW_OLD_CLT" -eq 1 ] && add_issue "brew output says the Command Line Tools are outdated -- softwareupdate --list, then install the 'Command Line Tools for Xcode' label"
[ "$BUDGET_SPENT" -eq 1 ] && add_issue "RUN_BUDGET (${RUN_BUDGET}s) used up; the steps after that were skipped"
ISSUES=$(printf '%s\n' "$ISSUES" | awk 'NF && !seen[$0]++')

log ""
log "================ SUMMARY ================"
[ "$GEMS_REMOVED" -gt 0 ] && log "Ruby gem specs removed: $GEMS_REMOVED"
[ -n "$FAILED" ] && log "Failed casks : $FAILED  (reasons above; logs: $LOG_DIR/homebrew_*_cask_<name>.log)"
if [ -n "$REMAINING" ]; then
    log "Still outdated: $REMAINING"
    NEEDS_HUMAN=1
fi
if [ -n "$ISSUES" ]; then
    log "Problems:"
    printf '%s\n' "$ISSUES" | while IFS= read -r l; do log "  - $l"; done
    NEEDS_HUMAN=1
fi
if [ "$FATAL" -eq 1 ]; then
    log "RESULT: at least one Homebrew prefix could not be maintained (see ERROR above)."
    log "===== END ====="
    exit 1
fi
if [ "$NEEDS_HUMAN" -eq 1 ] || [ -n "$FAILED" ]; then
    log "RESULT: brew ran, but the items above still need attention."
    log "===== END ====="
    exit 2
fi
log "RESULT: Homebrew, all formulae and all casks are current; superseded kegs removed."
log "===== END ====="
exit 0
