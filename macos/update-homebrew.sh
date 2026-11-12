#!/bin/bash
# =============================================================================
# update-homebrew.sh  (v3.2)
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
#     time limit; once one step hits it the remaining brew steps are
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
# v3, from the fleet runs of 2026-10-14..11-03:
#   * Mosyle shows only the first ~9 KB of output, so 56 of 99 runs lost their
#     SUMMARY (cut mid-word in "Removing: ..."). stdout is now a digest kept
#     under OUTPUT_LIMIT with room reserved for the SUMMARY; brew's own output
#     goes to the main log file and the per-step logs only.
#   * Time asleep no longer counts. A 60s retry wait took 2 hours on CSMB-011
#     (lid closed) and used up RUN_BUDGET; a CLT download was killed at its
#     limit on CSMB-026 with heartbeats ~17 min apart. Limits and the budget
#     now count awake time (kern.sleeptime / kern.waketime), and caffeinate
#     holds off idle sleep while the job runs (KEEP_AWAKE).
#   * A step that ended during a sleep is no longer killed as "timed out"
#     (CLT install on CSMB-036 had printed "Done." and was reported failed);
#     a CLT install that hit its limit is re-checked with pkgutil.
#   * [0] probes github.com / formulae.brew.sh / ghcr.io first and waits up
#     to NETWORK_WAIT for the network. Still offline -> exit 1 "OFFLINE"
#     instead of an hour of DNS failures (many Macs at 07:00 on 10-28).
#   * "Cant connect to the Apple Software Update server" was reported as
#     "Command Line Tools are current"; it is now "not checked".
#   * Steps skipped for the time limit or budget are listed as skipped, not
#     as "brew upgrade failed" / "gem install failed, exit 124".
#   * brew link failures name the formula and the file in the way (ARMB-02,
#     ARMB-09 pkgconf vs pkg-config); a brew update whose only error is such a
#     link failure is no longer "brew update failed".
#   * Untrusted taps are listed in the SUMMARY: brew silently ignores what
#     they installed, so "all current" was not true for those formulae.
#   * Cleanup that stops on "Fix your permissions on: <keg>" (root-owned
#     files in python@3.10 on CSMB-020) chowns that keg to the brew user and
#     runs cleanup once more.
#   * CASK_SUDO also takes a list of cask names, so sudo can be granted only
#     while those casks upgrade.
#
# v3.1, from the fleet runs of 2026-11-04..05:
#   * [5b] ran ruby, ruby@4.0 and ruby@4 -- one keg under three opt/ names --
#     and installed every gem three times. Each keg is now done once.
#   * The network wait gave up after fewer than NETWORK_WAIT awake seconds
#     when Power Nap slept the Mac several times between two probes
#     (CSMB-036, CSMB-026). It now also needs NETWORK_WAIT / NETWORK_POLL
#     probe rounds, and logs when the set of hosts that do not answer
#     changes (ghcr.io alone -> all three on CSMB-036).
#
# v3.2, from the fleet runs of 2026-10-19..11-12:
#   * A cask that failed for want of sudo is not downloaded again while its
#     installed version is unchanged and sudo is still not granted for it
#     (android-ndk + sage + zulu@11 + zulu@8 cost jriegel-mac ~20 minutes of
#     downloads every run, only to fail). It is still listed as failed.
#   * The sudo failure says CFG_CASK_SUDO (Mosyle passes no CASK_SUDO), and
#     the SUMMARY prints the CFG_CASK_SUDO line that covers every such cask.
#   * Untrusted taps with nothing installed from them (ethereum/ethereum,
#     microsoft/git on CSPRMB-21-A) are a Note, not a Problem: brew ignores
#     nothing there. Taps in use name the exact brew trust commands.
#
# Casks are upgraded ONE AT A TIME so one broken cask cannot stop the rest and
# the log names exactly which ones failed. Casks that ship a .pkg installer
# call sudo, which has no password to give in an unattended run. Those fail
# and are listed; CASK_SUDO=1 grants the brew user passwordless sudo for the
# duration of the cask step only (sudoers drop-in, removed on exit, and
# removed at the start of the next run if a kill ever left it behind).
# CASK_SUDO="temurin@21 docker-desktop" grants it only while those upgrade.
#
# CONFIG -- Mosyle passes no environment variables. Edit the block below
# before paste, or pass the same names from a terminal (DRY_RUN=1 ...).
# BREW_PREFIXES, LOG_DIR and SUDOERS_FILE may be set for tests.
#
# Exit: 0 = everything current
#       2 = ran, but something is still outdated (failed / pinned / skipped
#           cask or formula) or a step failed / timed out -- see "Problems"
#       1 = brew could not be run at all (no owning user, Rosetta missing,
#           no network)
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
# Grant the brew user passwordless sudo while casks upgrade, so casks with
# .pkg installers can upgrade unattended. See the header before enabling.
# "0" = never, "1" = for every cask, or cask names ("temurin@21 displaylink")
# = only while those casks upgrade.
CFG_CASK_SUDO="0"
# A cask that failed for want of sudo on the last run, still at the same
# installed version and still not in CASK_SUDO, is listed as failed without
# downloading it again. "0" = try it every run anyway.
CFG_SKIP_KNOWN_SUDO_CASKS="1"
# Uninstall formulae that were only installed as dependencies and are no
# longer needed by anything (old python@3.x, openssl@1.1 ...).
CFG_AUTOREMOVE="0"
# Space-separated names to leave alone, e.g. "docker postgresql@14".
CFG_SKIP_FORMULAE=""
CFG_SKIP_CASKS=""
# Per-brew-step wall-clock limit, seconds. 0 = no limit.
CFG_BREW_TIMEOUT="3600"
CFG_CASK_TIMEOUT="900"
# Budget for the whole run, seconds of AWAKE time (a Mac asleep with its lid
# closed does not use it up). When it runs out the remaining steps are
# skipped and the SUMMARY is still written. 0 = no budget.
CFG_RUN_BUDGET="6600"
# Hold off idle sleep while the job runs (caffeinate -i -s; the display may
# still sleep, and closing the lid still sleeps the Mac). "0" = don't.
CFG_KEEP_AWAKE="1"
# No route to github.com / formulae.brew.sh / ghcr.io at the start (Macs in
# a dark wake at 07:00): wait up to this many awake seconds for the network,
# then stop with OFFLINE (exit 1) instead of an hour of DNS failures.
CFG_NETWORK_WAIT="600"
# Mosyle shows only the first ~9 KB of a script's output. stdout is kept
# below this many bytes, with room saved for the SUMMARY; the full output
# is in LOG_DIR/homebrew_update.log. 0 = no limit (terminal runs).
CFG_OUTPUT_LIMIT="7000"
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
SKIP_KNOWN_SUDO_CASKS="${SKIP_KNOWN_SUDO_CASKS:-$CFG_SKIP_KNOWN_SUDO_CASKS}"
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
KEEP_AWAKE="${KEEP_AWAKE:-$CFG_KEEP_AWAKE}"
NETWORK_WAIT="${NETWORK_WAIT:-$CFG_NETWORK_WAIT}"
OUTPUT_LIMIT="${OUTPUT_LIMIT:-$CFG_OUTPUT_LIMIT}"
# Seconds before a step that failed on a network error is retried once.
RETRY_DELAY="${RETRY_DELAY:-60}"
# Seconds between network probes while waiting for the network.
NETWORK_POLL="${NETWORK_POLL:-30}"
# brew update needs github.com and formulae.brew.sh; bottles come from ghcr.io.
NET_PROBE_HOSTS="github.com formulae.brew.sh ghcr.io"

LOG_DIR="${LOG_DIR:-/var/log/composecure}"
LOG_FILE="$LOG_DIR/homebrew_update.log"
SUDOERS_FILE="${SUDOERS_FILE:-/etc/sudoers.d/zz-composecure-brew}"
# Lines "<prefix> <cask> <installed version>": casks the last run could not
# upgrade without sudo. Delete it to make every cask try again.
SUDO_MEMO="$LOG_DIR/casks_needing_sudo"

# stdout is what Mosyle shows, and it keeps only the first ~9 KB. "body"
# lines stop at OUTPUT_LIMIT minus the SUMMARY's share; "summary" lines may
# use the rest; "final" lines (RESULT, END) always print.
OUT_PHASE="body"
OUT_USED=0
OUT_CUT=0
to_stdout() {
    ts_line="$1"
    [ "${#ts_line}" -gt 300 ] && ts_line="$(printf '%s' "$ts_line" | cut -c1-297)..."
    if [ "${OUTPUT_LIMIT:-0}" -le 0 ] || [ "$OUT_PHASE" = "final" ]; then
        printf '%s\n' "$ts_line"
        return 0
    fi
    ts_cap=$OUTPUT_LIMIT
    [ "$OUT_PHASE" = "body" ] && ts_cap=$(( OUTPUT_LIMIT * 3 / 5 ))
    ts_n=$(( ${#ts_line} + 1 ))
    if [ $(( OUT_USED + ts_n )) -le "$ts_cap" ]; then
        printf '%s\n' "$ts_line"
        OUT_USED=$(( OUT_USED + ts_n ))
    elif [ "$OUT_CUT" -eq 0 ]; then
        OUT_CUT=1
        ts_note="[...] output trimmed for Mosyle; everything is in $LOG_FILE"
        printf '%s\n' "$ts_note"
        OUT_USED=$(( OUT_USED + ${#ts_note} + 1 ))
    fi
}
set_output_phase() { OUT_PHASE="$1"; OUT_CUT=0; }

# log: main log file and (within the limit) stdout. detail: log file only.
log() {
    lg_line="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    printf '%s\n' "$lg_line" >> "$LOG_FILE"
    to_stdout "$lg_line"
}
detail() { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" >> "$LOG_FILE"; }

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
        echo "needs sudo (.pkg installer) -- add it to CFG_CASK_SUDO"
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

# --- awake time -------------------------------------------------------------
# A Mac asleep (lid closed, dark wake) stops brew but not the wall clock: a
# 60s retry wait took 2 hours on CSMB-011 and ate RUN_BUDGET. Every limit
# here counts awake seconds: wall time minus SLEPT, the sleep that
# kern.sleeptime / kern.waketime show between two ticks.

# Seconds field of a timeval sysctl: "{ sec = 1761650000, usec = 12 } Tue ..."
sysctl_sec() {
    sysctl -n "$1" 2>/dev/null | sed -n 's/^{[[:space:]]*sec[[:space:]]*=[[:space:]]*\([0-9][0-9]*\),.*/\1/p'
}

# Seconds asleep between ticks at $1 and $2, given the last sleep $3 and the
# last wake $4 (epoch, empty = unknown). Only a wake inside the gap counts.
slept_between() {
    sb_from="$1"; sb_to="$2"; sb_sleep="${3:-0}"; sb_wake="${4:-0}"
    if [ "$sb_wake" -gt "$sb_from" ] && [ "$sb_wake" -le "$sb_to" ]; then
        sb_start=$sb_from
        if [ "$sb_sleep" -gt "$sb_from" ] && [ "$sb_sleep" -lt "$sb_wake" ]; then
            sb_start=$sb_sleep
        fi
        echo $(( sb_wake - sb_start ))
    else
        echo 0
    fi
}

SLEPT=0
LAST_TICK=$(date +%s)
AWAKE_NOW=$LAST_TICK
# Call in the main shell (not in $(...)) so SLEPT and AWAKE_NOW stick.
tick() {
    tk_now=$(date +%s)
    if [ $(( tk_now - LAST_TICK )) -ge 30 ]; then
        tk_s=$(slept_between "$LAST_TICK" "$tk_now" "$(sysctl_sec kern.sleeptime)" "$(sysctl_sec kern.waketime)")
        SLEPT=$(( SLEPT + tk_s ))
    fi
    LAST_TICK=$tk_now
    AWAKE_NOW=$(( tk_now - SLEPT ))
}

# --- network ----------------------------------------------------------------
# Hosts of $1 that do not answer HTTPS at all (any HTTP status is an answer).
unreachable_hosts() {
    for uh in $1; do
        curl -sS -o /dev/null -I --connect-timeout 10 --max-time 20 "https://$uh" >/dev/null 2>&1 \
            || printf '%s\n' "$uh"
    done
}

# softwareupdate prints these and still exits 0; the list it "found" is empty.
# The apostrophe is U+2019 (3 bytes, and Mosyle runs us with no locale), so
# "[^ ]*" stands in for it.
softwareupdate_unreachable() {
    grep -qiE "Can[^ ]*t connect to the Apple Software Update server|Didn[^ ]*t get a response from the Apple Software Update server|The network connection was lost|A TLS error caused the secure connection to fail|not connected to the internet" "$1" 2>/dev/null
}

# "Command Line Tools for Xcode 27.2-27.2" / "...for Xcode-16.4" -> 27.2 / 16.4
clt_label_version() { printf '%s\n' "${1##*-}" | grep -E '^[0-9]+(\.[0-9]+)*$' || true; }

# Installed CLT version $1 (pkgutil "version: 27.2.0.0.1.1761100000") covers
# label version $2 when its first components are at least $2.
clt_version_covers() {
    [ -n "$1" ] && [ -n "$2" ] || return 1
    cv_n=$(printf '%s\n' "$2" | awk -F. '{print NF}')
    cv_have=$(printf '%s\n' "$1" | cut -d. -f1-"$cv_n")
    [ "$(printf '%s\n%s\n' "$2" "$cv_have" | sort -V | head -n 1)" = "$2" ]
}

# --- brew output parsers ----------------------------------------------------
# One line per "brew link step did not complete": formula, file, and what is
# in the way. brew names the formula only in the ==> line before the error.
#   python@3.13: bin/pip3.13 -- /opt/homebrew/bin/pip3.13 already exists
#   pkgconf: bin/pkg-config -- /opt/homebrew/bin/pkg-config belongs to pkg-config
link_failures() {
    awk '
        { sub(/^[ \t]+/, "") }
        /^==> (Pouring|Upgrading|Reinstalling|Installing) / { f = $3; sub(/--.*/, "", f); next }
        /^Error: The `brew link` step did not complete successfully/ { want = 1; sym = ""; tgt = ""; next }
        want && /^Could not symlink / { sym = $4; next }
        want && /^Target / && tgt == "" { tgt = $2 }
        want && tgt != "" && /already exists/ { print f ": " sym " -- " tgt " already exists"; want = 0; next }
        want && tgt != "" && /is a symlink belonging to/ {
            o = $0; sub(/.*belonging to /, "", o); sub(/\. .*/, "", o); sub(/\.$/, "", o)
            print f ": " sym " -- " tgt " belongs to " o; want = 0; next
        }
        want && /^==> / { print f ": not linked (see the step log)"; want = 0 }
        END { if (want) print f ": not linked (see the step log)" }
    ' "$1" 2>/dev/null | awk '!seen[$0]++' | to_ascii
}

# brew update errors that mean the catalog was not fetched.
update_fetch_failed() {
    grep -qE '^(Error: )?Fetching .* failed!|^fatal:|^Failed to download https://formulae\.brew\.sh' "$1" 2>/dev/null
}

# Taps named under "Warning: The following taps are not trusted:".
untrusted_taps() {
    awk '
        /^Warning: The following taps are not trusted:/ { f = 1; next }
        f && /^Homebrew is currently ignoring/ { f = 0 }
        f { gsub(/^[ \t]+|[ \t]+$/, ""); if ($0 != "") print }
    ' "$1" 2>/dev/null
}

# Installed formulae/casks brew is ignoring: its "brew trust --formula
# <tap>/<name>" lines, without the <user>/<tap>/<cask> placeholders.
untrusted_items() {
    sed -nE 's/^[[:space:]]*brew trust --(formula|cask) ([^<[:space:]]+)[[:space:]]*$/\2/p' "$1" 2>/dev/null
}

# Paths listed after "Error: Could not cleanup old kegs! Fix your permissions on:".
cleanup_permission_paths() {
    awk '
        /Could not cleanup old kegs! Fix your permissions on:/ { f = 1; next }
        f { s = $0; gsub(/^[ \t]+|[ \t]+$/, "", s); if (s ~ /^\//) print s; else f = 0 }
    ' "$1" 2>/dev/null
}

# CASK_SUDO is "1" (every cask), "0"/empty (none) or a list of cask names.
cask_sudo_wanted() {
    case "$2" in
        1) return 0 ;;
        0|"") return 1 ;;
    esac
    case " $(echo $2) " in *" $1 "*) return 0 ;; esac
    return 1
}

# The CFG_CASK_SUDO value that covers the current setting ($1) plus the
# casks ($2) that failed for want of sudo. Nothing when $1 is already "1".
cask_sudo_suggestion() {
    [ "$1" = "1" ] && return 0
    [ -n "$(echo $2)" ] || return 0
    case "$1" in 0|"") set -- "" "$2" ;; esac
    printf '%s\n' $1 $2 | awk 'NF && !seen[$0]++' | tr '\n' ' ' | sed 's/ $//'
}

# Installed version of cask $2 under prefix $1 (its Caskroom version dir).
cask_installed_version() {
    for v in "$1/Caskroom/$2"/*; do
        [ -d "$v" ] && { basename "$v"; return 0; }
    done
}

# Is "<prefix> <cask> <version>" ($1 $2 $3) in the sudo memo file $4?
sudo_memo_has() {
    [ -n "$3" ] && [ -f "$4" ] || return 1
    awk -v p="$1" -v c="$2" -v v="$3" '$1 == p && $2 == c && $3 == v { f = 1 } END { exit !f }' "$4"
}

# Lines of sudo memo $3 to carry over: other prefixes, and casks of prefix
# $1 that are in $2 (still outdated but not tried this run).
sudo_memo_untried() {
    [ -f "$3" ] || return 0
    awk -v p="$1" -v keep=" $(echo $2) " '$1 != p || index(keep, " " $2 " ")' "$3"
}

# Does install receipt $1 name tap $2? No receipt counts as yes, so a
# formula of the same name from homebrew/core does not hide a tap in use.
receipt_from_tap() {
    [ -f "$1" ] || return 0
    tr -d ' \n' < "$1" | grep -iqF "\"tap\":\"$2\""
}

# What prefix $1 has installed from tap $2, as "formula|cask <tap>/<name>",
# found from the tap's own files (brew lists only formulae, never casks).
# Prints "unknown" when the tap's directory is not there to look at.
tap_installed_items() {
    td="$1/Library/Taps/${2%%/*}/homebrew-${2#*/}"
    [ -d "$td" ] || { echo unknown; return 0; }
    find "$td" -maxdepth 4 -name '*.rb' 2>/dev/null | while IFS= read -r rb; do
        n=$(basename "$rb" .rb)
        case "${rb#"$td"/}" in
            Casks/*) kind=cask ;;
            Formula/*|HomebrewFormula/*) kind=formula ;;
            */*) continue ;;
            *) kind=formula ;;
        esac
        if [ "$kind" = "cask" ]; then
            [ -d "$1/Caskroom/$n" ] || continue
            receipt_from_tap "$1/Caskroom/$n/.metadata/INSTALL_RECEIPT.json" "$2" && echo "cask $2/$n"
        else
            [ -d "$1/Cellar/$n" ] || continue
            for k in "$1/Cellar/$n"/*; do
                receipt_from_tap "$k/INSTALL_RECEIPT.json" "$2" && { echo "formula $2/$n"; break; }
            done
        fi
    done | sort -u
}

# Label already recorded for keg $1 in $2 (lines "keg|label"), or nothing.
keg_seen_as() {
    [ -n "$1" ] || return 0
    printf '%s' "$2" | awk -F'|' -v k="$1" '$1 == k { print $2; exit }'
}

# Log line for the probe hosts still down ($1) when that set changes from $2.
network_change_line() {
    [ "$1" = "$2" ] && return 0
    if [ "$1" = "$(echo $3)" ]; then
        echo "Now no host answers ($1)."
    else
        echo "Now no answer from: $1"
    fi
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
OFFLINE=0
SCRIPT_START=$(date +%s)
LAST_TICK=$SCRIPT_START
AWAKE_NOW=$SCRIPT_START
SKIPPED_STEPS=""
NOTES=""
UNTRUSTED_TAPS=""
UNTRUSTED_ITEMS=""
# One line per problem; any of them makes the run exit 2 and is listed in
# the SUMMARY, so a failed update or cleanup can no longer end in "current".
ISSUES=""
add_issue() { ISSUES="${ISSUES}${ISSUES:+
}$1"; }
# Issues that name $1 (a step log), e.g. a time limit the re-check disproved.
drop_issues_for() { ISSUES=$(printf '%s\n' "$ISSUES" | grep -vF -- "$1" || true); }
add_note() { NOTES="${NOTES}${NOTES:+
}$1"; }

if [ "$KEEP_AWAKE" = "1" ] && command -v caffeinate >/dev/null 2>&1; then
    caffeinate -i -s -w $$ >/dev/null 2>&1 &
fi

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

# Mark the current step as not run (time limit or budget) and return 125.
skip_step() {
    log "    skipped ($1)"
    SKIPPED_STEPS="${SKIPPED_STEPS}${SKIPPED_STEPS:+, }$STEP_NAME"
    return 125
}

# Run one command with a time limit. $1 = limit seconds, rest = the command;
# $STEP_TOOL names it in messages. Output streams to $STEP_LOG (appended);
# the filtered tail is copied into the main log file, and only the error
# lines reach stdout. Returns 124 on a time limit, 125 when not started.
# Elapsed time comes from the clock, not from counting sleeps (background
# timers stretch while a Mac idles: a 900s cask limit let sage run 2304s),
# minus the time the Mac was asleep (tick).
run_limited() {
    limit="$1"; shift
    tick
    if [ "$BUDGET_SPENT" -eq 1 ]; then
        skip_step "RUN_BUDGET of ${RUN_BUDGET}s used up"
        return 125
    fi
    if [ "$TIMED_OUT" -eq 1 ]; then
        skip_step "an earlier step hit its time limit"
        return 125
    fi
    if [ "${RUN_BUDGET:-0}" -gt 0 ]; then
        left=$(( RUN_BUDGET - (AWAKE_NOW - SCRIPT_START) ))
        if [ "$left" -le 0 ]; then
            BUDGET_SPENT=1
            skip_step "RUN_BUDGET of ${RUN_BUDGET}s used up"
            return 125
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
    start=$AWAKE_NOW
    slept_before=$SLEPT
    next_beat=$((start + 300))
    "$@" >>"$STEP_LOG" 2>&1 &
    pid=$!
    hit_limit=0
    while kill -0 "$pid" 2>/dev/null; do
        if [ $((AWAKE_NOW - start)) -lt 5 ]; then sleep 0.2; else sleep 2; fi
        tick
        # It may have finished while the Mac slept (CSMB-036's CLT install
        # had printed "Done." and was then killed as over its limit).
        kill -0 "$pid" 2>/dev/null || break
        if [ "$AWAKE_NOW" -ge "$next_beat" ]; then
            log "    ...still running ($((AWAKE_NOW - start))s): $(tail -n 1 "$STEP_LOG" 2>/dev/null | to_ascii | cut -c1-100)"
            next_beat=$((AWAKE_NOW + 300))
        fi
        if [ "$limit" -gt 0 ] && [ $((AWAKE_NOW - start)) -ge "$limit" ]; then
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
    tick
    tail -n "$TAIL_LINES" "$STEP_LOG" 2>/dev/null | filter_brew_output | while IFS= read -r l; do
        detail "    $l"
    done
    if [ "$rc" -ne 0 ]; then
        # Whole log, not just the tail: brew names the formula that broke a
        # batch near the top. A heredoc, not a pipe, so log's byte count sticks.
        while IFS= read -r l; do
            [ -n "$l" ] && log "    ! $l"
        done <<EOF
$(step_error_lines "$STEP_LOG" 0)
EOF
    fi
    rl_slept=$(( SLEPT - slept_before ))
    log "    exit $rc after $(( AWAKE_NOW - start ))s$( [ "$rl_slept" -gt 0 ] && echo " (+${rl_slept}s asleep, not counted)")"
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
    STEP_NAME="$rs_step"
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
        if [ "$rs_rc" -eq 0 ] || [ "$rs_rc" -ge 124 ] || [ "$attempt" -ge 2 ] || ! is_transient_failure "$STEP_LOG"; then
            collect_brew_findings
            return "$rs_rc"
        fi
        log "    network error -- retrying once in ${RETRY_DELAY}s"
        sleep "$RETRY_DELAY"
        echo "----- retry -----" >> "$STEP_LOG"
        attempt=2
    done
}

# Things brew reports in passing that the SUMMARY must name: untrusted taps
# (brew silently skips what they installed) and formulae left unlinked.
collect_brew_findings() {
    UNTRUSTED_TAPS="$UNTRUSTED_TAPS $(untrusted_taps "$STEP_LOG" | tr '\n' ' ')"
    UNTRUSTED_ITEMS="$UNTRUSTED_ITEMS $(untrusted_items "$STEP_LOG" | tr '\n' ' ')"
    while IFS= read -r cf_l; do
        [ -n "$cf_l" ] || continue
        log "    NOT LINKED $cf_l"
        add_issue "$PREFIX: ${cf_l%%:*} is installed but not linked (${cf_l#*: }); check what owns the file, then as $BREW_USER: brew link --overwrite ${cf_l%%:*}"
    done <<EOF
$(link_failures "$STEP_LOG")
EOF
}

# Run a root command (xcodebuild, softwareupdate) through the same limits.
run_root_step() {
    step="$1"; limit="$2"; shift 2
    STEP_LOG="$LOG_DIR/homebrew_system_${step}.log"
    : > "$STEP_LOG"
    STEP_TOOL=$(basename "$1")
    STEP_NAME="$step"
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
    seen_kegs=""
    for gembin in "$PREFIX"/opt/ruby/bin/gem "$PREFIX"/opt/ruby@*/bin/gem; do
        [ -x "$gembin" ] || continue
        found_ruby=1
        rlabel=$(basename "$(dirname "$(dirname "$gembin")")")
        # opt/ruby@4 and opt/ruby@4.0 are aliases of opt/ruby: one keg, one
        # gem path, so the gems would be installed three times over.
        rkeg=$(cd "$(dirname "$gembin")/.." 2>/dev/null && pwd -P)
        rsame=$(keg_seen_as "$rkeg" "$seen_kegs")
        if [ -n "$rsame" ]; then
            log "  $rlabel  same keg as $rsame ($rkeg) -- already done."
            continue
        fi
        seen_kegs="${seen_kegs}${rkeg}|${rlabel}
"
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
                if [ "$gi_rc" -ne 0 ] && [ "$gi_rc" -ne 125 ]; then
                    add_issue "$rlabel: gem install $g ${req:+($req) }failed, exit $gi_rc -- $STEP_LOG"
                fi
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
    if ! xdev=$(xcode-select -p 2>/dev/null); then
        log "  No developer tools selected (xcode-select -p failed)."
        return 0
    fi
    case "$xdev" in *.app/Contents/Developer) ;; *) return 0 ;; esac
    if xcodebuild -license check >/dev/null 2>&1; then
        log "  Xcode license accepted ($xdev)."
        return 0
    fi
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

clt_installed_version() {
    pkgutil --pkg-info=com.apple.pkg.CLTools_Executables 2>/dev/null | sed -n 's/^version:[[:space:]]*//p'
}

update_command_line_tools() {
    if ! pkgutil --pkg-info=com.apple.pkg.CLTools_Executables >/dev/null 2>&1; then
        log "  Command Line Tools package not installed -- not checked (brew uses ${xdev:-the selected developer dir})."
        return 0
    fi
    if ! run_root_step clt_list 600 softwareupdate --list; then
        TIMED_OUT=0
        log "  softwareupdate --list failed -- Command Line Tools not checked."
        add_note "Command Line Tools not checked (softwareupdate --list failed)"
        return 0
    fi
    if softwareupdate_unreachable "$STEP_LOG"; then
        log "  Apple Software Update server not reachable -- Command Line Tools not checked."
        add_note "Command Line Tools not checked (Apple Software Update server not reachable)"
        return 0
    fi
    clt_label=$(clt_update_label < "$STEP_LOG")
    if [ -z "$clt_label" ]; then
        log "  Command Line Tools are current ($(clt_installed_version))."
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
        # softwareupdate can finish the install and still be stopped or exit
        # non-zero; what pkgutil reports is what brew will see.
        ci_have=$(clt_installed_version)
        if clt_version_covers "$ci_have" "$(clt_label_version "$clt_label")"; then
            drop_issues_for "$STEP_LOG"
            log "  Installed $clt_label (pkgutil reports $ci_have)."
            return 0
        fi
        add_issue "Command Line Tools update '$clt_label' failed to install (pkgutil reports ${ci_have:-nothing}) -- $STEP_LOG"
    else
        add_issue "Command Line Tools update pending: softwareupdate --install '$clt_label' (or set UPDATE_CLT=1)"
    fi
}

# Wait until every probe host answers, at most NETWORK_WAIT. Sets OFFLINE=1
# when none answer; a partial outage is only reported. The awake clock alone
# is not enough here: Power Nap sleeps and wakes several times between two
# ticks and only the last sleep is booked (CSMB-036 / CSMB-026 gave up after
# "1121s" / "1044s" of a 600s wait), so also require NETWORK_WAIT worth of
# probe rounds.
check_network() {
    cn_waited_from=$AWAKE_NOW
    cn_said=0
    cn_rounds=0
    cn_prev=""
    cn_need=0
    [ "${NETWORK_POLL:-0}" -gt 0 ] && cn_need=$(( ${NETWORK_WAIT:-0} / NETWORK_POLL ))
    while :; do
        cn_down=$(unreachable_hosts "$NET_PROBE_HOSTS" | tr '\n' ' ' | sed 's/ $//')
        [ -z "$cn_down" ] && break
        tick
        [ $(( AWAKE_NOW - cn_waited_from )) -ge "${NETWORK_WAIT:-0}" ] && [ "$cn_rounds" -ge "$cn_need" ] && break
        if [ "$cn_said" -eq 0 ]; then
            log "  No answer from: $cn_down -- waiting up to ${NETWORK_WAIT}s for the network."
            cn_said=1
        else
            cn_line=$(network_change_line "$cn_down" "$cn_prev" "$NET_PROBE_HOSTS")
            [ -n "$cn_line" ] && log "  $cn_line"
        fi
        cn_prev=$cn_down
        sleep "$NETWORK_POLL"
        cn_rounds=$(( cn_rounds + 1 ))
        tick
    done
    tick
    cn_waited=$(( AWAKE_NOW - cn_waited_from ))
    if [ -z "$cn_down" ]; then
        log "  Network OK ($NET_PROBE_HOSTS answer)$( [ "$cn_said" -eq 1 ] && echo " after ${cn_waited}s")."
    elif [ "$cn_down" = "$(echo $NET_PROBE_HOSTS)" ]; then
        OFFLINE=1
        log "  OFFLINE: none of $NET_PROBE_HOSTS answered at the last of $(( cn_rounds + 1 )) probe rounds, ${NETWORK_POLL}s apart (${cn_waited}s awake). Not running brew."
    else
        log "  WARNING: no answer from $cn_down -- brew steps that need it will fail."
        add_issue "no answer from $cn_down at the start (proxy, filter or DNS?); brew steps that need it fail"
    fi
}

log ""
log "[0] Network, Xcode license and Command Line Tools"
check_network
if [ "$OFFLINE" -eq 0 ]; then
    check_xcode_license
    update_command_line_tools
fi
TIMED_OUT=0

NO_AUTOREMOVE_ENV="HOMEBREW_NO_AUTOREMOVE=1"
[ "$AUTOREMOVE" = "1" ] && NO_AUTOREMOVE_ENV=""

GREEDY_FLAG=""
[ "$GREEDY" = "1" ] && GREEDY_FLAG="--greedy"

grant_sudo() {
    sudoers_line "$BREW_USER" > "$SUDOERS_FILE.tmp"
    chmod 440 "$SUDOERS_FILE.tmp"
    if visudo -cf "$SUDOERS_FILE.tmp" >/dev/null 2>&1; then
        mv -f "$SUDOERS_FILE.tmp" "$SUDOERS_FILE"
        log "  Temporary passwordless sudo granted to $BREW_USER${1:+ for $1} (removed on exit)."
    else
        rm -f "$SUDOERS_FILE.tmp"
        log "  WARNING: sudoers drop-in failed validation -- not granting sudo."
    fi
}

FAILED_REASONS=""
SUDO_CASKS=""
[ "$OFFLINE" -eq 1 ] && PREFIXES=""
for PREFIX in $PREFIXES; do
    PREFIX_TAG=$(echo "$PREFIX" | tr '/' '_' | sed 's/^_//')
    UNTRUSTED_TAPS=""
    UNTRUSTED_ITEMS=""
    MEMO_KEEP=""
    TRIED_C=""
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
    run_brew update "$BREW_TIMEOUT" update
    up_rc=$?
    if [ "$up_rc" -eq 125 ]; then
        log "  brew update did not run -- upgrading against the existing catalog."
    elif [ "$up_rc" -eq 124 ]; then
        log "  WARNING: brew update was stopped -- upgrading against the existing catalog."
        add_issue "$PREFIX: brew update did not finish (stopped at its time limit), so newer versions may be missing -- $STEP_LOG"
    elif [ "$up_rc" -ne 0 ]; then
        # brew update reinstalls formulae built for another macOS; a link
        # conflict there exits 1 after the catalog WAS fetched (ARMB-09).
        if ! update_fetch_failed "$STEP_LOG" && [ -n "$(link_failures "$STEP_LOG")" ]; then
            log "  Catalog updated; the formula brew reinstalled afterwards is not linked (NOT LINKED above)."
        else
            log "  WARNING: brew update failed -- upgrading against the existing catalog."
            add_issue "$PREFIX: brew update failed, so newer versions may be missing from the outdated list -- $STEP_LOG"
        fi
    fi

    log ""
    log "[2] Outdated"
    OUT_F=$(brew_query outdated --formula --quiet)
    OUT_C=$(brew_query outdated --cask --quiet $GREEDY_FLAG)
    PINNED=$(brew_query list --pinned)
    brew_query outdated --formula --verbose | while IFS= read -r l; do [ -n "$l" ] && detail "  formula  $l"; done
    brew_query outdated --cask --verbose $GREEDY_FLAG | while IFS= read -r l; do [ -n "$l" ] && detail "  cask     $l"; done
    [ -n "$OUT_F" ] && log "  formulae ($(echo $OUT_F | wc -w | tr -d ' ')): $(echo $OUT_F)"
    [ -n "$OUT_C" ] && log "  casks ($(echo $OUT_C | wc -w | tr -d ' ')): $(echo $OUT_C)"
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
        run_brew formulae "$BREW_TIMEOUT" upgrade --formula $DO_F
        fo_rc=$?
        if [ "$fo_rc" -ne 0 ] && [ "$fo_rc" -ne 125 ]; then
            log "  WARNING: formula upgrade reported errors (the ! lines above; what is left is listed in [6])."
            first_err=$(grep -E '^Error:' "$STEP_LOG" 2>/dev/null | grep -vF 'The `brew link` step did not complete' | head -n 1 | to_ascii)
            if [ -n "$first_err" ] || [ -z "$(link_failures "$STEP_LOG")" ]; then
                add_issue "$PREFIX: brew upgrade --formula failed${first_err:+: $first_err} -- $STEP_LOG"
            fi
        fi
    else
        log "  Nothing to upgrade."
    fi

    log ""
    log "[4] Casks (one at a time)"
    if [ -n "$DO_C" ] && [ "$TIMED_OUT" -eq 1 ]; then
        log "  Skipped (an earlier step hit its time limit): $(echo $DO_C)"
        SKIPPED_STEPS="${SKIPPED_STEPS}${SKIPPED_STEPS:+, }casks ($(echo $DO_C))"
    elif [ -n "$DO_C" ]; then
        [ "$CASK_SUDO" = "1" ] && grant_sudo
        for c in $DO_C; do
            if [ "$CASK_SUDO" != "1" ] && cask_sudo_wanted "$c" "$CASK_SUDO"; then
                grant_sudo "$c"
            fi
            cv=$(cask_installed_version "$PREFIX" "$c")
            if [ "$SKIP_KNOWN_SUDO_CASKS" = "1" ] && ! cask_sudo_wanted "$c" "$CASK_SUDO" \
                && sudo_memo_has "$PREFIX" "$c" "$cv" "$SUDO_MEMO"; then
                reason="needs sudo (.pkg installer) -- add it to CFG_CASK_SUDO (not downloaded again: $cv failed the same way last run)"
                log "  FAILED   $c -- $reason"
                FAILED="$FAILED $c"
                FAILED_REASONS="${FAILED_REASONS}${FAILED_REASONS:+
}$c -- $reason"
                SUDO_CASKS="$SUDO_CASKS $c"
                MEMO_KEEP="${MEMO_KEEP}$PREFIX $c $cv
"
                TRIED_C="$TRIED_C $c"
                continue
            fi
            # shellcheck disable=SC2086
            run_brew "cask_$c" "$CASK_TIMEOUT" upgrade --cask $GREEDY_FLAG "$c"
            ca_rc=$?
            [ "$ca_rc" -ne 125 ] && TRIED_C="$TRIED_C $c"
            if [ "$ca_rc" -eq 0 ]; then
                log "  OK       $c"
            elif [ "$ca_rc" -eq 125 ]; then
                log "  SKIPPED  $c"
            elif [ "$REPAIR_CASKS" = "1" ] && cask_app_missing "$STEP_LOG" \
                && run_brew "cask_${c}_uninstall" "$CASK_TIMEOUT" uninstall --cask --force "$c" \
                && run_brew "cask_${c}_install" "$CASK_TIMEOUT" install --cask "$c"; then
                log "  REPAIRED $c (brew's copy of the app was missing; reinstalled)"
            else
                reason=$(cask_failure_reason "$STEP_LOG")
                log "  FAILED   $c -- $reason"
                FAILED="$FAILED $c"
                FAILED_REASONS="${FAILED_REASONS}${FAILED_REASONS:+
}$c -- $reason"
                case "$reason" in
                    "needs sudo"*)
                        SUDO_CASKS="$SUDO_CASKS $c"
                        [ -n "$cv" ] && MEMO_KEEP="${MEMO_KEEP}$PREFIX $c $cv
" ;;
                esac
            fi
            [ "$CASK_SUDO" != "1" ] && remove_sudoers
            # One slow cask should not cost the rest of the list.
            TIMED_OUT=0
        done
        remove_sudoers
    else
        log "  Nothing to upgrade."
    fi
    # Casks not tried this run (time limit, budget) keep their old entry.
    { sudo_memo_untried "$PREFIX" "$(list_minus "$DO_C" "$TRIED_C")" "$SUDO_MEMO"; printf '%s' "$MEMO_KEEP"; } > "$SUDO_MEMO.tmp"
    if [ -s "$SUDO_MEMO.tmp" ]; then mv -f "$SUDO_MEMO.tmp" "$SUDO_MEMO"; else rm -f "$SUDO_MEMO.tmp" "$SUDO_MEMO"; fi

    if [ "$AUTOREMOVE" = "1" ]; then
        log ""
        log "[5a] brew autoremove (unused dependencies)"
        run_brew autoremove "$BREW_TIMEOUT" autoremove || true
    fi

    log ""
    log "[5] brew cleanup (superseded kegs, old portable-ruby, download cache)"
    # Old Cellar/<formula>/<version> kegs are what Tenable keeps reporting
    # after an upgrade; this is the step that clears them.
    run_brew cleanup "$BREW_TIMEOUT" cleanup --prune=all
    cl_rc=$?
    # A superseded keg with files root left behind (python@3.10 __pycache__
    # on CSMB-020): brew names it; hand it back to the brew user, run again.
    cl_fixed=0
    if [ "$cl_rc" -ne 0 ] && [ "$cl_rc" -lt 124 ]; then
        while IFS= read -r cp_path; do
            case "$cp_path" in "$PREFIX"/*) ;; *) continue ;; esac
            case "$cp_path" in *..*) continue ;; esac
            [ -e "$cp_path" ] || continue
            if chown -R "$BREW_USER" "$cp_path" 2>/dev/null; then
                log "  FIXED    $cp_path had files brew could not remove -- chowned to $BREW_USER"
                cl_fixed=1
            else
                log "  WARNING: could not chown $cp_path to $BREW_USER"
            fi
        done <<EOF
$(cleanup_permission_paths "$STEP_LOG")
EOF
    fi
    if [ "$cl_fixed" -eq 1 ]; then
        run_brew cleanup_retry "$BREW_TIMEOUT" cleanup --prune=all
        cl_rc=$?
    fi
    if [ "$cl_rc" -eq 0 ]; then
        for f in $(brew_query list --formula); do
            n=$(find "$PREFIX/Cellar/$f" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
            [ "${n:-0}" -gt 1 ] && log "  NOTE     $f still has $n kegs in $PREFIX/Cellar (pinned, or in use by a dependent)"
        done
    elif [ "$cl_rc" -ne 125 ]; then
        log "  WARNING: cleanup reported errors -- superseded kegs may still be on disk."
        add_issue "$PREFIX: brew cleanup failed, so old kegs Tenable reports may remain -- $STEP_LOG"
    fi

    maintain_ruby_gems

    log ""
    log "[6] Still outdated"
    LEFT=$(printf '%s\n%s\n' "$(brew_query outdated --formula --quiet)" "$(brew_query outdated --cask --quiet $GREEDY_FLAG)")
    LEFT=$(echo $LEFT)
    if [ -n "$LEFT" ]; then
        log "  $LEFT"
        REMAINING="$REMAINING $LEFT"
    else
        log "  None."
    fi
    UT=$(printf '%s\n' $UNTRUSTED_TAPS | awk 'NF && !seen[$0]++' | tr '\n' ' ' | sed 's/ $//')
    if [ -n "$UT" ]; then
        UI=$(printf '%s\n' $UNTRUSTED_ITEMS | awk 'NF && !seen[$0]++')
        USED_T=""; UNUSED_T=""; TRUST=""; UNKNOWN=0
        for t in $UT; do
            found=$(tap_installed_items "$PREFIX" "$t")
            listed=$(printf '%s\n' "$UI" | awk -v t="$t/" 'index($0, t) == 1 { print "formula " $0 }')
            items=$(printf '%s\n%s\n' "$listed" "$found" | grep -v '^unknown$' | awk 'NF && !seen[$0]++')
            if [ -n "$items" ]; then
                USED_T="$USED_T $t"
                TRUST="${TRUST}${items}
"
            elif [ "$found" = "unknown" ]; then
                USED_T="$USED_T $t"; UNKNOWN=1
            else
                UNUSED_T="$UNUSED_T $t"
            fi
        done
        USED_T=$(echo $USED_T); UNUSED_T=$(echo $UNUSED_T)
        TRUST_NAMES=$(printf '%s' "$TRUST" | awk 'NF { print $2 }' | tr '\n' ' ' | sed 's/ $//')
        [ "$UNKNOWN" -eq 1 ] && TRUST_NAMES="${TRUST_NAMES}${TRUST_NAMES:+ and }what else they installed"
        TRUST_CMDS=$(printf '%s' "$TRUST" | awk 'NF { printf "%sbrew trust --%s %s", (n++ ? "; " : ""), $1, $2 }')
        if [ -n "$USED_T" ]; then
            log "  UNTRUSTED taps: $USED_T -- brew ignores $TRUST_NAMES"
            add_issue "$PREFIX: untrusted taps ($USED_T) -- brew neither upgrades nor lists $TRUST_NAMES. As $BREW_USER: ${TRUST_CMDS:-brew trust --formula <tap>/<name>}${TRUST_CMDS:+;} or brew untap <tap>"
        fi
        if [ -n "$UNUSED_T" ]; then
            log "  UNTRUSTED taps with nothing installed: $UNUSED_T"
            add_note "$PREFIX: untrusted taps with nothing installed from them ($UNUSED_T) -- nothing is ignored; as $BREW_USER 'brew untap $UNUSED_T' stops brew's warning"
        fi
    fi
done

REMAINING=$(printf '%s\n' $REMAINING | sort -u | tr '\n' ' ' | sed 's/ $//')
FAILED=$(echo $FAILED)

[ "$SAW_XCODE_LICENSE" -eq 1 ] && add_issue "brew output says the Xcode license is not accepted -- run 'sudo xcodebuild -license accept'"
[ "$SAW_OLD_CLT" -eq 1 ] && add_issue "brew output says the Command Line Tools are outdated -- softwareupdate --list, then install the 'Command Line Tools for Xcode' label"
if [ "$BUDGET_SPENT" -eq 1 ]; then
    add_issue "RUN_BUDGET (${RUN_BUDGET}s awake) used up; not run: ${SKIPPED_STEPS:-the remaining steps}"
elif [ -n "$SKIPPED_STEPS" ]; then
    add_issue "not run after a time limit: $SKIPPED_STEPS"
fi
ISSUES=$(printf '%s\n' "$ISSUES" | awk 'NF && !seen[$0]++')
tick

log ""
set_output_phase summary
log "================ SUMMARY ================"
log "Logs: $LOG_DIR (homebrew_update.log has everything; step logs named below)"
[ "$SLEPT" -gt 0 ] && log "Mac was asleep ${SLEPT}s of $(( $(date +%s) - SCRIPT_START ))s (not counted against limits)"
[ "$GEMS_REMOVED" -gt 0 ] && log "Ruby gem specs removed: $GEMS_REMOVED"
if [ -n "$FAILED" ]; then
    log "Failed casks:"
    while IFS= read -r l; do [ -n "$l" ] && log "  - $l"; done <<EOF
$FAILED_REASONS
EOF
    SUGGEST=$(cask_sudo_suggestion "$CASK_SUDO" "$SUDO_CASKS")
    [ -n "$SUGGEST" ] && log "  To upgrade the sudo casks unattended, set in the CONFIG block: CFG_CASK_SUDO=\"$SUGGEST\""
fi
if [ -n "$REMAINING" ]; then
    log "Still outdated: $REMAINING"
    NEEDS_HUMAN=1
fi
if [ -n "$ISSUES" ]; then
    log "Problems:"
    while IFS= read -r l; do log "  - $l"; done <<EOF
$(printf '%s\n' "$ISSUES" | sed "s#$LOG_DIR/##g")
EOF
    NEEDS_HUMAN=1
fi
if [ -n "$NOTES" ]; then
    while IFS= read -r l; do [ -n "$l" ] && log "Note: $l"; done <<EOF
$NOTES
EOF
fi
set_output_phase final
if [ "$OFFLINE" -eq 1 ]; then
    log "RESULT: OFFLINE -- no network for ${NETWORK_WAIT}s; nothing was changed. The next scheduled run tries again."
    log "===== END ====="
    exit 1
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
