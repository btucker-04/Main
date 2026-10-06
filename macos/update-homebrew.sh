#!/bin/bash
# =============================================================================
# update-homebrew.sh  (v1)
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
# Not covered (keep using the dedicated scripts): gems installed into a Ruby
# gem dir by `gem install` (remediate-ruby-gem.sh), official .pkg installs
# outside Homebrew (update-nodejs.sh, update-golang.sh), and apps that are not
# Homebrew casks.
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
#           cask or formula, or a step timed out) -- see the summary
#       1 = brew could not be run at all (no owning user, Rosetta missing)
# =============================================================================

set -uo pipefail
HOME="${HOME:-/var/root}"
export HOME

# =============================================================================
CFG_DRY_RUN="0"
# Also upgrade casks that update themselves (Chrome, Slack, Zoom, ...). brew
# skips those by default, but Tenable reports whatever is on disk, and a user
# who never relaunches the app never gets the self-update.
CFG_GREEDY="1"
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
# =============================================================================
DRY_RUN="${DRY_RUN:-$CFG_DRY_RUN}"
GREEDY="${GREEDY:-$CFG_GREEDY}"
CASK_SUDO="${CASK_SUDO:-$CFG_CASK_SUDO}"
AUTOREMOVE="${AUTOREMOVE:-$CFG_AUTOREMOVE}"
SKIP_FORMULAE="${SKIP_FORMULAE:-$CFG_SKIP_FORMULAE}"
SKIP_CASKS="${SKIP_CASKS:-$CFG_SKIP_CASKS}"
BREW_TIMEOUT="${BREW_TIMEOUT:-$CFG_BREW_TIMEOUT}"
CASK_TIMEOUT="${CASK_TIMEOUT:-$CFG_CASK_TIMEOUT}"

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
        printf '%s\n' "$line"
    done
}

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
    elif grep -qiE 'is not there|It seems there is already an App|already exists' "$1" 2>/dev/null; then
        echo "app on disk does not match brew's record -- reinstall the cask by hand"
    elif grep -qiE 'Operation not permitted|Permission denied' "$1" 2>/dev/null; then
        echo "permission denied (app owned by another user, or App Management privacy block)"
    elif grep -qiE 'SHA256 mismatch|Download failed|Failed to download|curl: \([0-9]+\)' "$1" 2>/dev/null; then
        echo "download failed -- usually transient, next week's run retries"
    else
        echo "see the cask log"
    fi
}

sudoers_line() { printf '%s ALL=(ALL) NOPASSWD: ALL\n' "$1"; }

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

# Run brew for the current prefix. $1 = step label, $2 = timeout seconds,
# rest = brew arguments. Output streams to $STEP_LOG; the filtered tail is
# copied into the main log.
run_brew() {
    step="$1"; limit="$2"; shift 2
    STEP_LOG="$LOG_DIR/homebrew_${PREFIX_TAG}_${step}.log"
    if [ "$TIMED_OUT" -eq 1 ]; then
        log "  brew $* -- skipped (an earlier step hit its time limit)"
        return 124
    fi
    log "  brew $*"
    : > "$STEP_LOG"
    start=$(date +%s)
    # The redirect is the root shell's on purpose: root owns $LOG_DIR.
    # shellcheck disable=SC2024
    sudo -u "$BREW_USER" \
        HOME="$BREW_HOME" \
        PATH="$PREFIX/bin:$PREFIX/sbin:/usr/bin:/bin:/usr/sbin:/sbin" \
        NONINTERACTIVE=1 \
        HOMEBREW_NO_AUTO_UPDATE=1 \
        HOMEBREW_NO_ANALYTICS=1 \
        HOMEBREW_NO_ENV_HINTS=1 \
        HOMEBREW_NO_INSTALL_CLEANUP=1 \
        $ARCH_CMD "$PREFIX/bin/brew" "$@" >>"$STEP_LOG" 2>&1 &
    pid=$!
    waited=0
    while kill -0 "$pid" 2>/dev/null; do
        sleep 2
        waited=$((waited + 2))
        if [ $((waited % 300)) -eq 0 ]; then
            log "    ...still running (${waited}s): $(tail -n 1 "$STEP_LOG" 2>/dev/null)"
        fi
        if [ "$limit" -gt 0 ] && [ "$waited" -ge "$limit" ]; then
            log "    TIME LIMIT (${limit}s) reached -- stopping brew."
            kill "$pid" 2>/dev/null || true
            sleep 5
            kill -9 "$pid" 2>/dev/null || true
            TIMED_OUT=1
            break
        fi
    done
    wait "$pid" 2>/dev/null
    rc=$?
    [ "$TIMED_OUT" -eq 1 ] && rc=124
    tail -n 40 "$STEP_LOG" 2>/dev/null | filter_brew_output | while IFS= read -r l; do
        log "    $l"
    done
    log "    exit $rc after $(( $(date +%s) - start ))s"
    return "$rc"
}

# Quiet query (no step log): prints brew's stdout.
brew_query() {
    sudo -u "$BREW_USER" \
        HOME="$BREW_HOME" \
        PATH="$PREFIX/bin:$PREFIX/sbin:/usr/bin:/bin:/usr/sbin:/sbin" \
        NONINTERACTIVE=1 HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 HOMEBREW_NO_ENV_HINTS=1 \
        $ARCH_CMD "$PREFIX/bin/brew" "$@" 2>/dev/null
}

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
        REMAINING="$REMAINING $(echo $DO_F $DO_C)"
        continue
    fi

    log ""
    log "[3] Formulae"
    if [ -n "$DO_F" ]; then
        # One call, so brew orders dependencies itself.
        # shellcheck disable=SC2086
        run_brew formulae "$BREW_TIMEOUT" upgrade --formula $DO_F || log "  WARNING: formula upgrade reported errors (checked below)."
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
    run_brew cleanup "$BREW_TIMEOUT" cleanup --prune=all || log "  WARNING: cleanup reported errors."
    for f in $(brew_query list --formula); do
        n=$(find "$PREFIX/Cellar/$f" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
        [ "${n:-0}" -gt 1 ] && log "  NOTE     $f still has $n kegs in $PREFIX/Cellar (pinned, or in use by a dependent)"
    done

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

log ""
log "================ SUMMARY ================"
[ -n "$FAILED" ] && log "Failed casks : $FAILED  (reasons above; logs: $LOG_DIR/homebrew_*_cask_<name>.log)"
if [ -n "$REMAINING" ]; then
    log "Still outdated: $REMAINING"
    NEEDS_HUMAN=1
fi
if [ "$FATAL" -eq 1 ]; then
    log "RESULT: at least one Homebrew prefix could not be maintained (see ERROR above)."
    log "===== END ====="
    exit 1
fi
if [ "$NEEDS_HUMAN" -eq 1 ] || [ -n "$FAILED" ]; then
    log "RESULT: brew maintained, but the items above are still outdated."
    log "===== END ====="
    exit 2
fi
log "RESULT: Homebrew, all formulae and all casks are current; superseded kegs removed."
log "===== END ====="
exit 0
