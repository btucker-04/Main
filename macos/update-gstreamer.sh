#!/bin/bash
# =============================================================================
# update-gstreamer.sh  (v1)
# Remediates : Homebrew GStreamer < 1.28.5
# Nessus Plugin IDs : 326245 (GStreamer < 1.28.4), 326246 (GStreamer < 1.28.5)
# CVEs       : CVE-2026-53703, CVE-2026-53704, CVE-2026-53705,
#              CVE-2026-52721, CVE-2026-52722
# Platform   : macOS (bash 3.2 compatible) | Deploy: Mosyle (runs as root)
#
# Written for JRIEGEL-MAC (2026-09-14 Tenable group export):
#   Path              : /opt/homebrew/Cellar/gstreamer/1.26.2
#   Installed version : 1.26.2
#   Fixed version     : 1.28.5  (plugin 326246; 326245 is satisfied by the same)
#
# Tenable keys on the Cellar VERSION DIRECTORY, not on `brew list`.
# `brew upgrade gstreamer` installs 1.28.x alongside 1.26.2 and leaves the
# old keg -- the finding stays until that folder is removed. Cleanup is
# gated on a patched keg (>= 1.28.5) being present first.
#
# Homebrew now bundles gst-plugins-* inside the gstreamer formula (formerly
# gst-plugins-good/ugly/bad/base, gst-libav, ...). Leftover split-plugin
# kegs are removed once a patched gstreamer keg exists.
#
# CONFIG -- Mosyle passes no environment variables. Edit the block below
# before paste, or pass DRY_RUN=1 / FORCE_CLOSE=1 / NO_INSTALL=1 from a
# terminal. BREW_PREFIX may be set for tests.
# =============================================================================

set -uo pipefail
HOME="${HOME:-/var/root}"
export HOME

# =============================================================================
CFG_DRY_RUN="0"
CFG_FORCE_CLOSE="0"
CFG_NO_INSTALL="0"
# Per-brew-step wall-clock limit, seconds. gstreamer bundles gst-plugins-rs,
# so a source build (no matching bottle) runs for hours and Mosyle kills the
# job mid-flight. Ending on our own terms keeps the log and the exit code
# meaningful. 0 = no limit.
CFG_BREW_TIMEOUT="2700"
# =============================================================================
DRY_RUN="${DRY_RUN:-$CFG_DRY_RUN}"
FORCE_CLOSE="${FORCE_CLOSE:-$CFG_FORCE_CLOSE}"
NO_INSTALL="${NO_INSTALL:-$CFG_NO_INSTALL}"
BREW_TIMEOUT="${BREW_TIMEOUT:-$CFG_BREW_TIMEOUT}"

LOG_DIR="${LOG_DIR:-/var/log/composecure}"
LOG_FILE="$LOG_DIR/gstreamer_update.log"
MIN_FIXED="1.28.5"

# Former Homebrew formulae now absorbed by `gstreamer`.
SPLIT_FORMULAE="gst-plugins-base gst-plugins-good gst-plugins-ugly gst-plugins-bad gst-libav gst-devtools gst-editing-services gst-rtsp-server gst-python gst-plugins-rs gst-validate"

mkdir -p "$LOG_DIR"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }

version_ge() { [ "$(printf '%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

keg_version() {
    # Prefer the keg folder name (what Tenable reports); fall back to gst-inspect.
    local vdir="$1"
    local ver
    ver=$(basename "$vdir")
    case "$ver" in
        [0-9]*) echo "$ver"; return ;;
    esac
    if [ -x "$vdir/bin/gst-inspect-1.0" ]; then
        "$vdir/bin/gst-inspect-1.0" --version 2>/dev/null | awk '/GStreamer/{print $2; exit}'
        return
    fi
    echo ""
}

VULN_SEEN=0
VULN_REMAINING=0
NEEDS_HUMAN=0
BREW_TIMED_OUT=0

log "===== update-gstreamer.sh START ====="
log "Host: $(hostname -s 2>/dev/null || hostname)   plugins 326245/326246"
log "DryRun=$DRY_RUN  ForceClose=$FORCE_CLOSE  NoInstall=$NO_INSTALL"
log "Minimum fixed version: $MIN_FIXED"

# -----------------------------------------------------------------------
# Homebrew prefix
# -----------------------------------------------------------------------
if [ -z "${BREW_PREFIX:-}" ]; then
    BREW_PREFIX=""
    for prefix in "/opt/homebrew" "/usr/local"; do
        if [ -x "$prefix/bin/brew" ] || [ -d "$prefix/Cellar/gstreamer" ]; then
            BREW_PREFIX="$prefix"
            break
        fi
    done
fi
if [ -n "$BREW_PREFIX" ]; then
    log "Homebrew prefix: $BREW_PREFIX"
else
    log "Homebrew not found (checked /opt/homebrew and /usr/local)."
    log "RESULT: no Homebrew GStreamer on this host."
    log "===== update-gstreamer.sh END ====="
    exit 0
fi

CELLAR="$BREW_PREFIX/Cellar"
valid_macos_user() {
    case "$1" in
        ""|root|loginwindow|_mbsetupuser) return 1 ;;
    esac
    echo "$1" | grep -Eq '^[A-Za-z0-9._-]+$' || return 1
    return 0
}

# BREW_USER may be preset (brew refuses to run as root, and console-user
# detection has no answer on an unattended machine at the login window).
CONSOLE_USER="${BREW_USER:-}"
if ! valid_macos_user "$CONSOLE_USER"; then
    CONSOLE_USER=$(stat -f "%Su" /dev/console 2>/dev/null || true)
fi
if ! valid_macos_user "$CONSOLE_USER"; then
    if [ -x "$BREW_PREFIX/bin/brew" ]; then
        CONSOLE_USER=$(stat -f "%Su" "$BREW_PREFIX/bin/brew" 2>/dev/null || true)
    else
        CONSOLE_USER=""
    fi
fi
BREW_USER=""
if [ -x "$BREW_PREFIX/bin/brew" ]; then
    if valid_macos_user "$CONSOLE_USER"; then
        BREW_USER="$CONSOLE_USER"
        log "Homebrew user: $BREW_USER"
    else
        log "WARNING: brew is present but no non-root user found -- cannot run brew as root."
    fi
fi

run_brew() {
    # brew writes to its own file on disk rather than into $(...). Capturing
    # output in a subshell meant a Mosyle timeout kill during `brew update`
    # discarded every line of it -- the jriegel-mac 2026-09-14 run ended
    # after "[1] Inventory" with no record of what brew was doing.
    # $1 = step label used for the per-step log filename.
    local step="$1"
    shift
    local step_log="$LOG_DIR/gstreamer_brew_${step}.log"
    local start
    start=$(date +%s)

    # Once one step has been stopped at the limit, the rest would only burn
    # another full timeout each and push the job past Mosyle's own limit.
    if [ "$BREW_TIMED_OUT" -eq 1 ]; then
        log "  brew $* -- skipped (an earlier brew step hit the timeout)"
        return 1
    fi

    log "  brew $* -- running as $BREW_USER"
    log "    live output: $step_log"
    if [ "$BREW_TIMEOUT" -gt 0 ]; then
        log "    limit: ${BREW_TIMEOUT}s"
    fi

    # The redirect is deliberately the root shell's, not sudo's: root owns
    # $LOG_DIR and $BREW_USER may not be able to write there.
    : > "$step_log"
    sudo -u "$BREW_USER" \
        HOME="/Users/$BREW_USER" \
        PATH="$BREW_PREFIX/bin:$BREW_PREFIX/sbin:/usr/bin:/bin:/usr/sbin:/sbin" \
        NONINTERACTIVE=1 \
        HOMEBREW_NO_AUTO_UPDATE=1 \
        HOMEBREW_NO_ANALYTICS=1 \
        HOMEBREW_NO_ENV_HINTS=1 \
        "$BREW_PREFIX/bin/brew" "$@" >>"$step_log" 2>&1 &
    local brew_pid=$!

    local waited=0
    while kill -0 "$brew_pid" 2>/dev/null; do
        sleep 2
        waited=$((waited + 2))
        # Heartbeat so a killed run still shows how far brew got.
        if [ $((waited % 300)) -eq 0 ]; then
            log "    ...still running (${waited}s): $(tail -n 1 "$step_log" 2>/dev/null)"
        fi
        if [ "$BREW_TIMEOUT" -gt 0 ] && [ "$waited" -ge "$BREW_TIMEOUT" ]; then
            log "    TIMEOUT after ${waited}s -- terminating brew."
            kill "$brew_pid" 2>/dev/null || true
            sleep 5
            kill -9 "$brew_pid" 2>/dev/null || true
            BREW_TIMED_OUT=1
            break
        fi
    done

    wait "$brew_pid" 2>/dev/null
    local rc=$?
    local elapsed=$(( $(date +%s) - start ))

    while IFS= read -r line; do
        [ -n "$line" ] && log "    $line"
    done < <(tail -n 40 "$step_log" 2>/dev/null)

    log "  brew $1 finished: exit $rc after ${elapsed}s"
    return "$rc"
}

# -----------------------------------------------------------------------
# Running GStreamer processes
# -----------------------------------------------------------------------
GST_PROCS=$(ps -axo pid=,comm= 2>/dev/null | grep -E 'gst-launch|gst-play|gst-inspect|gst-device-monitor' || true)
if [ -n "$GST_PROCS" ]; then
    log "GStreamer helper processes are running:"
    echo "$GST_PROCS" | while IFS= read -r l; do [ -n "$l" ] && log "  $l"; done
    if [ "$FORCE_CLOSE" = "1" ]; then
        log "FORCE_CLOSE=1 -- sending TERM."
        echo "$GST_PROCS" | awk '{print $1}' | while IFS= read -r p; do
            [ -n "$p" ] && kill "$p" 2>/dev/null || true
        done
        sleep 2
    else
        log "Continuing anyway (Homebrew can replace kegs under helpers; re-run if files stay busy)."
    fi
fi

# -----------------------------------------------------------------------
# Inventory
# -----------------------------------------------------------------------
log ""
log "[1] Inventory"

GST_FORMULA_PRESENT=0
SPLIT_PRESENT=""
PATCHED_GST=0

if [ -d "$CELLAR/gstreamer" ]; then
    GST_FORMULA_PRESENT=1
    while IFS= read -r vdir; do
        [ -d "$vdir" ] || continue
        ver=$(keg_version "$vdir")
        [ -n "$ver" ] || continue
        if version_ge "$ver" "$MIN_FIXED"; then
            log "  $vdir  ($ver)  [OK >= $MIN_FIXED]"
            PATCHED_GST=1
        else
            log "  $vdir  ($ver)  [VULNERABLE < $MIN_FIXED]"
            VULN_SEEN=1
        fi
    done < <(find "$CELLAR/gstreamer" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort)
fi

for f in $SPLIT_FORMULAE; do
    [ -d "$CELLAR/$f" ] || continue
    SPLIT_PRESENT="$SPLIT_PRESENT $f"
    while IFS= read -r vdir; do
        [ -d "$vdir" ] || continue
        ver=$(keg_version "$vdir")
        log "  $vdir  (${ver:-unknown})  [SPLIT FORMULA -- bundled into gstreamer now]"
        VULN_SEEN=1
    done < <(find "$CELLAR/$f" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort)
done

if [ "$GST_FORMULA_PRESENT" -eq 0 ] && [ -z "$SPLIT_PRESENT" ]; then
    log "  No gstreamer / gst-* kegs in $CELLAR."
    log "RESULT: no Homebrew GStreamer on this host."
    log "===== update-gstreamer.sh END ====="
    exit 0
fi

# -----------------------------------------------------------------------
# Upgrade
# -----------------------------------------------------------------------
log ""
log "[2] Homebrew upgrade"

if [ "$DRY_RUN" = "1" ]; then
    log "  [DRY_RUN] Would brew update + upgrade gstreamer + cleanup."
elif [ "$NO_INSTALL" = "1" ]; then
    log "  NO_INSTALL=1 -- skipping brew upgrade (inventory/cleanup only)."
elif [ -z "$BREW_USER" ] || [ ! -x "$BREW_PREFIX/bin/brew" ]; then
    log "  Cannot run brew -- skipping upgrade."
    if [ "$PATCHED_GST" -eq 0 ]; then
        NEEDS_HUMAN=1
    fi
else
    # `brew update` refreshes the formula; without it `upgrade` may still see
    # 1.26.2 as current. HOMEBREW_NO_AUTO_UPDATE is set in run_brew so the
    # upgrade step does not silently repeat this.
    run_brew update update || log "  brew update failed -- continuing with the formula already on disk."

    # --force-bottle keeps this off the multi-hour gst-plugins-rs source
    # build path. If no bottle exists the step fails fast and is reported,
    # which is a far better outcome than being killed at the Mosyle timeout.
    if ! run_brew upgrade_gstreamer upgrade --force-bottle gstreamer; then
        if [ "$BREW_TIMED_OUT" -eq 1 ]; then
            log "  Upgrade hit the ${BREW_TIMEOUT}s limit."
        else
            log "  Bottled upgrade failed -- retrying without --force-bottle (may build from source)."
            run_brew upgrade_gstreamer_src upgrade gstreamer || \
                log "  brew upgrade gstreamer failed. See the per-step log above."
        fi
    fi

    for f in $SPLIT_PRESENT; do
        run_brew "upgrade_${f}" upgrade "$f" || \
            log "  brew upgrade $f failed (legacy split formula) -- cleanup below still applies."
    done

    run_brew cleanup_gstreamer cleanup gstreamer || log "  brew cleanup gstreamer failed."
fi

# Re-read patched state after upgrade
PATCHED_GST=0
if [ -d "$CELLAR/gstreamer" ]; then
    while IFS= read -r vdir; do
        [ -d "$vdir" ] || continue
        ver=$(keg_version "$vdir")
        [ -n "$ver" ] || continue
        if version_ge "$ver" "$MIN_FIXED"; then PATCHED_GST=1; fi
    done < <(find "$CELLAR/gstreamer" -mindepth 1 -maxdepth 1 -type d 2>/dev/null)
fi

# -----------------------------------------------------------------------
# Cellar cleanup (Tenable keys on the version folder)
# -----------------------------------------------------------------------
log ""
log "[3] Cellar cleanup"

if [ -d "$CELLAR/gstreamer" ]; then
    while IFS= read -r vdir; do
        [ -d "$vdir" ] || continue
        ver=$(keg_version "$vdir")
        [ -n "$ver" ] || continue
        version_ge "$ver" "$MIN_FIXED" && continue
        if [ "$PATCHED_GST" -eq 1 ]; then
            if [ "$DRY_RUN" = "1" ]; then
                log "  [DRY_RUN] Would remove $vdir (v$ver < $MIN_FIXED; patched keg present)"
            else
                log "  [REMOVE] $vdir (v$ver < $MIN_FIXED; patched keg present)"
                rm -rf "$vdir"
            fi
        else
            log "  [KEEP]   $vdir (v$ver < $MIN_FIXED) -- no patched gstreamer keg yet."
            VULN_REMAINING=1
        fi
    done < <(find "$CELLAR/gstreamer" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort)
fi

for f in $SPLIT_FORMULAE; do
    [ -d "$CELLAR/$f" ] || continue
    while IFS= read -r vdir; do
        [ -d "$vdir" ] || continue
        if [ "$PATCHED_GST" -eq 1 ]; then
            if [ "$DRY_RUN" = "1" ]; then
                log "  [DRY_RUN] Would remove split formula keg $vdir (plugins now in gstreamer)"
            else
                log "  [REMOVE] split formula keg $vdir (plugins now in gstreamer)"
                rm -rf "$vdir"
            fi
        else
            log "  [KEEP]   $vdir -- not removing split plugins until patched gstreamer is installed."
            VULN_REMAINING=1
        fi
    done < <(find "$CELLAR/$f" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort)
    if [ "$PATCHED_GST" -eq 1 ] && [ -d "$CELLAR/$f" ]; then
        leftover=$(find "$CELLAR/$f" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | head -n 1)
        if [ -z "$leftover" ] && [ "$DRY_RUN" != "1" ]; then
            rmdir "$CELLAR/$f" 2>/dev/null || true
        fi
    fi
done

# -----------------------------------------------------------------------
# Verify
# -----------------------------------------------------------------------
log ""
log "[4] Verification"
REMAIN=0
if [ -d "$CELLAR/gstreamer" ]; then
    while IFS= read -r vdir; do
        [ -d "$vdir" ] || continue
        ver=$(keg_version "$vdir")
        [ -n "$ver" ] || continue
        if version_ge "$ver" "$MIN_FIXED"; then
            log "  OK: $vdir ($ver)"
        else
            log "  STILL VULNERABLE: $vdir ($ver < $MIN_FIXED)"
            REMAIN=1
        fi
    done < <(find "$CELLAR/gstreamer" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort)
fi
for f in $SPLIT_FORMULAE; do
    if [ -d "$CELLAR/$f" ]; then
        while IFS= read -r vdir; do
            [ -d "$vdir" ] || continue
            log "  STILL PRESENT (split formula): $vdir"
            REMAIN=1
        done < <(find "$CELLAR/$f" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort)
    fi
done

log ""
if [ "$DRY_RUN" = "1" ]; then
    log "RESULT: DRY_RUN -- nothing was changed."
    log "===== END (dry run) ====="
    exit 0
fi
if [ "$REMAIN" -eq 1 ] || [ "$VULN_REMAINING" -eq 1 ]; then
    log "RESULT: vulnerable GStreamer remains -- review log."
    if [ "$BREW_TIMED_OUT" -eq 1 ]; then
        log "        brew exceeded BREW_TIMEOUT=${BREW_TIMEOUT}s and was stopped."
        log "        gstreamer bundles gst-plugins-rs; with no matching bottle it"
        log "        builds from source for hours. Either raise CFG_BREW_TIMEOUT,"
        log "        or run 'brew upgrade gstreamer' once by hand on this host and"
        log "        re-run this script with NO_INSTALL=1 to do the keg cleanup."
        log "===== END (attention) ====="
        exit 2
    fi
    if [ "$NEEDS_HUMAN" -eq 1 ]; then
        log "        brew could not be run as a non-root user (Mosyle is root)."
        log "===== END (attention) ====="
        exit 2
    fi
    log "===== END (incomplete) ====="
    exit 1
fi
if [ "$VULN_SEEN" -eq 1 ]; then
    log "RESULT: vulnerable GStreamer found and remediated."
else
    log "RESULT: Homebrew GStreamer is already >= $MIN_FIXED."
fi
log "Re-run a Nessus scan to confirm plugins 326245 and 326246 clear."
log "===== update-gstreamer.sh END ====="
exit 0
