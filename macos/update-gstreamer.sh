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
# =============================================================================
DRY_RUN="${DRY_RUN:-$CFG_DRY_RUN}"
FORCE_CLOSE="${FORCE_CLOSE:-$CFG_FORCE_CLOSE}"
NO_INSTALL="${NO_INSTALL:-$CFG_NO_INSTALL}"

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

CONSOLE_USER=$(stat -f "%Su" /dev/console 2>/dev/null || true)
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
    sudo -u "$BREW_USER" \
        HOME="/Users/$BREW_USER" \
        PATH="$BREW_PREFIX/bin:$BREW_PREFIX/sbin:/usr/bin:/bin:/usr/sbin:/sbin" \
        NONINTERACTIVE=1 \
        "$BREW_PREFIX/bin/brew" "$@"
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
    log "  brew update..."
    OUT=$(run_brew update 2>&1); log "  $OUT"
    log "  brew upgrade gstreamer ..."
    OUT=$(run_brew upgrade gstreamer 2>&1); log "  $OUT"
    for f in $SPLIT_PRESENT; do
        log "  brew upgrade $f (legacy split formula)..."
        OUT=$(run_brew upgrade "$f" 2>&1); log "  $OUT"
    done
    OUT=$(run_brew cleanup gstreamer 2>&1); log "  cleanup gstreamer: $OUT"
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
