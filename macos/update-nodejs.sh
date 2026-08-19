#!/bin/bash
# =============================================================================
# update-nodejs-322793.sh  (v2)
# Remediates : Node.js 22.x < 22.23.0 / 24.x < 24.17.0 / 26.x < 26.3.1
#              (June 18 2026 security releases)
# Nessus Plugin ID : 322793
# Platform   : macOS (bash 3.2 compatible) | Deploy: Mosyle (runs as root)
#
# Handles THREE Node install methods, because the fleet has more than one:
#   A. Homebrew        -> <prefix>/Cellar/node*/<ver>            (csmb-010/-023/-033/-036)
#   B. Official .pkg   -> /usr/local/bin/node                    (csmb-067)
#   C. nvm / fnm / asdf-> per-user toolchains  (REPORTED, never modified)
#
# v2 fixes, from the 2026-08-03 CSMB-067 run:
#   * v1 only understood Homebrew. On a machine with the official pkg install
#     it found no Cellar, logged "no vulnerable Homebrew Node versions remain"
#     and exited 0 -- a FALSE PASS while a vulnerable /usr/local/bin/node sat
#     untouched. v2 detects and updates the pkg install via the official
#     macOS installer for the same major line.
#   * Exit code now reflects what was actually REMEDIATED, not merely what was
#     inspected: any vulnerable Node still present at the end exits non-zero.
#   * No longer logs a "Homebrew user" when Homebrew is not installed.
#
# Design notes:
#   * Stays on the installed major line (22->22.23.0, 24->24.17.0, 26->26.3.1);
#     never jumps a developer across majors.
#   * Homebrew path still needs Cellar cleanup (side-by-side versions linger and
#     Tenable keys on the version directory). The .pkg upgrades IN PLACE, so no
#     cleanup is required there.
#   * A /usr/local/bin/node that is a SYMLINK into Cellar/nvm/fnm is left to the
#     owning manager -- pkg-installing over it would create a split install.
# =============================================================================

set -uo pipefail
HOME="${HOME:-/var/root}"
export HOME

LOG_DIR="/var/log/composecure"
LOG_FILE="$LOG_DIR/nodejs_update.log"
WORK_DIR="/tmp/node_update_$$"

FIX_22="22.23.0"
FIX_24="24.17.0"
FIX_26="26.3.1"
MIN_PKG_BYTES=$((20 * 1024 * 1024))   # official macOS pkg is ~60-90MB

mkdir -p "$LOG_DIR"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }
cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

version_ge() { [ "$(printf '%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

required_fixed_for() {
    case "$1" in
        22.*) echo "$FIX_22" ;;
        24.*) echo "$FIX_24" ;;
        26.*) echo "$FIX_26" ;;
        *)    echo "" ;;      # branch not named in the advisory -> review, never auto-remove
    esac
}

VULN_SEEN=0        # a vulnerable Node was found somewhere
VULN_REMAINING=0   # ...and is still vulnerable at the end
UNMANAGED_NOTE=0   # something needs a human (nvm/fnm/odd branch)

log "===== update-nodejs-322793.sh (v2) START ====="
log "Host: $(hostname)"

# -----------------------------------------------------------------------
# 0a. Homebrew prefix (Apple Silicon vs Intel). Absence is normal.
# -----------------------------------------------------------------------
BREW_PREFIX=""
for prefix in "/opt/homebrew" "/usr/local"; do
    if [ -x "$prefix/bin/brew" ]; then
        BREW_PREFIX="$prefix"
        break
    fi
done
if [ -n "$BREW_PREFIX" ]; then
    log "Homebrew prefix: $BREW_PREFIX"
else
    log "Homebrew not installed (checked /opt/homebrew and /usr/local)."
fi

# -----------------------------------------------------------------------
# 0b. Console user (only needed to run brew; brew refuses to run as root)
# -----------------------------------------------------------------------
CONSOLE_USER=$(stat -f "%Su" /dev/console 2>/dev/null || true)
if [ -z "$CONSOLE_USER" ] || [ "$CONSOLE_USER" = "root" ] || [ "$CONSOLE_USER" = "loginwindow" ] || [ "$CONSOLE_USER" = "_mbsetupuser" ]; then
    if [ -n "$BREW_PREFIX" ]; then
        CONSOLE_USER=$(stat -f "%Su" "$BREW_PREFIX/bin/brew" 2>/dev/null || true)
    else
        CONSOLE_USER=""
    fi
fi
BREW_USER=""
if [ -n "$BREW_PREFIX" ]; then
    if [ -n "$CONSOLE_USER" ] && [ "$CONSOLE_USER" != "root" ]; then
        BREW_USER="$CONSOLE_USER"
        log "Homebrew user: $BREW_USER"
    else
        log "WARNING: Homebrew present but no non-root user found -- cannot run brew."
    fi
fi

run_brew() {
    sudo -u "$BREW_USER" \
        HOME="/Users/$BREW_USER" \
        PATH="$BREW_PREFIX/bin:$BREW_PREFIX/sbin:/usr/bin:/bin:/usr/sbin:/sbin" \
        NONINTERACTIVE=1 \
        "$BREW_PREFIX/bin/brew" "$@"
}

# =======================================================================
# METHOD A -- Homebrew
# =======================================================================
log ""
log "[A] Homebrew Node.js"

CELLAR=""
NODE_FORMULAE=""
if [ -n "$BREW_PREFIX" ] && [ -d "$BREW_PREFIX/Cellar" ]; then
    CELLAR="$BREW_PREFIX/Cellar"
    while IFS= read -r fdir; do
        [ -d "$fdir" ] || continue
        NODE_FORMULAE="$NODE_FORMULAE $(basename "$fdir")"
    done < <(find "$CELLAR" -mindepth 1 -maxdepth 1 -type d -name 'node*' 2>/dev/null | sort)
fi

if [ -z "$NODE_FORMULAE" ]; then
    log "  No Homebrew node formulae installed."
else
    # inventory
    while IFS= read -r vdir; do
        [ -d "$vdir" ] || continue
        ver=$(basename "$vdir")
        need=$(required_fixed_for "$ver")
        if [ -z "$need" ]; then
            log "  $vdir  [branch not in advisory -- review manually]"
            UNMANAGED_NOTE=1
        elif version_ge "$ver" "$need"; then
            log "  $vdir  [OK >= $need]"
        else
            log "  $vdir  [VULNERABLE < $need]"
            VULN_SEEN=1
        fi
    done < <(find "$CELLAR" -mindepth 2 -maxdepth 2 -type d -path '*/node*' 2>/dev/null | sort)

    if [ -n "$BREW_USER" ]; then
        log "  brew update..."
        OUT=$(run_brew update 2>&1); log "  $OUT"
        for f in $NODE_FORMULAE; do
            log "  brew upgrade $f ..."
            OUT=$(run_brew upgrade "$f" 2>&1); log "  $OUT"
            OUT=$(run_brew cleanup "$f" 2>&1); log "  cleanup $f: $OUT"
        done
    else
        log "  Cannot run brew -- skipping Homebrew upgrade."
    fi

    # Remove Cellar versions still below their branch threshold, but only when a
    # patched version of that SAME branch is present (never leave a branch empty).
    while IFS= read -r vdir; do
        [ -d "$vdir" ] || continue
        ver=$(basename "$vdir")
        need=$(required_fixed_for "$ver")
        [ -z "$need" ] && continue
        version_ge "$ver" "$need" && continue
        fdir=$(dirname "$vdir")
        branch=$(echo "$ver" | cut -d. -f1)
        patched_present=0
        while IFS= read -r other; do
            [ -d "$other" ] || continue
            over=$(basename "$other")
            [ "$(echo "$over" | cut -d. -f1)" = "$branch" ] || continue
            oneed=$(required_fixed_for "$over")
            [ -z "$oneed" ] && continue
            if version_ge "$over" "$oneed"; then patched_present=1; fi
        done < <(find "$fdir" -mindepth 1 -maxdepth 1 -type d 2>/dev/null)
        if [ "$patched_present" -eq 1 ]; then
            log "  [REMOVE] $vdir (v$ver < $need; patched ${branch}.x present)"
            rm -rf "$vdir"
        else
            log "  [KEEP]   $vdir (v$ver < $need) -- no patched ${branch}.x present; not removing the only Node on this branch."
            VULN_REMAINING=1
        fi
    done < <(find "$CELLAR" -mindepth 2 -maxdepth 2 -type d -path '*/node*' 2>/dev/null | sort)
fi

# =======================================================================
# METHOD B -- official Node.js .pkg install at /usr/local/bin/node
# =======================================================================
log ""
log "[B] Standalone Node.js (official .pkg)"

STANDALONE="/usr/local/bin/node"
if [ ! -e "$STANDALONE" ]; then
    log "  No $STANDALONE present."
else
    REAL=$(/usr/bin/python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$STANDALONE" 2>/dev/null || echo "$STANDALONE")
    log "  $STANDALONE -> $REAL"

    case "$REAL" in
        */Cellar/*|*/.nvm/*|*/fnm/*|*/.asdf/*)
            log "  This is a symlink into a managed toolchain -- handled by its own"
            log "  manager (see sections A and C). Not pkg-installing over it."
            ;;
        *)
            CUR=$("$STANDALONE" --version 2>/dev/null | sed 's/^v//' || true)
            if [ -z "$CUR" ]; then
                log "  ERROR: could not read version from $STANDALONE"
                UNMANAGED_NOTE=1
            else
                NEED=$(required_fixed_for "$CUR")
                log "  Installed: $CUR"
                if [ -z "$NEED" ]; then
                    log "  Branch not named in the advisory -- review manually (possibly EOL line)."
                    UNMANAGED_NOTE=1
                elif version_ge "$CUR" "$NEED"; then
                    log "  Already >= $NEED. Nothing to do."
                else
                    VULN_SEEN=1
                    log "  VULNERABLE (< $NEED). Updating via official macOS pkg..."
                    PKG="node-v${NEED}.pkg"
                    URL="https://nodejs.org/dist/v${NEED}/${PKG}"
                    mkdir -p "$WORK_DIR"
                    DEST="$WORK_DIR/$PKG"
                    log "  Downloading $URL"
                    if ! curl -fL --retry 3 --retry-delay 5 -o "$DEST" "$URL" 2>>"$LOG_FILE"; then
                        log "  ERROR: download failed. If Zscaler blocks nodejs.org, stage the pkg"
                        log "         locally and run: installer -pkg <path> -target /"
                        VULN_REMAINING=1
                    else
                        SZ=$(stat -f "%z" "$DEST" 2>/dev/null || echo 0)
                        log "  Downloaded: $((SZ / 1024 / 1024)) MB"
                        MAGIC=$(dd if="$DEST" bs=4 count=1 2>/dev/null | LC_ALL=C tr -d '\0')
                        if [ "$SZ" -lt "$MIN_PKG_BYTES" ] || [ "$MAGIC" != "xar!" ]; then
                            log "  ERROR: not a valid .pkg (size or xar! header check failed)."
                            log "         Almost certainly a proxy block page. Aborting this component."
                            VULN_REMAINING=1
                        else
                            log "  Installing (installer -pkg ... -target /)..."
                            if /usr/sbin/installer -pkg "$DEST" -target / >>"$LOG_FILE" 2>&1; then
                                NEW=$("$STANDALONE" --version 2>/dev/null | sed 's/^v//' || true)
                                log "  Post-install version: ${NEW:-unknown}"
                                if [ -n "$NEW" ] && version_ge "$NEW" "$NEED"; then
                                    log "  SUCCESS: $CUR -> $NEW"
                                else
                                    log "  ERROR: version did not reach $NEED."
                                    VULN_REMAINING=1
                                fi
                            else
                                log "  ERROR: installer failed -- see $LOG_FILE"
                                VULN_REMAINING=1
                            fi
                        fi
                    fi
                fi
            fi
            ;;
    esac
fi

# =======================================================================
# METHOD C -- per-user version managers (REPORT ONLY)
# =======================================================================
log ""
log "[C] nvm / fnm / asdf Node versions (report only)"
FOUND_OTHER=0
for udir in /Users/*; do
    [ -d "$udir" ] || continue
    uname_only=$(basename "$udir")
    case "$uname_only" in Shared|.*) continue ;; esac
    for mgr in ".nvm/versions/node" ".local/share/fnm/node-versions" ".asdf/installs/nodejs"; do
        mpath="$udir/$mgr"
        [ -d "$mpath" ] || continue
        while IFS= read -r v; do
            [ -d "$v" ] || continue
            FOUND_OTHER=1
            vv=$(basename "$v" | sed 's/^v//')
            need=$(required_fixed_for "$vv")
            if [ -n "$need" ] && ! version_ge "$vv" "$need"; then
                log "  $uname_only: $vv  [VULNERABLE < $need]  <- $mpath"
                UNMANAGED_NOTE=1
            else
                log "  $uname_only: $vv  <- $mpath"
            fi
        done < <(find "$mpath" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort)
    done
done
if [ "$FOUND_OTHER" -eq 0 ]; then
    log "  None found."
else
    log "  NOTE: per-user toolchains are NOT modified by this script. Any version"
    log "        flagged above should be updated by the developer, e.g."
    log "        'nvm install <fixed> && nvm uninstall <old>'."
fi

# =======================================================================
# Verification
# =======================================================================
log ""
log "[D] Final verification"

REMAIN=0
if [ -n "$CELLAR" ]; then
    while IFS= read -r vdir; do
        [ -d "$vdir" ] || continue
        ver=$(basename "$vdir")
        need=$(required_fixed_for "$ver")
        if [ -n "$need" ] && ! version_ge "$ver" "$need"; then
            log "  STILL VULNERABLE: $vdir (< $need)"
            REMAIN=1
        else
            log "  OK: $vdir"
        fi
    done < <(find "$CELLAR" -mindepth 2 -maxdepth 2 -type d -path '*/node*' 2>/dev/null | sort)
fi

if [ -x "$STANDALONE" ]; then
    SV=$("$STANDALONE" --version 2>/dev/null | sed 's/^v//' || true)
    SN=$(required_fixed_for "${SV:-0.0.0}")
    if [ -n "$SV" ] && [ -n "$SN" ] && ! version_ge "$SV" "$SN"; then
        log "  STILL VULNERABLE: $STANDALONE at $SV (< $SN)"
        REMAIN=1
    else
        log "  OK: $STANDALONE at ${SV:-unknown}"
    fi
fi

log ""
if [ "$REMAIN" -eq 1 ] || [ "$VULN_REMAINING" -eq 1 ]; then
    log "RESULT: vulnerable Node.js remains on this host -- review log above."
    log "===== END (incomplete) ====="
    exit 1
fi
if [ "$UNMANAGED_NOTE" -eq 1 ]; then
    log "RESULT: managed installs are patched, but items above need a human"
    log "        (per-user toolchain or a branch not covered by the advisory)."
    log "===== END (attention) ====="
    exit 2
fi
if [ "$VULN_SEEN" -eq 1 ]; then
    log "RESULT: vulnerable Node.js found and remediated."
else
    log "RESULT: no vulnerable Node.js found on this host."
fi
log "Re-run a Nessus scan to confirm plugin 322793 clears."
log "===== update-nodejs-322793.sh (v2) END ====="
exit 0
