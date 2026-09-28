#!/bin/bash
# =============================================================================
# update-nodejs-322793.sh  (v4)
# Remediates : Node.js security updates. No pinned target version.
#              Homebrew formulae are upgraded to the current formula.
#              An official /usr/local pkg is raised to the latest stable
#              release of its installed major (nodejs.org dist index).
# Nessus Plugin ID : 322793 (and later floors on the same lines)
# Platform   : macOS (bash 3.2 compatible) | Deploy: Mosyle (runs as root)
#
# Handles THREE Node install methods, because the fleet has more than one:
#   A. Homebrew        -> <prefix>/Cellar/node*/<ver>            (csmb-010/-023/-033/-036)
#   B. Official .pkg   -> /usr/local/bin/node                    (csmb-067)
#   C. nvm / fnm / asdf-> per-user toolchains  (REPORTED, never modified)
#
# v4 (CSMB-036, 2026-09-28): v3 still carried FIX_26=26.3.1, so a host on
#   26.5.0 logged "OK >= 26.3.1" and skipped brew while Tenable wanted
#   26.5.1. The floors are gone. Installed Homebrew node* formulae are
#   always `brew upgrade`d. The official pkg looks up the latest stable
#   release of the installed major at run time.
#   Brew output is still filtered: progress bars and the new/deleted
#   formula and cask catalogs are omitted.
#
# v3 (CSMB-036, 2026-09-28): brew update was logging the full catalog.
#   That filter stays. The "skip brew when already above the floor" rule
#   from v3 does not: the floor is what hid 26.5.0.
#
# v2 fixes, from the 2026-08-03 CSMB-067 run:
#   * v1 only understood Homebrew. On a machine with the official pkg install
#     it found no Cellar, logged "no vulnerable Homebrew Node versions remain"
#     and exited 0 -- a FALSE PASS while a vulnerable /usr/local/bin/node sat
#     untouched. v2 detects and updates the pkg install via the official
#     macOS installer for the same major line.
#   * Exit code now reflects what was actually REMEDIATED, not merely what was
#     inspected: a failed upgrade exits non-zero.
#   * No longer logs a "Homebrew user" when Homebrew is not installed.
#
# Design notes:
#   * Homebrew `node` tracks whatever the formula currently is. `node@N`
#     stays on that major because that is how the formula is defined.
#   * The official pkg stays on the installed major (26.x -> latest 26.x).
#     The patch number comes from the dist index, not from this file.
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
NODE_DIST_INDEX="${NODE_DIST_INDEX:-https://nodejs.org/dist/index.json}"
# Tests point NODE_DIST_JSON at a cached index. A live run downloads it.
NODE_DIST_JSON="${NODE_DIST_JSON:-}"

MIN_PKG_BYTES=$((20 * 1024 * 1024))   # official macOS pkg is ~60-90MB

mkdir -p "$LOG_DIR"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }
cleanup() { rm -rf "$WORK_DIR"; }

# Drop brew's download bar and the new/deleted formula+cask catalogs.
# Progress updates arrive as carriage-return frames; callers translate those
# to newlines before this function sees them.
filter_brew_output() {
    skip=0
    noted=0
    while IFS= read -r line || [ -n "$line" ]; do
        [ -n "$line" ] || continue
        case "$line" in
            "==> New Formulae"*|"==> New Casks"*|"==> Deleted Formulae"*|"==> Deleted Casks"*)
                skip=1
                if [ "$noted" -eq 0 ]; then
                    echo "(omitted brew catalog: new and deleted formulae/casks)"
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

# Latest stable X.Y.Z on major $1 from a nodejs dist index.json ($2).
# Release candidates (v26.6.0-rc.1) are ignored.
latest_node_release() {
    major="$1"
    index="$2"
    [ -n "$major" ] && [ -f "$index" ] || return 1
    py=/usr/bin/python3
    [ -x "$py" ] || py=$(command -v python3 || true)
    [ -n "$py" ] || return 1
    "$py" - "$major" "$index" <<'PY'
import json, sys
major, path = sys.argv[1], sys.argv[2]
try:
    data = json.load(open(path))
except Exception:
    sys.exit(1)
if isinstance(data, dict):
    data = [data]
prefix = "v" + major + "."
best = None
for rel in data:
    ver = rel.get("version") or ""
    if not ver.startswith(prefix):
        continue
    rest = ver[len(prefix):]
    parts = rest.split(".")
    if not parts or any(not p.isdigit() for p in parts):
        continue
    key = tuple(int(p) for p in parts)
    if best is None or key > best[0]:
        best = (key, ver[1:])
if best is None:
    sys.exit(1)
sys.stdout.write(best[1])
PY
}

if [ "${NODE_SELFTEST:-0}" = "1" ]; then
    return 0 2>/dev/null || exit 0
fi
trap cleanup EXIT

version_ge() { [ "$(printf '%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

node_major_of() { echo "$1" | cut -d. -f1; }

fetch_node_index() {
    if [ -n "$NODE_DIST_JSON" ] && [ -f "$NODE_DIST_JSON" ]; then
        return 0
    fi
    mkdir -p "$WORK_DIR"
    NODE_DIST_JSON="$WORK_DIR/node-index.json"
    log "  Fetching Node release index: $NODE_DIST_INDEX"
    if ! curl -fL --retry 3 --retry-delay 5 -o "$NODE_DIST_JSON" "$NODE_DIST_INDEX" 2>>"$LOG_FILE"; then
        log "  ERROR: could not download the Node release index."
        return 1
    fi
    if ! grep -q '"version"' "$NODE_DIST_JSON" 2>/dev/null; then
        log "  ERROR: release index is not JSON (proxy block page?)."
        return 1
    fi
    return 0
}

VULN_SEEN=0
VULN_REMAINING=0
UNMANAGED_NOTE=0

log "===== update-nodejs-322793.sh (v4) START ====="
log "Host: $(hostname)"
log "No pinned target. Homebrew node* is upgraded; an official pkg goes to the latest stable release of its major."

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
    while IFS= read -r vdir; do
        [ -d "$vdir" ] || continue
        log "  $vdir  [installed $(basename "$vdir")]"
    done < <(find "$CELLAR" -mindepth 2 -maxdepth 2 -type d -path '*/node*' 2>/dev/null | sort)

    if [ -n "$BREW_USER" ]; then
        log "  brew update..."
        run_brew update 2>&1 | tr '\r' '\n' | filter_brew_output | while IFS= read -r line; do
            [ -n "$line" ] && log "  $line"
        done
        for f in $NODE_FORMULAE; do
            log "  brew upgrade $f ..."
            if ! run_brew upgrade "$f" 2>&1 | tr '\r' '\n' | filter_brew_output | while IFS= read -r line; do
                [ -n "$line" ] && log "  $line"
            done; then
                log "  ERROR: brew upgrade $f failed."
                VULN_REMAINING=1
            fi
            log "  brew cleanup $f ..."
            run_brew cleanup "$f" 2>&1 | tr '\r' '\n' | filter_brew_output | while IFS= read -r line; do
                [ -n "$line" ] && log "  $line"
            done
        done
        VULN_SEEN=1
    else
        log "  Cannot run brew -- skipping Homebrew upgrade."
        VULN_REMAINING=1
    fi

    # brew cleanup usually drops old kegs. If two remain in one formula,
    # delete every keg except the highest version. No advisory floor.
    while IFS= read -r fdir; do
        [ -d "$fdir" ] || continue
        newest=""
        while IFS= read -r vdir; do
            [ -d "$vdir" ] || continue
            ver=$(basename "$vdir")
            if [ -z "$newest" ] || version_ge "$ver" "$newest"; then
                newest="$ver"
            fi
        done < <(find "$fdir" -mindepth 1 -maxdepth 1 -type d 2>/dev/null)
        [ -n "$newest" ] || continue
        while IFS= read -r vdir; do
            [ -d "$vdir" ] || continue
            ver=$(basename "$vdir")
            [ "$ver" = "$newest" ] && continue
            log "  [REMOVE] $vdir (v$ver; $newest is the newest keg of $(basename "$fdir"))"
            rm -rf "$vdir"
        done < <(find "$fdir" -mindepth 1 -maxdepth 1 -type d 2>/dev/null)
    done < <(find "$CELLAR" -mindepth 1 -maxdepth 1 -type d -name 'node*' 2>/dev/null | sort)
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
                MAJOR=$(node_major_of "$CUR")
                log "  Installed: $CUR"
                if ! fetch_node_index; then
                    VULN_REMAINING=1
                else
                    NEED=$(latest_node_release "$MAJOR" "$NODE_DIST_JSON" 2>/dev/null || true)
                    if [ -z "$NEED" ]; then
                        log "  ERROR: no stable ${MAJOR}.x release in the Node index."
                        VULN_REMAINING=1
                    elif version_ge "$CUR" "$NEED"; then
                        log "  Already at the latest ${MAJOR}.x release ($NEED)."
                    else
                        VULN_SEEN=1
                        log "  $CUR is behind the latest ${MAJOR}.x release ($NEED). Updating via official macOS pkg..."
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
            log "  $uname_only: $vv  <- $mpath"
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

if [ -n "$CELLAR" ]; then
    while IFS= read -r vdir; do
        [ -d "$vdir" ] || continue
        log "  present: $vdir"
    done < <(find "$CELLAR" -mindepth 2 -maxdepth 2 -type d -path '*/node*' 2>/dev/null | sort)
fi

if [ -x "$STANDALONE" ]; then
    SV=$("$STANDALONE" --version 2>/dev/null | sed 's/^v//' || true)
    log "  present: $STANDALONE at ${SV:-unknown}"
fi

log ""
if [ "$VULN_REMAINING" -eq 1 ]; then
    log "RESULT: a Node.js update did not complete -- review the log above."
    log "===== END (incomplete) ====="
    exit 1
fi
if [ "$UNMANAGED_NOTE" -eq 1 ]; then
    log "RESULT: Homebrew/pkg update finished, but an item above needs a human."
    log "===== END (attention) ====="
    exit 2
fi
if [ "$VULN_SEEN" -eq 1 ]; then
    log "RESULT: Node.js update ran."
else
    log "RESULT: no Homebrew or official Node.js install needed an update."
fi
log "Re-run a Nessus scan to confirm the Node.js finding clears."
log "===== update-nodejs-322793.sh (v4) END ====="
exit 0
