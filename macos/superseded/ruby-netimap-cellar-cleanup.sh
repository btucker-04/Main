#!/bin/bash
# =============================================================================
# ruby-netimap-cellar-cleanup.sh (v2)
# Remediates : Ruby net-imap < 0.4.24 / 0.5.x < 0.5.14 / 0.6.x < 0.6.4
# Nessus Plugin ID : 313278
#
# Scope: the LEFTOVER stale gemspec case -- gem update installs the patched
# gem into the SHARED gems dir while the Cellar's built-in spec stays behind,
# and Tenable keys on gemspec file presence.
#
# v2 changes:
#   * Per-branch patched check: a spec only counts as "patched" if it meets
#     ITS OWN branch threshold (v1 used a flat >= 0.5.14 bar, which let a
#     vulnerable 0.6.x spec satisfy the safety guard).
#   * Intel support: Homebrew prefix auto-detected (/opt/homebrew on Apple
#     Silicon, /usr/local on Intel) instead of hardcoded.
#   * gem cleanup after install; generic summary text for fleet use.
#
# bash 3.2 compatible (macOS). Mosyle runs this as root.
# =============================================================================

set -uo pipefail
HOME="${HOME:-/var/root}"
export HOME

LOG_DIR="/var/log/composecure"
LOG_FILE="$LOG_DIR/ruby-netimap-cellar-cleanup.log"

# Branch thresholds from the advisory
FIX_04="0.4.24"
FIX_05="0.5.14"
FIX_06="0.6.4"

mkdir -p "$LOG_DIR"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }

version_ge() { [ "$(printf '%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }
required_fixed_for() {
    case "$1" in
        0.6.*) echo "$FIX_06" ;;
        0.5.*) echo "$FIX_05" ;;
        *)     echo "$FIX_04" ;;
    esac
}
spec_version() { echo "$1" | sed -E 's/^net-imap-([0-9][0-9.]*)\.gemspec$/\1/'; }

# A spec is patched iff it meets its OWN branch threshold (v2 fix)
spec_is_patched() {
    local v="$1"
    version_ge "$v" "$(required_fixed_for "$v")"
}

log "===== ruby-netimap-cellar-cleanup.sh (v2) START ====="
log "Host: $(hostname)"

# -----------------------------------------------------------------------
# 0a. Detect Homebrew prefix (Apple Silicon vs Intel)
# -----------------------------------------------------------------------
BREW_PREFIX=""
for prefix in "/opt/homebrew" "/usr/local"; do
    if [ -x "$prefix/bin/brew" ]; then
        BREW_PREFIX="$prefix"
        break
    fi
done

if [ -z "$BREW_PREFIX" ]; then
    log "Homebrew not installed (checked /opt/homebrew and /usr/local). Nothing to do."
    log "===== END ====="
    exit 0
fi
BREW="$BREW_PREFIX/bin/brew"
HOMEBREW_GEM="$BREW_PREFIX/opt/ruby/bin/gem"
log "Homebrew prefix: $BREW_PREFIX"

# -----------------------------------------------------------------------
# 0b. Robust Homebrew user (no GUI login required)
# -----------------------------------------------------------------------
CURRENT_USER=$(stat -f "%Su" /dev/console 2>/dev/null || true)
if [ -z "$CURRENT_USER" ] || [ "$CURRENT_USER" = "root" ] || [ "$CURRENT_USER" = "loginwindow" ] || [ "$CURRENT_USER" = "_mbsetupuser" ]; then
    log "No valid console user ('$CURRENT_USER'). Falling back to Homebrew owner..."
    CURRENT_USER=$(stat -f "%Su" "$BREW" 2>/dev/null || true)
fi

BREW_USER=""
if [ -n "$CURRENT_USER" ] && [ "$CURRENT_USER" != "root" ]; then
    BREW_USER="$CURRENT_USER"
    log "Homebrew user: $BREW_USER"
else
    log "WARNING: no non-root Homebrew user found. Will skip gem install; only"
    log "         removes stale specs IF a patched one is already present on disk."
fi

run_as_brew_user() {
    sudo -u "$BREW_USER" \
        HOME="/Users/$BREW_USER" \
        PATH="$BREW_PREFIX/opt/ruby/bin:$BREW_PREFIX/bin:$BREW_PREFIX/sbin:/usr/bin:/bin" \
        NONINTERACTIVE=1 \
        "$@"
}

# -----------------------------------------------------------------------
# Helper: does a spec exist that meets ITS OWN branch threshold?
# -----------------------------------------------------------------------
patched_spec_present() {
    local found=1
    while IFS= read -r spec; do
        [ -f "$spec" ] || continue
        local v; v=$(spec_version "$(basename "$spec")")
        [ "$v" = "$(basename "$spec")" ] && continue
        if spec_is_patched "$v"; then
            log "  Patched spec present: $spec (v$v, branch needs $(required_fixed_for "$v"))"
            found=0
        fi
    done < <(find "$BREW_PREFIX" -name 'net-imap-*.gemspec' -type f 2>/dev/null | sort)
    return $found
}

# -----------------------------------------------------------------------
# 1. Ensure a patched net-imap is installed for the active Homebrew Ruby
# -----------------------------------------------------------------------
log ""
log "[1] Ensuring a patched net-imap is installed..."

if patched_spec_present; then
    log "  A patched net-imap is already present. No install needed."
else
    log "  No patched net-imap found on disk."
    if [ -n "$BREW_USER" ] && [ -x "$HOMEBREW_GEM" ]; then
        log "  Installing latest net-imap via $HOMEBREW_GEM ..."
        OUT=$(run_as_brew_user "$HOMEBREW_GEM" install net-imap 2>&1); log "  $OUT"
        log "  Running gem cleanup net-imap..."
        OUT=$(run_as_brew_user "$HOMEBREW_GEM" cleanup net-imap 2>&1); log "  $OUT"
    else
        log "  Cannot install (no brew user or gem binary). Aborting to avoid"
        log "  removing the only net-imap and breaking Ruby."
        log "===== END (no-op) ====="
        exit 0
    fi
fi

# -----------------------------------------------------------------------
# 2. Re-confirm patched version is present before removing anything
# -----------------------------------------------------------------------
log ""
log "[2] Confirming patched net-imap is present post-install..."
if ! patched_spec_present; then
    log "  ERROR: still no patched net-imap on disk after install attempt."
    log "  Refusing to remove stale specs (would break net-imap). Investigate manually."
    log "===== END (aborted) ====="
    exit 1
fi
log "  Confirmed. Safe to remove stale specs below threshold."

# -----------------------------------------------------------------------
# 3. Remove leftover stale net-imap specs (+ gem dirs) below threshold
# -----------------------------------------------------------------------
log ""
log "[3] Removing stale net-imap gemspecs below branch threshold..."
REMOVED=0
KEPT_OK=0

while IFS= read -r spec; do
    [ -f "$spec" ] || continue
    base=$(basename "$spec")
    ver=$(spec_version "$base")
    [ "$ver" = "$base" ] && continue

    need=$(required_fixed_for "$ver")

    if version_ge "$ver" "$need"; then
        log "  [OK]     $spec (v$ver >= $need)"
        KEPT_OK=$((KEPT_OK + 1))
        continue
    fi

    log "  [REMOVE] $spec (v$ver < $need)"
    rm -f "$spec" && REMOVED=$((REMOVED + 1))

    specdir=$(dirname "$spec")
    gemdir="$(dirname "$specdir")/gems/net-imap-$ver"
    if [ -d "$gemdir" ]; then
        rm -rf "$gemdir" && log "           Removed gem dir: $gemdir"
    fi
done < <(find "$BREW_PREFIX" -name 'net-imap-*.gemspec' -type f 2>/dev/null | sort)

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
log ""
log "===== SUMMARY ====="
log "  Stale specs removed  : $REMOVED"
log "  Patched specs kept   : $KEPT_OK"
log ""
log "  Remaining net-imap specs on disk:"
FOUND_ANY=0
while IFS= read -r spec; do
    [ -f "$spec" ] || continue
    FOUND_ANY=1
    log "    $(spec_version "$(basename "$spec")")  <-  $spec"
done < <(find "$BREW_PREFIX" -name 'net-imap-*.gemspec' -type f 2>/dev/null | sort)
[ "$FOUND_ANY" -eq 0 ] && log "    (none)"
log ""
log "  Re-run a Nessus scan to confirm plugin 313278 clears on this host."
log "===== ruby-netimap-cellar-cleanup.sh (v2) END ====="
exit 0
