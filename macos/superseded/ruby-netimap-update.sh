#!/bin/bash
# =============================================================================
# ruby-netimap-update.sh
# Remediates : Ruby net-imap < 0.4.24 / 0.5.x < 0.5.14 / 0.6.x < 0.6.4
# Nessus Plugin ID : 313278
#
# Key facts driving this script:
#   * Tenable keys on GEMSPEC FILE PRESENCE, not runtime gem state. Updating
#     the gem is not enough — the old gemspec must be removed from disk.
#   * Two vuln paths are STALE Homebrew-internal portable-ruby bundles
#     (/vendor/portable-ruby/<ver>/) that brew cleanup failed to remove.
#   * One vuln path is the ACTIVE Homebrew ruby formula (/Cellar/ruby/<ver>/),
#     which must be gem-updated (not deleted) then have its old spec removed.
#
# Strategy:
#   0. Determine a usable Homebrew user WITHOUT requiring a GUI login
#      (console user -> fall back to the owner of the brew binary).
#   1. Active Cellar ruby: gem update net-imap + gem cleanup, then drop the
#      stale spec once a patched spec exists alongside it.
#   2. Portable-ruby: brew update + aggressive cleanup to rotate/remove stale
#      bundles; then nuke any stale (non-current) portable-ruby version dirs.
#   3. Final sweep: remove any remaining net-imap gemspec below its branch
#      threshold (guarding the CURRENT portable-ruby), then report.
#
# bash 3.2 compatible (macOS). Mosyle runs this as root.
# =============================================================================

set -uo pipefail   # deliberately NOT -e: we continue past individual failures

LOG_DIR="/var/log/composecure"
LOG_FILE="$LOG_DIR/ruby-netimap-update.log"
BREW="/opt/homebrew/bin/brew"
BREW_PREFIX="/opt/homebrew"
PORTABLE_RUBY_DIR="$BREW_PREFIX/Library/Homebrew/vendor/portable-ruby"

# Branch thresholds from the advisory
FIX_04="0.4.24"
FIX_05="0.5.14"
FIX_06="0.6.4"

mkdir -p "$LOG_DIR"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }

# --- version helpers (sort -V handles 4-part versions like 0.4.9.1) ----------
# version_ge A B  -> true (0) if A >= B
version_ge() { [ "$(printf '%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }
# version_lt A B  -> true (0) if A <  B
version_lt() { ! version_ge "$1" "$2"; }

# Required fixed version for a given installed net-imap version
required_fixed_for() {
    case "$1" in
        0.6.*) echo "$FIX_06" ;;
        0.5.*) echo "$FIX_05" ;;
        *)     echo "$FIX_04" ;;   # 0.4.x and anything older
    esac
}

log "===== ruby-netimap-update.sh START ====="
log "Host: $(hostname)"

# =============================================================================
# 0. Determine a usable Homebrew user (no GUI login required)
# =============================================================================
CURRENT_USER=$(stat -f "%Su" /dev/console 2>/dev/null || true)

if [ -z "$CURRENT_USER" ] || [ "$CURRENT_USER" = "root" ] || [ "$CURRENT_USER" = "loginwindow" ] || [ "$CURRENT_USER" = "_mbsetupuser" ]; then
    log "No valid console user ('$CURRENT_USER'). Falling back to Homebrew owner..."
    if [ -e "$BREW" ]; then
        CURRENT_USER=$(stat -f "%Su" "$BREW" 2>/dev/null || true)
    fi
fi

if [ -z "$CURRENT_USER" ] || [ "$CURRENT_USER" = "root" ]; then
    log "WARNING: Could not determine a non-root Homebrew user."
    log "         gem/brew steps will be skipped; file-cleanup steps will still run as root."
    BREW_USER=""
else
    BREW_USER="$CURRENT_USER"
    log "Homebrew user: $BREW_USER"
fi

# Run a command as the Homebrew user with a sane environment
run_as_brew_user() {
    sudo -u "$BREW_USER" \
        HOME="/Users/$BREW_USER" \
        PATH="/opt/homebrew/bin:/opt/homebrew/sbin:/opt/homebrew/opt/ruby/bin:/usr/bin:/bin" \
        NONINTERACTIVE=1 \
        "$@"
}

HAVE_BREW=false
[ -e "$BREW" ] && [ -n "$BREW_USER" ] && HAVE_BREW=true

# Fix ownership so brew/gem don't hit "not writable" errors
if $HAVE_BREW; then
    log "Ensuring Homebrew ownership for $BREW_USER..."
    chown -R "$BREW_USER" "$BREW_PREFIX" 2>>"$LOG_FILE" || true
fi

# =============================================================================
# 1. ACTIVE Cellar Ruby: update net-imap gem, then drop stale spec
# =============================================================================
log ""
log "[1] Active Homebrew Ruby (Cellar) net-imap update..."
HOMEBREW_GEM="/opt/homebrew/opt/ruby/bin/gem"

if $HAVE_BREW && [ -x "$HOMEBREW_GEM" ]; then
    log "  Updating net-imap via $HOMEBREW_GEM ..."
    OUT=$(run_as_brew_user "$HOMEBREW_GEM" update net-imap 2>&1); log "  $OUT"
    log "  Running gem cleanup net-imap (removes superseded versions)..."
    OUT=$(run_as_brew_user "$HOMEBREW_GEM" cleanup net-imap 2>&1); log "  $OUT"
else
    log "  Skipped (no Homebrew-managed gem binary, or no brew user)."
fi

# =============================================================================
# 2. Portable-ruby: rotate current + remove stale bundles
# =============================================================================
log ""
log "[2] Homebrew portable-ruby maintenance..."

CURRENT_PORTABLE_VER=""
if $HAVE_BREW; then
    log "  brew update (rotates current portable-ruby to a patched bundle)..."
    OUT=$(run_as_brew_user "$BREW" update 2>&1); log "  $OUT"

    log "  brew cleanup --prune=0 (removes stale bundles/downloads)..."
    OUT=$(run_as_brew_user "$BREW" cleanup --prune=0 2>&1); log "  $OUT"

    # Identify the CURRENT portable-ruby so we never delete it out from under brew.
    RUBY_PATH=$(run_as_brew_user "$BREW" ruby -e 'puts RbConfig.ruby' 2>/dev/null || true)
    case "$RUBY_PATH" in
        *"/vendor/portable-ruby/"*)
            # Extract the version segment after portable-ruby/
            CURRENT_PORTABLE_VER=$(echo "$RUBY_PATH" | sed -n 's#.*/vendor/portable-ruby/\([^/]*\)/.*#\1#p')
            log "  Current portable-ruby in use: ${CURRENT_PORTABLE_VER:-unknown}"
            ;;
        *)
            log "  brew is not currently running on a portable-ruby (path: ${RUBY_PATH:-unknown})."
            log "  All portable-ruby version dirs are therefore treated as stale."
            ;;
    esac
else
    log "  Skipped brew update/cleanup (no brew user). Stale bundles handled by file sweep below."
fi

# Remove stale (non-current) portable-ruby version directories entirely.
# These are Homebrew-internal interpreters; a stale one has no live dependents.
if [ -d "$PORTABLE_RUBY_DIR" ]; then
    while IFS= read -r verdir; do
        [ -d "$verdir" ] || continue
        ver=$(basename "$verdir")
        if [ -n "$CURRENT_PORTABLE_VER" ] && [ "$ver" = "$CURRENT_PORTABLE_VER" ]; then
            log "  [KEEP]  portable-ruby $ver (currently in use by brew)."
            continue
        fi
        # Only bother removing if it actually carries a vulnerable net-imap spec
        if find "$verdir" -name 'net-imap-*.gemspec' 2>/dev/null | grep -q .; then
            log "  [STALE] Removing stale portable-ruby bundle: $verdir"
            rm -rf "$verdir" && log "    Removed." || log "    WARNING: could not remove $verdir"
        else
            log "  [OK]    portable-ruby $ver has no net-imap spec — leaving as-is."
        fi
    done < <(find "$PORTABLE_RUBY_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort)
else
    log "  No portable-ruby directory present."
fi

# =============================================================================
# 3. Final gemspec sweep — the part that actually clears Tenable
# =============================================================================
log ""
log "[3] Final net-imap gemspec sweep under $BREW_PREFIX ..."
REMOVED=0
KEPT_OK=0
WARN_CURRENT=0

while IFS= read -r spec; do
    [ -f "$spec" ] || continue
    base=$(basename "$spec")
    # Strip 'net-imap-' prefix and '.gemspec' suffix to get the version
    ver=$(echo "$base" | sed -E 's/^net-imap-([0-9][0-9.]*)\.gemspec$/\1/')
    [ "$ver" = "$base" ] && continue   # didn't match expected pattern

    need=$(required_fixed_for "$ver")

    if version_ge "$ver" "$need"; then
        log "  [OK]     $spec (version $ver >= $need)"
        KEPT_OK=$((KEPT_OK + 1))
        continue
    fi

    # Vulnerable spec. Decide if it's safe to remove.
    case "$spec" in
        *"/vendor/portable-ruby/$CURRENT_PORTABLE_VER/"*)
            # This is the CURRENT portable-ruby — do not break brew.
            log "  [WARN]   $spec is in the CURRENT portable-ruby ($ver < $need)."
            log "           Not deleting (would risk breaking brew). 'brew update' should"
            log "           have rotated this; a newer Homebrew may be required."
            WARN_CURRENT=$((WARN_CURRENT + 1))
            ;;
        *"/Cellar/ruby/"*)
            # Active ruby formula: only remove the old spec if a patched spec
            # exists in the SAME specifications dir (so net-imap still works).
            specdir=$(dirname "$spec")
            if find "$specdir" -name 'net-imap-*.gemspec' 2>/dev/null | while IFS= read -r other; do
                   ov=$(basename "$other" | sed -E 's/^net-imap-([0-9][0-9.]*)\.gemspec$/\1/')
                   version_ge "$ov" "$need" && echo FOUND
               done | grep -q FOUND; then
                log "  [REMOVE] $spec ($ver < $need; patched spec present alongside)"
                rm -f "$spec" && REMOVED=$((REMOVED + 1))
                gemdir="$(dirname "$specdir")/gems/net-imap-$ver"
                [ -d "$gemdir" ] && rm -rf "$gemdir" && log "           Removed gem dir: $gemdir"
            else
                log "  [WARN]   $spec ($ver < $need) — no patched spec alongside; gem update"
                log "           may have failed. NOT removing to avoid breaking net-imap."
                WARN_CURRENT=$((WARN_CURRENT + 1))
            fi
            ;;
        *)
            # Any other stale location — safe to remove spec + gem dir.
            log "  [REMOVE] $spec ($ver < $need)"
            rm -f "$spec" && REMOVED=$((REMOVED + 1))
            specdir=$(dirname "$spec")
            gemdir="$(dirname "$specdir")/gems/net-imap-$ver"
            [ -d "$gemdir" ] && rm -rf "$gemdir" && log "           Removed gem dir: $gemdir"
            ;;
    esac
done < <(find "$BREW_PREFIX" -name 'net-imap-*.gemspec' -type f 2>/dev/null | sort)

# =============================================================================
# Summary
# =============================================================================
log ""
log "===== SUMMARY ====="
log "  Stale gemspecs removed : $REMOVED"
log "  Already-patched specs  : $KEPT_OK"
log "  Warnings (manual look) : $WARN_CURRENT"

if [ "$WARN_CURRENT" -gt 0 ]; then
    log ""
    log "  ACTION: $WARN_CURRENT vulnerable spec(s) were left in place because removing"
    log "  them could break the active Ruby or brew. Re-run after a 'brew upgrade ruby'"
    log "  / newer Homebrew, or investigate those paths manually."
fi

log ""
log "  Re-run a Nessus scan to confirm plugin 313278 clears."
log "===== ruby-netimap-update.sh END ====="
exit 0
