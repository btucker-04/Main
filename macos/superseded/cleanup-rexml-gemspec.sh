#!/bin/bash
# ============================================================
# Gemspec Cleanup: Ruby REXML Plugin 210049
# Purpose  : Remove residual rexml gemspec/gem directories below
#            3.3.9 that keep Nessus flagging the finding.
#            Nessus keys on gemspec FILE PRESENCE, not gem list
#            output — so rexml 3.4.2 installed is not enough if
#            the old rexml-3.2.5.gemspec is still on disk.
# Platform : macOS (bash 3.2 compatible — no mapfile/readarray)
# Deploy   : Mosyle (runs as root)
# ============================================================

set -euo pipefail

HOME="${HOME:-/var/root}"
export HOME

FIXED_VERSION="3.3.9"
LOG_DIR="/var/log/composecure"
LOG_FILE="${LOG_DIR}/rexml_gemspec_cleanup_$(date +%Y%m%d_%H%M%S).log"

# ---- Color helpers ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

mkdir -p "$LOG_DIR"
log() { echo -e "$1" | tee -a "$LOG_FILE"; }

version_lt() {
    [ "$(printf '%s\n' "$1" "$2" | sort -V | head -n1)" = "$1" ] && [ "$1" != "$2" ]
}

log ""
log "${BLUE}=============================================="
log " REXML Gemspec Cleanup — Plugin 210049"
log " Host : $(hostname)"
log " Date : $(date)"
log "==============================================${NC}"
log ""
log "Nessus flags this plugin based on gemspec file presence."
log "This script removes any rexml gemspec/gem files below $FIXED_VERSION."
log ""

if [ "$EUID" -ne 0 ]; then
    log "${YELLOW}[WARN]${NC} Requires root. Re-running with sudo..."
    exec sudo bash "$0" "$@"
fi

# ------------------------------------------------------------------
# Build list of gem root directories that actually exist.
# Using a simple loop instead of mapfile — bash 3.2 compatible.
# ------------------------------------------------------------------
GEM_ROOTS=()

for dir in \
    "/Library/Ruby/Gems" \
    "/usr/local/lib/ruby/gems" \
    "/opt/homebrew/lib/ruby/gems"; do
    [ -d "$dir" ] && GEM_ROOTS+=("$dir")
done

# rbenv per-user installs
for user_home in /Users/*/; do
    rbenv_versions="${user_home}.rbenv/versions"
    [ -d "$rbenv_versions" ] && GEM_ROOTS+=("$rbenv_versions")
done

if [ ${#GEM_ROOTS[@]} -eq 0 ]; then
    log "${YELLOW}[WARN]${NC} No gem root directories found. Nothing to clean."
    exit 0
fi

log "Searching in:"
for r in "${GEM_ROOTS[@]}"; do
    log "  $r"
done
log ""

# ------------------------------------------------------------------
# Find every rexml-*.gemspec under the discovered roots and remove
# any whose version is below FIXED_VERSION.
# Using < <(...) process substitution so REMOVED stays in scope.
# ------------------------------------------------------------------
REMOVED=0
ALREADY_CLEAN=0

while IFS= read -r gemspec; do
    GEMSPEC_FILE="$(basename "$gemspec")"
    VER="$(echo "$GEMSPEC_FILE" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')"

    if [ -z "$VER" ]; then
        continue
    fi

    if version_lt "$VER" "$FIXED_VERSION"; then
        log "${YELLOW}[STALE]${NC} $gemspec  (version $VER < $FIXED_VERSION)"

        # Remove gemspec file
        rm -f "$gemspec"
        log "  ${GREEN}[REMOVED]${NC} Deleted gemspec"

        # Remove corresponding gem directory if present
        GEM_INSTALL_DIR="$(dirname "$(dirname "$gemspec")")/gems/rexml-${VER}"
        if [ -d "$GEM_INSTALL_DIR" ]; then
            rm -rf "$GEM_INSTALL_DIR"
            log "  ${GREEN}[REMOVED]${NC} Deleted gem dir : $GEM_INSTALL_DIR"
        fi

        REMOVED=$((REMOVED + 1))
    else
        log "${GREEN}[OK]${NC} $GEMSPEC_FILE — version $VER meets requirement."
        ALREADY_CLEAN=$((ALREADY_CLEAN + 1))
    fi

done < <(find "${GEM_ROOTS[@]}" -name "rexml-*.gemspec" -type f 2>/dev/null | sort)

log ""
log "${BLUE}=============================================="
log " Summary"
log " Stale gemspecs removed : $REMOVED"
log " Already-clean entries  : $ALREADY_CLEAN"
log " Log                    : $LOG_FILE"
log "==============================================${NC}"
log ""

if [ "$REMOVED" -gt 0 ]; then
    log "${GREEN}[DONE]${NC} Stale gemspecs removed. Nessus should clear on next re-scan."
else
    log "${YELLOW}[INFO]${NC} No stale gemspecs found — host was already clean."
    log "       If Tenable is still showing this finding, trigger a manual"
    log "       re-scan in the Tenable console to force re-evaluation."
fi

log ""
