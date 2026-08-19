#!/bin/bash
# ============================================================
# Remediation Script: Ruby REXML ReDoS Vulnerability
# Nessus Plugin ID : 210049
# Affected Package : rexml < 3.3.9
# Fixed Version    : 3.3.9
# Platform         : macOS
# Affected Assets  : csprmb-12-a (10.3.21.123)
#                    csmb-017 (100.64.0.1)
# ============================================================

set -euo pipefail

# When Mosyle (or sudo) runs scripts as root, HOME may be unset.
# Default to /var/root (macOS root home) to prevent unbound variable errors.
HOME="${HOME:-/var/root}"
export HOME

TARGET_GEM="rexml"
FIXED_VERSION="3.3.9"
LOG_FILE="/tmp/rexml_remediation_$(date +%Y%m%d_%H%M%S).log"

# ---- Color helpers ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "$1" | tee -a "$LOG_FILE"; }

# ---- Semver comparison: returns 0 (true) if $1 < $2 ----
version_lt() {
    [ "$(printf '%s\n' "$1" "$2" | sort -V | head -n1)" = "$1" ] && [ "$1" != "$2" ]
}

# ---- Check + update rexml for a given gem/ruby binary pair ----
update_rexml_for_ruby() {
    local GEM_BIN="$1"
    local RUBY_BIN="$2"

    [ -x "$RUBY_BIN" ] || { log "    ${YELLOW}[SKIP]${NC} $RUBY_BIN not found or not executable."; return 0; }
    [ -x "$GEM_BIN"  ] || { log "    ${YELLOW}[SKIP]${NC} $GEM_BIN not found or not executable.";  return 0; }

    local ruby_ver
    ruby_ver=$("$RUBY_BIN" -e 'puts RUBY_VERSION' 2>/dev/null) || { log "    ${RED}[ERROR]${NC} Could not determine Ruby version."; return 1; }
    log "    Ruby version : $ruby_ver  ($RUBY_BIN)"

    local current_ver
    current_ver=$("$GEM_BIN" list "$TARGET_GEM" 2>/dev/null \
        | grep "^rexml " \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' \
        | head -1 || true)

    if [ -z "$current_ver" ]; then
        log "    ${YELLOW}[SKIP]${NC} rexml not installed for this Ruby — nothing to remediate."
        return 0
    fi

    log "    Installed REXML : $current_ver"

    if version_lt "$current_ver" "$FIXED_VERSION"; then
        log "    ${YELLOW}[VULNERABLE]${NC} Updating rexml $current_ver → >= $FIXED_VERSION ..."
        "$GEM_BIN" update "$TARGET_GEM" 2>&1 | tee -a "$LOG_FILE"

        local new_ver
        new_ver=$("$GEM_BIN" list "$TARGET_GEM" 2>/dev/null \
            | grep "^rexml " \
            | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' \
            | head -1 || true)

        if version_lt "$new_ver" "$FIXED_VERSION"; then
            log "    ${RED}[FAIL]${NC} Update did not reach $FIXED_VERSION. Current: $new_ver"
            log "    Manual action may be required (see notes below)."
        else
            log "    ${GREEN}[FIXED]${NC} rexml updated to $new_ver ✓"
        fi
    else
        log "    ${GREEN}[OK]${NC} rexml $current_ver already meets the minimum requirement."
    fi
}

# ==============================================================
# Entry point
# ==============================================================
log ""
log "${BLUE}=============================================="
log " REXML ReDoS Remediation — Plugin 210049"
log " Host : $(hostname)"
log " Date : $(date)"
log "==============================================${NC}"
log ""

# Escalate to root if needed (system gem path requires sudo)
if [ "$EUID" -ne 0 ]; then
    log "${YELLOW}[WARN]${NC} Elevated privileges required for system gem path. Re-running with sudo..."
    exec sudo bash "$0" "$@"
fi

# ------------------------------------------------------------------
# 1. macOS System Ruby  (Ruby 2.6 shipped with macOS Catalina/Big Sur)
# ------------------------------------------------------------------
log "${BLUE}[1/3] System Ruby${NC}"
update_rexml_for_ruby "/usr/bin/gem" "/usr/bin/ruby"

# ------------------------------------------------------------------
# 2. Homebrew Ruby (if present and different from system Ruby)
# ------------------------------------------------------------------
log ""
log "${BLUE}[2/3] Homebrew / PATH Ruby${NC}"
BREW_RUBY="$(command -v ruby 2>/dev/null || true)"
BREW_GEM="$(command -v gem   2>/dev/null || true)"

if [ -n "$BREW_RUBY" ] && [ "$BREW_RUBY" != "/usr/bin/ruby" ]; then
    update_rexml_for_ruby "$BREW_GEM" "$BREW_RUBY"
else
    log "    ${YELLOW}[SKIP]${NC} No additional Homebrew Ruby detected."
fi

# ------------------------------------------------------------------
# 3. rbenv-managed Rubies (common on developer workstations)
# ------------------------------------------------------------------
log ""
log "${BLUE}[3/3] rbenv Ruby versions${NC}"
RBENV_FOUND=false

# Build search list: system-wide paths + every user's home under /Users/
# (rbenv is per-user; since Mosyle runs as root, $HOME won't cover user installs)
RBENV_SEARCH_PATHS=(
    "/usr/local/.rbenv"
    "/opt/homebrew/opt/rbenv"
    "/opt/rbenv"
)
for user_home in /Users/*/; do
    [ -d "$user_home" ] && RBENV_SEARCH_PATHS+=("${user_home}.rbenv")
done

for RBENV_ROOT in "${RBENV_SEARCH_PATHS[@]}"; do
    if [ -d "$RBENV_ROOT/versions" ]; then
        RBENV_FOUND=true
        log "    Found rbenv root: $RBENV_ROOT"
        for ruby_bin in "$RBENV_ROOT/versions"/*/bin/ruby; do
            gem_bin="${ruby_bin%ruby}gem"
            update_rexml_for_ruby "$gem_bin" "$ruby_bin"
        done
    fi
done
$RBENV_FOUND || log "    ${YELLOW}[SKIP]${NC} No rbenv installation detected."

# ------------------------------------------------------------------
# Post-run summary
# ------------------------------------------------------------------
log ""
log "${BLUE}=============================================="
log " Remediation Complete"
log " Log : $LOG_FILE"
log "==============================================${NC}"
log ""
log "Post-remediation verification commands:"
log "  gem list rexml                    # system / active gem env"
log "  gem list rexml --all              # all installed versions"
log ""
log "${YELLOW}Notes:${NC}"
log "  • The macOS system Ruby (2.6) is deprecated by Apple. If this"
log "    gem update fails, consider migrating workloads to a supported"
log "    Ruby version (3.1+) installed via Homebrew or rbenv."
log "  • Ruby 3.2+ is not affected by this vulnerability regardless of"
log "    REXML gem version (per the advisory)."
log "  • Re-run a Nessus scan after updating to confirm remediation."
log ""
