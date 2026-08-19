#!/bin/bash
# ============================================================
# Remediation Script: Microsoft PowerShell Security Feature Bypass
# Nessus Plugin ID : 306453
# CVE              : CVE-2026-26143
# Affected Version : PowerShell 7.5.x < 7.5.5
# Fixed Version    : 7.5.5
# Platform         : macOS
# Affected Asset   : csmb-030 (100.64.0.1)
# Deploy Via       : Mosyle
# ============================================================

set -euo pipefail

FIXED_VERSION="7.5.5"
PS_APP_PATH="/Applications/PowerShell.app"
LOG_FILE="/tmp/pwsh_remediation_$(date +%Y%m%d_%H%M%S).log"
WORK_DIR="/tmp/pwsh_update_$$"
GITHUB_BASE="https://github.com/PowerShell/PowerShell/releases/download/v${FIXED_VERSION}"

# ---- Color helpers ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "$1" | tee -a "$LOG_FILE"; }

cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

version_lt() {
    [ "$(printf '%s\n' "$1" "$2" | sort -V | head -n1)" = "$1" ] && [ "$1" != "$2" ]
}

# ---- Detect CPU architecture ----
detect_arch() {
    case "$(uname -m)" in
        arm64)  echo "arm64" ;;
        x86_64) echo "x64"   ;;
        *)
            log "${RED}[ERROR]${NC} Unsupported architecture: $(uname -m)"
            exit 1
            ;;
    esac
}

# ---- Get currently installed PowerShell version ----
get_installed_version() {
    # Try plist first (most reliable, doesn't require running pwsh as root)
    local plist="$PS_APP_PATH/Contents/Info.plist"
    if [ -f "$plist" ]; then
        /usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$plist" 2>/dev/null || true
    fi
}

# ==============================================================
# Entry point
# ==============================================================
log ""
log "${BLUE}=============================================="
log " PowerShell Remediation — Plugin 306453"
log " CVE : CVE-2026-26143"
log " Host: $(hostname)"
log " Date: $(date)"
log "==============================================${NC}"
log ""

# Escalate to root if needed
if [ "$EUID" -ne 0 ]; then
    log "${YELLOW}[WARN]${NC} Elevated privileges required. Re-running with sudo..."
    exec sudo bash "$0" "$@"
fi

# ------------------------------------------------------------------
# 1. Check if PowerShell is installed
# ------------------------------------------------------------------
log "${BLUE}[1/4] Checking installed PowerShell version...${NC}"

if [ ! -d "$PS_APP_PATH" ]; then
    log "${YELLOW}[SKIP]${NC} PowerShell.app not found at $PS_APP_PATH — nothing to remediate."
    exit 0
fi

CURRENT_VERSION="$(get_installed_version)"

if [ -z "$CURRENT_VERSION" ]; then
    log "${YELLOW}[WARN]${NC} Could not determine installed version. Proceeding with update to be safe."
    CURRENT_VERSION="0.0.0"
else
    log "    Installed : $CURRENT_VERSION"
    log "    Required  : >= $FIXED_VERSION"
fi

if ! version_lt "$CURRENT_VERSION" "$FIXED_VERSION"; then
    log "${GREEN}[OK]${NC} PowerShell $CURRENT_VERSION already meets the requirement. Exiting."
    exit 0
fi

log "${YELLOW}[VULNERABLE]${NC} PowerShell $CURRENT_VERSION is below the required $FIXED_VERSION."

# ------------------------------------------------------------------
# 2. Determine architecture and build download URL
# ------------------------------------------------------------------
log ""
log "${BLUE}[2/4] Detecting architecture...${NC}"

ARCH="$(detect_arch)"
PKG_NAME="powershell-${FIXED_VERSION}-osx-${ARCH}.pkg"
DOWNLOAD_URL="${GITHUB_BASE}/${PKG_NAME}"

log "    Architecture : $ARCH"
log "    Package      : $PKG_NAME"
log "    URL          : $DOWNLOAD_URL"

# ------------------------------------------------------------------
# 3. Download the installer package
# ------------------------------------------------------------------
log ""
log "${BLUE}[3/4] Downloading PowerShell $FIXED_VERSION...${NC}"

mkdir -p "$WORK_DIR"
PKG_PATH="$WORK_DIR/$PKG_NAME"

if ! curl -fL --retry 3 --retry-delay 5 --progress-bar \
     -o "$PKG_PATH" "$DOWNLOAD_URL" 2>&1 | tee -a "$LOG_FILE"; then
    log "${RED}[ERROR]${NC} Download failed. Check network connectivity or proxy settings."
    exit 1
fi

log "    ${GREEN}Download complete.${NC} $(du -sh "$PKG_PATH" | cut -f1) — $PKG_PATH"

# ------------------------------------------------------------------
# 4. Install the package
# ------------------------------------------------------------------
log ""
log "${BLUE}[4/4] Installing PowerShell $FIXED_VERSION...${NC}"

if ! installer -pkg "$PKG_PATH" -target / 2>&1 | tee -a "$LOG_FILE"; then
    log "${RED}[ERROR]${NC} Installation failed. Review the log at $LOG_FILE."
    exit 1
fi

# ------------------------------------------------------------------
# Verify
# ------------------------------------------------------------------
log ""
log "${BLUE}Verifying installation...${NC}"

NEW_VERSION="$(get_installed_version)"

if [ -z "$NEW_VERSION" ]; then
    log "${RED}[FAIL]${NC} Could not read version after installation."
    exit 1
elif version_lt "$NEW_VERSION" "$FIXED_VERSION"; then
    log "${RED}[FAIL]${NC} Installed version $NEW_VERSION is still below $FIXED_VERSION."
    exit 1
else
    log "${GREEN}[FIXED]${NC} PowerShell updated: $CURRENT_VERSION → $NEW_VERSION ✓"
fi

log ""
log "${BLUE}=============================================="
log " Remediation Complete"
log " Log : $LOG_FILE"
log "==============================================${NC}"
log ""
log "Post-remediation verification:"
log "  /usr/local/bin/pwsh --version"
log ""
log "${YELLOW}Notes:${NC}"
log "  • Re-run a Nessus scan after updating to confirm the finding is resolved."
log "  • If the download fails in a restricted environment, pre-stage"
log "    the package and update DOWNLOAD_URL to a local/internal path."
log ""
