#!/bin/bash
# =============================================================================
# update-claude-code.sh
# Remediates : Anthropic Claude Code < 2.1.163 data exfiltration
# Nessus Plugin ID : 322792 | CVE-2026-54316
# Platform   : macOS (bash 3.2 compatible) | Deploy: Mosyle (runs as root)
#
# Written for CSMB-047 (2026-08-27 Tenable group export):
#   Path              : /Users/Developer/.local/bin/claude
#   Installed version : 2.1.92
#   Fixed version     : 2.1.163
#
# WHY THIS SCRIPT EXISTS RATHER THAN A NORMAL PACKAGE UPDATE: Claude Code is a
# PER-USER install under the user's own home (~/.local), so it is invisible to
# the usual machine-wide package paths and cannot simply be replaced by root
# dropping a new binary in /Applications. The repo's standing lesson applies:
# per-user installs need USER-CONTEXT execution.
#
# The good news on macOS is that updating Claude Code is a pure CLI operation --
# no GUI session required -- so `sudo -u <user>` works even when that user is
# not logged in. That means this genuinely can be initiated remotely from
# Mosyle without waiting for the user to cooperate, which is the whole point:
# these findings sit open precisely because the owner is unresponsive.
#
# WHAT IT DOES NOT DO: it does not reinstall Claude Code from scratch and it
# does not touch a user who has no Claude Code at all. It updates in place and
# verifies by re-reading the version, because an updater's exit code is not
# evidence (the standing lesson from RUM and the WinGet bundle).
#
# ALSO REPORTED: whether DISABLE_AUTOUPDATER is set for the user. Claude Code
# self-updates by default, so a host sitting many versions behind is itself a
# signal -- either the autoupdater is switched off, or it cannot reach the
# update endpoint (Zscaler). Fixing the version without noticing that just
# means the host drifts again.
#
# ENVIRONMENT (all optional; Mosyle passes none, so edit CONFIG below):
#   TARGET_VERSION=2.1.163   minimum acceptable version
#   ONLY_USER=alice          restrict to a single account (default: all)
#   DRY_RUN=1                report only, change nothing
#
# Exit: 0 = no vulnerable install remains
#       2 = something needs a human (update ran but version did not advance,
#           no usable update path, or an unparseable version)
#       1 = an install is still below target that should have been fixable
# =============================================================================

set -uo pipefail
HOME="${HOME:-/var/root}"
export HOME

# =============================================================================
# CONFIG -- Mosyle passes no environment variables. Edit before deploying.
# =============================================================================
CFG_TARGET_VERSION="2.1.163"
CFG_ONLY_USER=""
CFG_DRY_RUN="0"
# =============================================================================
TARGET_VERSION="${TARGET_VERSION:-$CFG_TARGET_VERSION}"
ONLY_USER="${ONLY_USER:-$CFG_ONLY_USER}"
DRY_RUN="${DRY_RUN:-$CFG_DRY_RUN}"

LOG_DIR="/var/log/composecure"
LOG_FILE="$LOG_DIR/claude_code_update.log"
mkdir -p "$LOG_DIR"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }

version_ge() { [ "$(printf '%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

# "2.1.92 (Claude Code)" / "claude 2.1.92" / "2.1.92" -> 2.1.92
parse_version() {
    echo "$1" | tr -d '\r' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z]+)*' | head -1
}

# Run a command as a given local user. Claude Code lives in ~/.local/bin, which
# is not on a non-interactive PATH by default, so it is added explicitly.
run_as_user() {
    _u="$1"; shift
    sudo -u "$_u" \
        HOME="/Users/$_u" \
        PATH="/Users/$_u/.local/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
        "$@"
}

VULN_SEEN=0
VULN_REMAINING=0
NEEDS_HUMAN=0
FOUND_ANY=0

log "===== update-claude-code.sh START ====="
log "Host: $(hostname -s 2>/dev/null || hostname)   plugin 322792"
log "Target: >= $TARGET_VERSION   DryRun=$DRY_RUN   OnlyUser=${ONLY_USER:-<all>}"

# -----------------------------------------------------------------------
# 1. Find every per-user Claude Code install
# -----------------------------------------------------------------------
log ""
log "[1] Locating per-user Claude Code installs under /Users/*/.local/bin ..."

for udir in /Users/*; do
    [ -d "$udir" ] || continue
    uname_only=$(basename "$udir")
    case "$uname_only" in Shared|.*) continue ;; esac
    if [ -n "$ONLY_USER" ] && [ "$uname_only" != "$ONLY_USER" ]; then continue; fi

    claude_bin="$udir/.local/bin/claude"
    [ -e "$claude_bin" ] || continue
    FOUND_ANY=1

    log ""
    log "--- user: $uname_only ---"
    log "  Binary: $claude_bin"

    RAW=$(run_as_user "$uname_only" "$claude_bin" --version 2>/dev/null || true)
    CUR=$(parse_version "${RAW:-}")
    if [ -z "$CUR" ]; then
        log "  Could not read a version (output: ${RAW:-<none>})."
        log "  Not guessing at the state of someone's editor install -- reporting only."
        NEEDS_HUMAN=1
        continue
    fi
    log "  Installed: $CUR"

    # A host sitting many versions behind usually means self-update is off or
    # blocked. Report it, because fixing the version alone lets it drift back.
    # Single quotes are deliberate: the variable must expand in the TARGET
    # user's shell, not in this root script's, so shellcheck's SC2016 does not
    # apply here.
    # shellcheck disable=SC2016
    AUTOUPD=$(run_as_user "$uname_only" /bin/sh -c 'echo "${DISABLE_AUTOUPDATER:-}"' 2>/dev/null || true)
    if [ -n "$AUTOUPD" ]; then
        log "  NOTE: DISABLE_AUTOUPDATER=$AUTOUPD is set for this user -- Claude Code"
        log "        self-update is switched off, which is likely why this host drifted."
        log "        Clearing the version without addressing that means it drifts again."
        NEEDS_HUMAN=1
    fi

    if version_ge "$CUR" "$TARGET_VERSION"; then
        log "  Already >= $TARGET_VERSION. Nothing to do."
        continue
    fi

    VULN_SEEN=1
    log "  VULNERABLE (< $TARGET_VERSION)."

    if [ "$DRY_RUN" = "1" ]; then
        log "  [DRY_RUN] Would run: claude update  (as $uname_only)"
        continue
    fi

    # -------------------------------------------------------------------
    # 2. Update in the user's own context
    # -------------------------------------------------------------------
    log "  Running 'claude update' as $uname_only ..."
    OUT=$(run_as_user "$uname_only" "$claude_bin" update 2>&1 || true)
    echo "$OUT" | while IFS= read -r l; do [ -n "$l" ] && log "    $l"; done

    # -------------------------------------------------------------------
    # 3. Verify by re-reading the version, not by trusting the exit code
    # -------------------------------------------------------------------
    NEWRAW=$(run_as_user "$uname_only" "$claude_bin" --version 2>/dev/null || true)
    NEW=$(parse_version "${NEWRAW:-}")
    log "  Post-update version: ${NEW:-unreadable}"

    if [ -z "$NEW" ]; then
        log "  Could not re-read the version after updating." 
        NEEDS_HUMAN=1
        continue
    fi
    if version_ge "$NEW" "$TARGET_VERSION"; then
        log "  SUCCESS: $CUR -> $NEW"
    else
        log "  Version did not reach $TARGET_VERSION (still $NEW)."
        log "  'claude update' may be unable to reach the update endpoint -- this"
        log "  fleet has a documented history of Zscaler SSL inspection breaking"
        log "  vendor update channels. Check egress for this host before assuming"
        log "  the updater is at fault."
        VULN_REMAINING=1
    fi
done

if [ "$FOUND_ANY" -eq 0 ]; then
    log ""
    log "  No per-user Claude Code install found under /Users/*/.local/bin."
    log "  Nothing to remediate on this host."
    log "===== END ====="
    exit 0
fi

# -----------------------------------------------------------------------
# 4. Final sweep
# -----------------------------------------------------------------------
log ""
log "[4] Final verification across all users ..."
REMAIN=0
for udir in /Users/*; do
    [ -d "$udir" ] || continue
    uname_only=$(basename "$udir")
    case "$uname_only" in Shared|.*) continue ;; esac
    if [ -n "$ONLY_USER" ] && [ "$uname_only" != "$ONLY_USER" ]; then continue; fi
    claude_bin="$udir/.local/bin/claude"
    [ -e "$claude_bin" ] || continue
    V=$(parse_version "$(run_as_user "$uname_only" "$claude_bin" --version 2>/dev/null || true)")
    if [ -n "$V" ] && ! version_ge "$V" "$TARGET_VERSION"; then
        log "  STILL VULNERABLE: $uname_only at $V (< $TARGET_VERSION)"
        REMAIN=1
    else
        log "  OK: $uname_only at ${V:-unknown}"
    fi
done

log ""
if [ "$DRY_RUN" = "1" ]; then
    log "RESULT: DRY_RUN -- nothing was changed."
    log "===== END (dry run) ====="
    exit 0
fi
if [ "$REMAIN" -eq 1 ] || [ "$VULN_REMAINING" -eq 1 ]; then
    log "RESULT: a vulnerable Claude Code install remains -- review the log above."
    log "===== END (not remediated) ====="
    exit 1
fi
if [ "$NEEDS_HUMAN" -eq 1 ]; then
    log "RESULT: versions are at or above target, but something above needs a human"
    log "        (self-update disabled, or a version that could not be read)."
    log "===== END (attention) ====="
    exit 2
fi
if [ "$VULN_SEEN" -eq 1 ]; then
    log "RESULT: vulnerable Claude Code found and updated."
else
    log "RESULT: no vulnerable Claude Code found on this host."
fi
log "Re-run a Nessus scan to confirm plugin 322792 clears."
log "===== update-claude-code.sh END ====="
exit 0
