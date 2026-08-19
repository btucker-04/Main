#!/bin/bash
# =============================================================================
# Get-MacRebootReason.sh  (v2)
# Read-only diagnostic: why did this Mac last restart?
# Platform : macOS (bash 3.2 compatible) | Deploy: Mosyle (runs as root)
#
# v2 fixes, from the 2026-08-03 CSMB-067 run:
#   * Boot-time parse: v1's sed was greedy ('.*sec = ' ran through to
#     'usec = ...'), so it reported the microseconds as the epoch -> "Booted at
#     1970-01-10". Now parsed with awk, with the human-readable tail as a check.
#   * Self-pollution: running 'log show' with a predicate containing the search
#     string writes a log entry containing that string, so v1's section 3 found
#     only its OWN invocations. Queries are now scoped to process == "kernel"
#     (or exclude process "log") and header lines are filtered out.
#   * Apple Silicon: M-series Macs frequently do NOT emit the "Previous shutdown
#     cause" kernel message at all. v1 called that "UNDETERMINED" even when the
#     real cause was plainly visible. v2 detects the architecture, treats the
#     missing code as expected there, and adds a PLANNED-RESTART detector.
#   * Speed: the cause query starts at the current boot time instead of
#     scanning 30 days (v1 spent ~2 minutes per log query).
#   * Dropped the separate 'last shutdown' call -- 'last reboot' already lists
#     the shutdown/reboot pairs; the extra call only printed "wtmp begins".
#
# Sources correlated:
#   1. Boot time + uptime + architecture
#   2. Boot/shutdown pairing            (last reboot -- utmpx, long retention)
#   3. "Previous shutdown cause" code   (unified log, kernel; often absent on ARM)
#   4. Kernel panic reports             (/Library/Logs/DiagnosticReports)
#   5. PLANNED-RESTART evidence         (SoftwareUpdate / DDM / MDM near boot)
#   6. macOS update activity            (/var/log/install.log)
#   7. Power-management events          (pmset -g log)
#
# Changes nothing. Log: /var/log/composecure/mac_reboot_reason.log
# Exit: 0 = clean/explained restart | 2 = unclean or unexplained | 1 = error
# =============================================================================

set -uo pipefail
HOME="${HOME:-/var/root}"
export HOME

LOG_DIR="/var/log/composecure"
LOG_FILE="$LOG_DIR/mac_reboot_reason.log"
LOOKBACK_DAYS="${LOOKBACK_DAYS:-30}"

mkdir -p "$LOG_DIR"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }

# Strip unified-log header rows and self-referential 'log show' entries
clean_log_output() {
    grep -v '^Timestamp  *Thread' | grep -v 'com.apple.log:' | grep -v 'log run noninteractively'
}

log "=============================================="
log " Mac Reboot Reason Check (v2, read-only)"
log " Host : $(hostname)"
log " Date : $(date)"
log "=============================================="

CLEAN=1
EXPLAINED=0     # we found a positive explanation for the restart

# -----------------------------------------------------------------------
# 1. Current boot session
# -----------------------------------------------------------------------
log ""
log "[1] Current boot session"
BOOTLINE=$(sysctl -n kern.boottime 2>/dev/null || true)
log "  kern.boottime : ${BOOTLINE:-unavailable}"

# '{ sec = 1785767836, usec = 881362 } Mon Aug  3 10:37:16 2026'
# field 4 is the seconds value (with trailing comma); awk avoids the greedy-sed trap
BOOTEPOCH=$(echo "$BOOTLINE" | awk '{gsub(/,/,"",$4); print $4}')
case "$BOOTEPOCH" in
    ''|*[!0-9]*) BOOTEPOCH="" ;;
esac
if [ -n "$BOOTEPOCH" ]; then
    BOOTHUMAN=$(date -r "$BOOTEPOCH" '+%Y-%m-%d %H:%M:%S')
    log "  Booted at     : $BOOTHUMAN  (epoch $BOOTEPOCH)"
else
    BOOTHUMAN=$(echo "$BOOTLINE" | sed -n 's/.*} *//p')
    log "  Booted at     : ${BOOTHUMAN:-unparsed}"
fi
log "  Uptime        : $(uptime | sed 's/^ *//')"
log "  OS version    : $(sw_vers -productVersion 2>/dev/null) (build $(sw_vers -buildVersion 2>/dev/null))"

ARCH=$(uname -m 2>/dev/null || echo unknown)
log "  Architecture  : $ARCH"
IS_ARM=0
[ "$ARCH" = "arm64" ] && IS_ARM=1

# -----------------------------------------------------------------------
# 2. Boot / shutdown pairing -- orderly vs abrupt
# -----------------------------------------------------------------------
log ""
log "[2] Recent boots and shutdowns (last reboot)"
REBOOT_OUT=$(last reboot 2>/dev/null | head -12 || true)
echo "$REBOOT_OUT" | while IFS= read -r line; do
    [ -n "$line" ] && log "  $line"
done
# An orderly restart records a 'shutdown time' shortly BEFORE the newest
# 'reboot time'. No preceding shutdown record suggests an abrupt loss.
FIRST_TWO=$(echo "$REBOOT_OUT" | head -2)
if echo "$FIRST_TWO" | sed -n '2p' | grep -qi 'shutdown'; then
    log ""
    log "  Newest boot is preceded by a recorded shutdown -> ORDERLY shutdown."
else
    log ""
    log "  No shutdown record immediately before the newest boot -> possible"
    log "  ABRUPT loss (power, hard power-off, or panic). See sections 3-4." 
    CLEAN=0
fi

# -----------------------------------------------------------------------
# 3. Previous shutdown cause (kernel; commonly absent on Apple Silicon)
# -----------------------------------------------------------------------
log ""
log "[3] Previous shutdown cause"
if [ -n "$BOOTEPOCH" ]; then
    START_ARG=$(date -r "$BOOTEPOCH" '+%Y-%m-%d %H:%M:%S')
    CAUSE_RAW=$(/usr/bin/log show --predicate 'process == "kernel" AND eventMessage CONTAINS "shutdown cause"' \
                --start "$START_ARG" 2>/dev/null | clean_log_output | grep -i "shutdown cause" || true)
else
    CAUSE_RAW=$(/usr/bin/log show --predicate 'process == "kernel" AND eventMessage CONTAINS "shutdown cause"' \
                --last "${LOOKBACK_DAYS}d" 2>/dev/null | clean_log_output | grep -i "shutdown cause" || true)
fi

CAUSE_FOUND=0
if [ -z "$CAUSE_RAW" ]; then
    if [ "$IS_ARM" -eq 1 ]; then
        log "  Not present -- EXPECTED on Apple Silicon. M-series Macs generally do"
        log "  not emit the 'Previous shutdown cause' kernel message. Rely on"
        log "  sections 2, 4 and 5 on this hardware."
    else
        log "  Not found in the searched window (log may have rotated)."
    fi
else
    echo "$CAUSE_RAW" | tail -3 | while IFS= read -r line; do
        [ -n "$line" ] && log "  $(echo "$line" | cut -c1-200)"
    done
    LASTCODE=$(echo "$CAUSE_RAW" | tail -1 | sed -n 's/.*[Ss]hutdown cause: *\(-*[0-9]*\).*/\1/p')
    if [ -n "$LASTCODE" ]; then
        CAUSE_FOUND=1
        log "  Code: $LASTCODE"
        case "$LASTCODE" in
            5)  log "  -> CLEAN: software-initiated restart or shutdown."; EXPLAINED=1 ;;
            3)  log "  -> FORCED POWER-OFF (power button held, or power cut)."; CLEAN=0 ;;
            0)  log "  -> POWER LOST / cause not recorded."; CLEAN=0 ;;
            -*) log "  -> NEGATIVE code: hardware, thermal, power or watchdog fault."
                log "     Apple publishes no complete code list, so no specific meaning is"
                log "     asserted here. Check sections 4 and 7."; CLEAN=0 ;;
            *)  log "  -> Code outside the well-established set; treat as unexplained."; CLEAN=0 ;;
        esac
    fi
fi

# -----------------------------------------------------------------------
# 4. Kernel panic reports (definitive)
# -----------------------------------------------------------------------
log ""
log "[4] Kernel panic reports"
PANIC_FOUND=0
for dir in "/Library/Logs/DiagnosticReports" "/Library/Logs/DiagnosticReports/Retired"; do
    [ -d "$dir" ] || continue
    while IFS= read -r pf; do
        [ -f "$pf" ] || continue
        PANIC_FOUND=1
        CLEAN=0
        log "  PANIC: $pf  (modified $(date -r "$pf" '+%Y-%m-%d %H:%M:%S'))"
        grep -m 4 -iE '"panicString"|panic\(|Kernel Extensions in backtrace|Sleep/Wake' "$pf" 2>/dev/null | \
            cut -c1-200 | while IFS= read -r pl; do
                [ -n "$pl" ] && log "         $pl"
            done
    done < <(find "$dir" -maxdepth 1 \( -name '*.panic' -o -name 'Kernel*.ips' -o -name 'panic*.ips' \) -mtime -"${LOOKBACK_DAYS}" 2>/dev/null | sort)
done
[ "$PANIC_FOUND" -eq 0 ] && log "  None in the last ${LOOKBACK_DAYS} days."

# -----------------------------------------------------------------------
# 5. PLANNED-RESTART evidence around the boot  (the strongest signal on ARM)
# -----------------------------------------------------------------------
log ""
log "[5] Planned-restart evidence (software update / DDM / MDM)"
PLANNED=0

# 5a. Software-update restart countdown held open before the shutdown
PM_ASSERT=$(pmset -g log 2>/dev/null | grep -iE "SoftwareUpdateNotification|RestartCountdown" | tail -8 || true)
if [ -n "$PM_ASSERT" ]; then
    PLANNED=1
    log "  Software-update restart countdown assertions:"
    echo "$PM_ASSERT" | while IFS= read -r line; do
        [ -n "$line" ] && log "    $(echo "$line" | cut -c1-190)"
    done
    log "    -> macOS was counting down to an update restart. A ClientDied or"
    log "       TimedOut entry followed by the shutdown means the countdown"
    log "       expired or the user accepted: an INTENDED restart."
fi

# 5b. Declarative Device Management (Mosyle OS-update enforcement)
DDM=$(grep -iE "SUOSUManagedServiceDaemon|DDM action|softwareupdate.*declaration" /var/log/install.log 2>/dev/null | tail -5 || true)
if [ -n "$DDM" ]; then
    PLANNED=1
    log "  Declarative Device Management (MDM update enforcement) active:"
    echo "$DDM" | while IFS= read -r line; do
        [ -n "$line" ] && log "    $(echo "$line" | cut -c1-190)"
    done
    log "    -> OS updates are being enforced by MDM (Mosyle DDM). Restarts on"
    log "       this Mac are expected to be update-driven."
fi

# 5c. Explicit MDM restart command
MDM=$(/usr/bin/log show --predicate 'process == "mdmclient" AND (eventMessage CONTAINS "RestartDevice" OR eventMessage CONTAINS "ShutDownDevice")' \
      --last "${LOOKBACK_DAYS}d" 2>/dev/null | clean_log_output | tail -5 || true)
if [ -n "$MDM" ]; then
    PLANNED=1
    log "  MDM restart/shutdown command(s):"
    echo "$MDM" | while IFS= read -r line; do
        [ -n "$line" ] && log "    $(echo "$line" | cut -c1-190)"
    done
fi

if [ "$PLANNED" -eq 0 ]; then
    log "  No planned-restart indicators found."
else
    EXPLAINED=1
fi

# -----------------------------------------------------------------------
# 6. macOS update / install activity
# -----------------------------------------------------------------------
log ""
log "[6] OS update / install activity (install.log)"
if [ -f /var/log/install.log ]; then
    UPD=$(grep -iE "macOS Installer|Installed .*macOS|Preparing to install|will restart|SUScan" /var/log/install.log 2>/dev/null | tail -8 || true)
    if [ -n "$UPD" ]; then
        echo "$UPD" | while IFS= read -r line; do
            [ -n "$line" ] && log "  $(echo "$line" | cut -c1-190)"
        done
        log "  (Timestamps just before the boot in section 1 confirm an update restart.)"
    else
        log "  No recent OS-install activity found."
    fi
else
    log "  /var/log/install.log not present."
fi

# -----------------------------------------------------------------------
# 7. Power-management events (thermal / battery / AC)
# -----------------------------------------------------------------------
log ""
log "[7] Power-management events (pmset -g log)"
PM=$(pmset -g log 2>/dev/null | grep -iE "Shutdown|Restart|Thermal|LowBattery|Emergency" | tail -12 || true)
if [ -n "$PM" ]; then
    echo "$PM" | while IFS= read -r line; do
        [ -n "$line" ] && log "  $(echo "$line" | cut -c1-190)"
    done
else
    log "  No matching power-management events."
fi

# -----------------------------------------------------------------------
# Verdict
# -----------------------------------------------------------------------
log ""
log "=============================================="
if [ "$PANIC_FOUND" -eq 1 ]; then
    log "VERDICT: PANIC -- a kernel panic report exists (section 4). Investigate"
    log "         the panic string and any third-party kexts named in it."
    log "=============================================="
    exit 2
fi
if [ "$CLEAN" -eq 1 ] && [ "$EXPLAINED" -eq 1 ]; then
    if [ "$PLANNED" -eq 1 ]; then
        log "VERDICT: CLEAN -- planned restart, update/MDM driven (section 5)."
    else
        log "VERDICT: CLEAN -- software-initiated shutdown (code 5)."
    fi
    log "=============================================="
    exit 0
fi
if [ "$CLEAN" -eq 1 ]; then
    log "VERDICT: ORDERLY but unattributed -- the shutdown was graceful (section 2)"
    log "         with no panic, but no update/MDM/code evidence names the trigger."
    log "         Most likely a user-initiated restart."
    log "=============================================="
    exit 0
fi
log "VERDICT: UNCLEAN OR UNEXPLAINED -- see sections 2, 3, 4 and 7. Repeated"
log "         unclean shutdowns on the same Mac warrant Apple Diagnostics rather"
log "         than further software troubleshooting."
log "=============================================="
exit 2
