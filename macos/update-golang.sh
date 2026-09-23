#!/bin/bash
# =============================================================================
# update-golang.sh  (v2)
# Remediates : Golang N.M.x below the latest STABLE patch on that same N.M
#              branch (plugin 327411: 1.25.x < 1.25.12 / 1.26.x < 1.26.5;
#              also covers the older 314962 floor of 1.25.10 / 1.26.3).
# Platform   : macOS (bash 3.2 compatible) | Deploy: Mosyle (runs as root)
#
# Written for CSMB-011 (2026-08-20 Tenable group export):
#   Path              : /usr/local/go/bin/go
#   Installed version : 1.25.9
#   Fixed version     : 1.25.10
#
# v2 (CSMB-011, 2026-09-22 / plugin 327411):
#   * v1 hardcoded FIX_125=1.25.10. After that patch landed, Tenable raised
#     the floor to 1.25.12 and the script logged "Already >= 1.25.10" on a
#     still-vulnerable 1.25.10 tree. Targets and tarball SHA-256s now come
#     from https://go.dev/dl/?mode=json&include=all at run time: latest
#     STABLE patch on the installed N.M line only (1.25.x stays on 1.25.x;
#     never jumps to 1.26/1.27). Homebrew formula `go` (unversioned) is
#     NOT brew-upgraded -- it tracks latest stable and would jump minors;
#     go@N.M formulae are upgraded in place.
#
# Handles THREE install methods (same lesson as update-nodejs.sh v2 -- looking
# at only Homebrew produced a false pass while /usr/local stayed vulnerable):
#   A. Official tree   -> /usr/local/go            (CSMB-011)
#   B. Homebrew        -> <prefix>/Cellar/go*/
#   C. gvm / asdf / per-user GOPATH toolchains     (REPORTED, never modified)
#
# Design:
#   * Stays on the installed N.M line (1.25.x -> latest stable 1.25.y from
#     the go.dev catalog). Never jumps a developer across minors/majors.
#   * Official tree is replaced the way go.dev documents it: download the
#     darwin tarball, verify SHA-256, extract to a staging dir, swap
#     /usr/local/go. The tarball's exit code is not evidence -- `go version`
#     after the swap is.
#   * A /usr/local/go that is a SYMLINK into Cellar/gvm/asdf is left to its
#     manager -- extracting the official tree over it would create a split
#     install.
#   * Homebrew still needs Cellar cleanup (side-by-side kegs linger; Tenable
#     keys on the version directory / binary path).
#
# CONFIG -- Mosyle passes no environment variables. Edit the block below
# before paste, or pass DRY_RUN=1 / FORCE_CLOSE=1 from a terminal.
# A terminal-set GO_DL_JSON points at a cached go.dev catalog (tests).
# =============================================================================

set -uo pipefail
HOME="${HOME:-/var/root}"
export HOME

# =============================================================================
CFG_DRY_RUN="0"
CFG_FORCE_CLOSE="0"
CFG_GO_DL_URL="https://go.dev/dl/?mode=json&include=all"
# =============================================================================
DRY_RUN="${DRY_RUN:-$CFG_DRY_RUN}"
FORCE_CLOSE="${FORCE_CLOSE:-$CFG_FORCE_CLOSE}"
GO_DL_URL="${GO_DL_URL:-$CFG_GO_DL_URL}"
GO_DL_JSON="${GO_DL_JSON:-}"

LOG_DIR="/var/log/composecure"
LOG_FILE="$LOG_DIR/golang_update.log"
WORK_DIR="/tmp/go_update_$$"
OFFICIAL_ROOT="/usr/local/go"
MIN_TGZ_BYTES=$((40 * 1024 * 1024))   # official darwin tarball is ~55-65 MB

log() {
    line="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$line"
    if [ -d "$LOG_DIR" ] && { [ -w "$LOG_FILE" ] || [ -w "$LOG_DIR" ]; }; then
        echo "$line" >> "$LOG_FILE" 2>/dev/null || true
    fi
}
cleanup() { rm -rf "$WORK_DIR"; }

go_python() {
    if [ -x /usr/bin/python3 ]; then
        echo /usr/bin/python3
    else
        command -v python3
    fi
}

version_ge() { [ "$(printf '%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

go_branch_of() {
    # 1.25.10 -> 1.25
    echo "$1" | awk -F. '{ if (NF >= 2) print $1 "." $2 }'
}

ensure_go_catalog() {
    if [ -n "$GO_DL_JSON" ] && [ -f "$GO_DL_JSON" ]; then
        return 0
    fi
    mkdir -p "$WORK_DIR"
    GO_DL_JSON="$WORK_DIR/go-dl.json"
    if [ -f "$GO_DL_JSON" ] && [ -s "$GO_DL_JSON" ]; then
        return 0
    fi
    log "  Fetching Go release catalog: $GO_DL_URL"
    if ! curl -fL --retry 3 --retry-delay 5 -o "$GO_DL_JSON" "$GO_DL_URL" 2>"$WORK_DIR/curl-catalog.err"; then
        log "  ERROR: could not download the go.dev catalog. If Zscaler blocks go.dev,"
        log "         stage it and set GO_DL_JSON to the file, or use an internal mirror."
        return 1
    fi
    # Proxy block pages are HTML, not JSON.
    if ! grep -q '"version"' "$GO_DL_JSON" 2>/dev/null; then
        log "  ERROR: catalog is not JSON (proxy block page?). Aborting."
        return 1
    fi
    return 0
}

go_catalog_query() {
    # $1 = latest  $2 = branch like 1.25
    # $1 = sha     $2 = filename
    op="$1"
    arg="$2"
    "$(go_python)" - "$op" "$arg" "$GO_DL_JSON" <<'PY'
import json, sys
op, arg, path = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    data = json.load(open(path))
except Exception:
    sys.exit(1)
if not isinstance(data, list):
    sys.exit(1)
if op == 'latest':
    prefix = 'go' + arg + '.'
    best_n = -1
    best = ''
    for rel in data:
        if not rel.get('stable'):
            continue
        ver = rel.get('version') or ''
        if not ver.startswith(prefix):
            continue
        rest = ver[len(prefix):]
        if not rest.isdigit():
            continue
        n = int(rest)
        if n > best_n:
            best_n = n
            best = ver[2:]  # strip leading "go"
    if not best:
        sys.exit(1)
    sys.stdout.write(best)
    sys.exit(0)
if op == 'sha':
    for rel in data:
        for f in rel.get('files') or []:
            if f.get('filename') == arg and f.get('sha256'):
                sys.stdout.write(f.get('sha256'))
                sys.exit(0)
    sys.exit(1)
sys.exit(1)
PY
}

required_fixed_for() {
    ver="$1"
    [ -n "$ver" ] || { echo ""; return 0; }
    branch=$(go_branch_of "$ver")
    [ -n "$branch" ] || { echo ""; return 0; }
    ensure_go_catalog || { echo ""; return 0; }
    go_catalog_query latest "$branch" 2>/dev/null || echo ""
}

go_tarball_sha256() {
    name="$1"
    [ -n "$name" ] || { echo ""; return 0; }
    ensure_go_catalog || { echo ""; return 0; }
    go_catalog_query sha "$name" 2>/dev/null || echo ""
}

read_go_version() {
    # "go version go1.25.9 darwin/arm64" -> 1.25.9
    "$1" version 2>/dev/null | awk '{print $3}' | sed 's/^go//' || true
}

realpath_of() {
    py=$(go_python)
    if [ -n "$py" ]; then
        "$py" -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$1" 2>/dev/null || echo "$1"
    else
        echo "$1"
    fi
}

if [ "${GO_SELFTEST:-0}" = "1" ]; then
    return 0 2>/dev/null || exit 0
fi

mkdir -p "$LOG_DIR"
trap cleanup EXIT

VULN_SEEN=0
VULN_REMAINING=0
UNMANAGED_NOTE=0

log "===== update-golang.sh START ====="
log "Host: $(hostname -s 2>/dev/null || hostname)   plugin 327411 (also 314962)"
log "DryRun=$DRY_RUN  ForceClose=$FORCE_CLOSE"

if [ -z "$(go_python)" ]; then
    log "ERROR: python3 is required to parse the go.dev catalog."
    exit 1
fi
if ! ensure_go_catalog; then
    log "ERROR: cannot continue without a Go release catalog."
    exit 1
fi

# -----------------------------------------------------------------------
# Arch + Homebrew prefix
# -----------------------------------------------------------------------
case "$(uname -m)" in
    arm64)  GO_ARCH="arm64" ;;
    x86_64) GO_ARCH="amd64" ;;
    *)
        log "ERROR: unsupported architecture $(uname -m)"
        exit 1
        ;;
esac
log "Arch: $GO_ARCH"

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

CONSOLE_USER=$(stat -f "%Su" /dev/console 2>/dev/null || true)
case "$CONSOLE_USER" in ""|root|loginwindow|_mbsetupuser)
    if [ -n "$BREW_PREFIX" ]; then
        CONSOLE_USER=$(stat -f "%Su" "$BREW_PREFIX/bin/brew" 2>/dev/null || true)
    else
        CONSOLE_USER=""
    fi ;;
esac
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
# METHOD A -- official /usr/local/go  (CSMB-011)
# =======================================================================
log ""
log "[A] Official Go tree at $OFFICIAL_ROOT"

if [ ! -e "$OFFICIAL_ROOT/bin/go" ]; then
    log "  No $OFFICIAL_ROOT/bin/go present."
else
    REAL=$(realpath_of "$OFFICIAL_ROOT")
    log "  $OFFICIAL_ROOT -> $REAL"
    case "$REAL" in
        */Cellar/*|*/.gvm/*|*/.asdf/*|*/goenv/*)
            log "  This is a symlink into a managed toolchain -- handled by its own"
            log "  manager (see sections B and C). Not extracting the official tarball over it."
            ;;
        *)
            CUR=$(read_go_version "$OFFICIAL_ROOT/bin/go")
            if [ -z "$CUR" ]; then
                log "  ERROR: could not read version from $OFFICIAL_ROOT/bin/go"
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
                    log "  VULNERABLE (< $NEED). Replacing $OFFICIAL_ROOT from the official tarball."

                    GO_PROCS=$(ps -axo pid=,comm= 2>/dev/null | grep -i "$OFFICIAL_ROOT/" || true)
                    if [ -n "$GO_PROCS" ]; then
                        log "  Go toolchain processes are running:"
                        echo "$GO_PROCS" | while IFS= read -r l; do [ -n "$l" ] && log "    $l"; done
                        if [ "$FORCE_CLOSE" = "1" ]; then
                            log "  FORCE_CLOSE=1 -- sending TERM to those PIDs."
                            echo "$GO_PROCS" | awk '{print $1}' | while IFS= read -r p; do
                                [ -n "$p" ] && kill "$p" 2>/dev/null || true
                            done
                            sleep 2
                        else
                            log "  Refusing to swap GOROOT out from under a running compile."
                            log "  Re-run with FORCE_CLOSE=1 (or CFG_FORCE_CLOSE=1) or wait until idle."
                            VULN_REMAINING=1
                            UNMANAGED_NOTE=1
                            NEED=""
                        fi
                    fi

                    if [ -n "$NEED" ]; then
                        TARBALL="go${NEED}.darwin-${GO_ARCH}.tar.gz"
                        EXPECT=$(go_tarball_sha256 "$TARBALL")
                        URL="https://go.dev/dl/${TARBALL}"
                        mkdir -p "$WORK_DIR"
                        DEST="$WORK_DIR/$TARBALL"
                        if [ "$DRY_RUN" = "1" ]; then
                            log "  [DRY_RUN] Would download $URL, verify $EXPECT, swap $OFFICIAL_ROOT"
                        elif [ -z "$EXPECT" ]; then
                            log "  ERROR: no pinned SHA-256 for $TARBALL -- refusing to install an unhashed artifact."
                            VULN_REMAINING=1
                        else
                            log "  Downloading $URL"
                            if ! curl -fL --retry 3 --retry-delay 5 -o "$DEST" "$URL" 2>>"$LOG_FILE"; then
                                log "  ERROR: download failed. If Zscaler blocks go.dev / dl.google.com,"
                                log "         stage the tarball and re-run, or bump the URL to an internal mirror."
                                VULN_REMAINING=1
                            else
                                SZ=$(stat -f "%z" "$DEST" 2>/dev/null || echo 0)
                                log "  Downloaded: $((SZ / 1024 / 1024)) MB"
                                MAGIC=$(dd if="$DEST" bs=2 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')
                                GOT=$(shasum -a 256 "$DEST" | awk '{print $1}')
                                log "  SHA-256: $GOT"
                                if [ "$SZ" -lt "$MIN_TGZ_BYTES" ] || [ "$MAGIC" != "1f8b" ]; then
                                    log "  ERROR: not a valid gzip tarball (size or 1f8b header check failed)."
                                    log "         Almost certainly a proxy block page. Aborting this component."
                                    VULN_REMAINING=1
                                elif [ "$GOT" != "$EXPECT" ]; then
                                    log "  ERROR: SHA-256 mismatch (expected $EXPECT)."
                                    VULN_REMAINING=1
                                else
                                    log "  Extracting to staging..."
                                    mkdir -p "$WORK_DIR/extract"
                                    if ! tar -C "$WORK_DIR/extract" -xzf "$DEST" 2>>"$LOG_FILE"; then
                                        log "  ERROR: tar extract failed."
                                        VULN_REMAINING=1
                                    elif [ ! -x "$WORK_DIR/extract/go/bin/go" ]; then
                                        log "  ERROR: tarball did not contain go/bin/go."
                                        VULN_REMAINING=1
                                    else
                                        STAGED_VER=$(read_go_version "$WORK_DIR/extract/go/bin/go")
                                        log "  Staged version: ${STAGED_VER:-unknown}"
                                        if [ -z "$STAGED_VER" ] || ! version_ge "$STAGED_VER" "$NEED"; then
                                            log "  ERROR: staged binary is not >= $NEED -- leaving $OFFICIAL_ROOT untouched."
                                            VULN_REMAINING=1
                                        else
                                            BAK="${OFFICIAL_ROOT}.bak.$$"
                                            log "  Swapping $OFFICIAL_ROOT (backup $BAK)..."
                                            if ! mv "$OFFICIAL_ROOT" "$BAK"; then
                                                log "  ERROR: could not move existing tree aside."
                                                VULN_REMAINING=1
                                            elif ! mv "$WORK_DIR/extract/go" "$OFFICIAL_ROOT"; then
                                                log "  ERROR: swap failed -- restoring backup."
                                                mv "$BAK" "$OFFICIAL_ROOT" 2>/dev/null || true
                                                VULN_REMAINING=1
                                            else
                                                NEW=$(read_go_version "$OFFICIAL_ROOT/bin/go")
                                                log "  Post-swap version: ${NEW:-unknown}"
                                                if [ -n "$NEW" ] && version_ge "$NEW" "$NEED"; then
                                                    log "  SUCCESS: $CUR -> $NEW"
                                                    rm -rf "$BAK"
                                                else
                                                    log "  ERROR: version did not reach $NEED -- restoring backup."
                                                    rm -rf "$OFFICIAL_ROOT"
                                                    mv "$BAK" "$OFFICIAL_ROOT" 2>/dev/null || true
                                                    VULN_REMAINING=1
                                                fi
                                            fi
                                        fi
                                    fi
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
# METHOD B -- Homebrew
# =======================================================================
log ""
log "[B] Homebrew Go"

CELLAR=""
GO_FORMULAE=""
if [ -n "$BREW_PREFIX" ] && [ -d "$BREW_PREFIX/Cellar" ]; then
    CELLAR="$BREW_PREFIX/Cellar"
    while IFS= read -r fdir; do
        [ -d "$fdir" ] || continue
        GO_FORMULAE="$GO_FORMULAE $(basename "$fdir")"
    done < <(find "$CELLAR" -mindepth 1 -maxdepth 1 -type d \( -name 'go' -o -name 'go@*' \) 2>/dev/null | sort)
fi

if [ -z "$GO_FORMULAE" ]; then
    log "  No Homebrew go formulae installed."
else
    while IFS= read -r vdir; do
        [ -d "$vdir" ] || continue
        gobin="$vdir/bin/go"
        if [ -x "$gobin" ]; then
            ver=$(read_go_version "$gobin")
        else
            ver=$(basename "$vdir")
        fi
        [ -n "$ver" ] || continue
        need=$(required_fixed_for "$ver")
        if [ -z "$need" ]; then
            log "  $vdir  ($ver)  [branch not in advisory -- review manually]"
            UNMANAGED_NOTE=1
        elif version_ge "$ver" "$need"; then
            log "  $vdir  ($ver)  [OK >= $need]"
        else
            log "  $vdir  ($ver)  [VULNERABLE < $need]"
            VULN_SEEN=1
        fi
    done < <(find "$CELLAR" -mindepth 2 -maxdepth 2 -type d \( -path '*/go/*' -o -path '*/go@*/*' \) 2>/dev/null | sort)

    if [ "$DRY_RUN" = "1" ]; then
        log "  [DRY_RUN] Would brew update + upgrade + cleanup for versioned go@N.M formulae (not unversioned go):$GO_FORMULAE"
    elif [ -n "$BREW_USER" ]; then
        log "  brew update..."
        OUT=$(run_brew update 2>&1); log "  $OUT"
        for f in $GO_FORMULAE; do
            if [ "$f" = "go" ]; then
                log "  Skipping brew upgrade of unversioned formula 'go' -- it tracks latest stable and would jump N.M."
                log "  Use go@N.M or the official /usr/local/go tree to stay on the installed branch."
                continue
            fi
            log "  brew upgrade $f ..."
            OUT=$(run_brew upgrade "$f" 2>&1); log "  $OUT"
            OUT=$(run_brew cleanup "$f" 2>&1); log "  cleanup $f: $OUT"
        done
    else
        log "  Cannot run brew -- skipping Homebrew upgrade."
    fi

    # Remove Cellar kegs still below the branch threshold, but only when a
    # patched keg of that SAME 1.xx line is present.
    while IFS= read -r vdir; do
        [ -d "$vdir" ] || continue
        gobin="$vdir/bin/go"
        if [ -x "$gobin" ]; then
            ver=$(read_go_version "$gobin")
        else
            ver=$(basename "$vdir")
        fi
        [ -n "$ver" ] || continue
        need=$(required_fixed_for "$ver")
        [ -z "$need" ] && continue
        version_ge "$ver" "$need" && continue
        fdir=$(dirname "$vdir")
        branch=$(echo "$ver" | awk -F. '{print $1 "." $2}')
        patched_present=0
        while IFS= read -r other; do
            [ -d "$other" ] || continue
            obin="$other/bin/go"
            if [ -x "$obin" ]; then
                over=$(read_go_version "$obin")
            else
                over=$(basename "$other")
            fi
            [ -n "$over" ] || continue
            [ "$(echo "$over" | awk -F. '{print $1 "." $2}')" = "$branch" ] || continue
            oneed=$(required_fixed_for "$over")
            [ -z "$oneed" ] && continue
            if version_ge "$over" "$oneed"; then patched_present=1; fi
        done < <(find "$fdir" -mindepth 1 -maxdepth 1 -type d 2>/dev/null)
        if [ "$patched_present" -eq 1 ]; then
            if [ "$DRY_RUN" = "1" ]; then
                log "  [DRY_RUN] Would remove $vdir (v$ver < $need; patched ${branch}.x present)"
            else
                log "  [REMOVE] $vdir (v$ver < $need; patched ${branch}.x present)"
                rm -rf "$vdir"
            fi
        else
            log "  [KEEP]   $vdir (v$ver < $need) -- no patched ${branch}.x present; not removing the only Go on this branch."
            VULN_REMAINING=1
        fi
    done < <(find "$CELLAR" -mindepth 2 -maxdepth 2 -type d \( -path '*/go/*' -o -path '*/go@*/*' \) 2>/dev/null | sort)
fi

# =======================================================================
# METHOD C -- per-user version managers (REPORT ONLY)
# =======================================================================
log ""
log "[C] gvm / asdf / goenv Go versions (report only)"
FOUND_OTHER=0
for udir in /Users/*; do
    [ -d "$udir" ] || continue
    uname_only=$(basename "$udir")
    case "$uname_only" in Shared|.*) continue ;; esac
    for mgr in ".gvm/gos" ".asdf/installs/golang" ".asdf/installs/go" ".goenv/versions" "sdk/go"; do
        mpath="$udir/$mgr"
        [ -d "$mpath" ] || continue
        while IFS= read -r v; do
            [ -d "$v" ] || continue
            gobin="$v/bin/go"
            [ -x "$gobin" ] || continue
            FOUND_OTHER=1
            vv=$(read_go_version "$gobin")
            [ -n "$vv" ] || continue
            need=$(required_fixed_for "$vv")
            if [ -n "$need" ] && ! version_ge "$vv" "$need"; then
                log "  $uname_only: $vv  [VULNERABLE < $need]  <- $v"
                UNMANAGED_NOTE=1
            else
                log "  $uname_only: $vv  <- $v"
            fi
        done < <(find "$mpath" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort)
    done
done
if [ "$FOUND_OTHER" -eq 0 ]; then
    log "  None found."
else
    log "  NOTE: per-user toolchains are NOT modified by this script. Any version"
    log "        flagged above should be updated by the developer."
fi

# =======================================================================
# Verification
# =======================================================================
log ""
log "[D] Final verification"

REMAIN=0
if [ -x "$OFFICIAL_ROOT/bin/go" ]; then
    REAL=$(realpath_of "$OFFICIAL_ROOT")
    case "$REAL" in
        */Cellar/*|*/.gvm/*|*/.asdf/*|*/goenv/*) ;;
        *)
            SV=$(read_go_version "$OFFICIAL_ROOT/bin/go")
            SN=$(required_fixed_for "${SV:-0.0.0}")
            if [ -n "$SV" ] && [ -n "$SN" ] && ! version_ge "$SV" "$SN"; then
                log "  STILL VULNERABLE: $OFFICIAL_ROOT at $SV (< $SN)"
                REMAIN=1
            else
                log "  OK: $OFFICIAL_ROOT at ${SV:-unknown}"
            fi
            ;;
    esac
fi

if [ -n "$CELLAR" ]; then
    while IFS= read -r vdir; do
        [ -d "$vdir" ] || continue
        gobin="$vdir/bin/go"
        [ -x "$gobin" ] || continue
        ver=$(read_go_version "$gobin")
        need=$(required_fixed_for "$ver")
        if [ -n "$need" ] && ! version_ge "$ver" "$need"; then
            log "  STILL VULNERABLE: $vdir ($ver < $need)"
            REMAIN=1
        else
            log "  OK: $vdir ($ver)"
        fi
    done < <(find "$CELLAR" -mindepth 2 -maxdepth 2 -type d \( -path '*/go/*' -o -path '*/go@*/*' \) 2>/dev/null | sort)
fi

log ""
if [ "$DRY_RUN" = "1" ]; then
    log "RESULT: DRY_RUN -- nothing was changed."
    log "===== END (dry run) ====="
    exit 0
fi
if [ "$REMAIN" -eq 1 ] || [ "$VULN_REMAINING" -eq 1 ]; then
    log "RESULT: vulnerable Go remains on this host -- review log above."
    log "===== END (incomplete) ====="
    exit 1
fi
if [ "$UNMANAGED_NOTE" -eq 1 ]; then
    log "RESULT: managed installs are patched, but items above need a human"
    log "        (per-user toolchain, a running compile, or a branch not in the advisory)."
    log "===== END (attention) ====="
    exit 2
fi
if [ "$VULN_SEEN" -eq 1 ]; then
    log "RESULT: vulnerable Go found and remediated."
else
    log "RESULT: no vulnerable Go found on this host."
fi
log "Re-run a Nessus scan to confirm plugin 327411 (and 314962) clears."
log "===== update-golang.sh END ====="
exit 0
