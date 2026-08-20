#!/bin/bash
# =============================================================================
# remediate-ruby-gem.sh  (v3)
# Generic remediation for a vulnerable Ruby gem on macOS.
# Platform : macOS (bash 3.2 compatible) | Deploy: Mosyle (runs as root)
#
# Supersedes four single-purpose scripts:
#   remediate_rexml_210049.sh + cleanup_rexml_gemspec_210049.sh   (plugin 210049)
#   ruby-netimap-update.sh    + ruby-netimap-cellar-cleanup.sh    (plugin 313278)
#
# WHY UPDATE AND CLEANUP MUST BE ONE SCRIPT: Tenable keys these findings on
# GEMSPEC FILE PRESENCE, not on what `gem list` reports. `gem update` installs
# the patched gem into the SHARED gems directory and leaves the old .gemspec
# behind -- often in a completely different tree, e.g. Homebrew's Cellar
# built-in specs. So the finding does not clear on update alone. But cleanup run
# on its own is DANGEROUS: with no knowledge of whether the update succeeded, it
# can delete the only copy of a gem and break Ruby. Combined, the deletion is
# gated on a patched spec being confirmed present in the SAME BRANCH first.
#
# v3 (from the 2026-08-17 ARMB-02 run, where nothing was removed):
#   * THE GUARD WAS UNSATISFIABLE for a global threshold. It required a patched
#     spec in the same VERSION BRANCH, so a 3.2.5 spec needed a patched 3.2.x --
#     impossible when the fix is 3.3.9. The guard is now scoped to the same RUBY
#     TREE: a patched spec anywhere that Ruby loads from satisfies it. Homebrew's
#     Cellar built-in specs and <prefix>/lib/ruby/gems/<abi> are treated as one
#     tree, which is the whole point -- `gem update` writes to the shared dir
#     while the stale spec sits in the Cellar. Branch matching is applied ONLY
#     when THRESHOLDS are per-branch (net-imap style), because there an app
#     pinned to ~>0.4 is not helped by a 0.6.4 spec.
#   * ORDERING BUG: the guard's early exit ran BEFORE the portable-ruby and
#     system-Ruby classification, so superseded portable-ruby trees were logged
#     as KEEP instead of being removed. Classification now happens first.
#   * Default gems (specifications/default/...) are recognised and never deleted;
#     they ship with Ruby and removing one breaks the interpreter.
#
# PER-BRANCH THRESHOLDS: gems are commonly fixed independently per minor line.
# A flat "greater than X" test is wrong and has caused a real bug here -- a
# net-imap 0.6.3 spec satisfied a flat >= 0.5.14 check while being vulnerable in
# its own branch, which would have let the cleanup remove every remaining spec.
# Thresholds are therefore matched longest-prefix-first, per branch.
#
# ENVIRONMENT:
#   (Configure via the CONFIG block below, or positional args, or environment.)
#   GEM=rexml                       (required) gem name
#   THRESHOLDS="3.3.9"              (required) either a single minimum, or
#   THRESHOLDS="0.4:0.4.24;0.5:0.5.14;0.6:0.6.4"
#                                   per-branch "prefix:minimum" pairs.
#                                   A spec whose version matches no branch
#                                   prefix is REPORTED and never deleted.
#   PLUGIN=210049                   (optional) for the log header only
#   NO_INSTALL=1                    (optional) clean up only; never install
#   DRY_RUN=1                       (optional) report only, delete nothing
#
# Examples:
#   GEM=rexml    THRESHOLDS="3.3.9"                                    PLUGIN=210049
#   GEM=net-imap THRESHOLDS="0.4:0.4.24;0.5:0.5.14;0.6:0.6.4"          PLUGIN=313278
#   GEM=webrick  THRESHOLDS="1.8.2"                                    PLUGIN=<n>
#
# HOMEBREW PORTABLE RUBY: Homebrew ships its own Ruby under
# <prefix>/Library/Homebrew/vendor/portable-ruby/<version>/ to run brew itself,
# and each copy carries its own bundled gems. armb-02 (2026-08-17) had THREE
# stale portable-ruby trees holding vulnerable rexml specs -- 3.1.4, 3.3.1 and
# 3.3.2 -- alongside the real Cellar Ruby. Those specs are NOT user-updatable
# with `gem install`; the correct remediation is to remove the SUPERSEDED
# portable-ruby trees (brew keeps only the current one), while the CURRENT tree
# is left alone because deleting it breaks brew. A vulnerable spec in the
# current portable-ruby is a Homebrew-upstream matter: reported, not touched.
#
# Covers the Ruby locations the fleet actually has: macOS system Ruby
# (/Library/Ruby/Gems -- note this is SIP-adjacent and usually NOT writable, so
# it is reported rather than modified), Homebrew Ruby (prefix auto-detected for
# Intel /usr/local vs Apple Silicon /opt/homebrew, including Cellar built-in
# specs), and per-user rbenv under /Users/*/.rbenv and the Homebrew rbenv root.
#
# Exit: 0 = no vulnerable spec remains
#       2 = something needs a human (system-Ruby spec, unknown branch, or no
#           usable brew user to install with)
#       1 = a vulnerable spec remains that should have been fixable
# =============================================================================

set -uo pipefail
HOME="${HOME:-/var/root}"
export HOME

# =============================================================================
# CONFIG -- EDIT THESE TWO LINES BEFORE PASTING INTO MOSYLE.
# Mosyle runs the script directly and passes no environment variables, so
# in-script config is the deployable path (same constraint as EC stripping
# parameters). Precedence: command-line args > environment > these defaults.
#
#   rexml    : CFG_GEM="rexml"    CFG_THRESHOLDS="3.3.9"
#   net-imap : CFG_GEM="net-imap" CFG_THRESHOLDS="0.4:0.4.24;0.5:0.5.14;0.6:0.6.4"
#   webrick  : CFG_GEM="webrick"  CFG_THRESHOLDS="1.8.2"
# =============================================================================
CFG_GEM="rexml"
CFG_THRESHOLDS="3.3.9"
CFG_PLUGIN="210049"
CFG_NO_INSTALL="0"
CFG_DRY_RUN="0"

# Positional args win, then environment, then the CONFIG block above.
GEM="${1:-${GEM:-$CFG_GEM}}"
THRESHOLDS="${2:-${THRESHOLDS:-$CFG_THRESHOLDS}}"
PLUGIN="${3:-${PLUGIN:-$CFG_PLUGIN}}"
NO_INSTALL="${NO_INSTALL:-$CFG_NO_INSTALL}"
DRY_RUN="${DRY_RUN:-$CFG_DRY_RUN}"

LOG_DIR="/var/log/composecure"
LOG_FILE="$LOG_DIR/ruby_gem_remediation.log"
mkdir -p "$LOG_DIR"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }

if [ -z "$GEM" ] || [ -z "$THRESHOLDS" ]; then
    log "ERROR: no gem/thresholds configured. Set the CONFIG block at the top of"
    log "       this script (Mosyle passes no environment variables), or pass them"
    log "       positionally:  ./remediate-ruby-gem.sh rexml \"3.3.9\" 210049"
    exit 1
fi

version_ge() { [ "$(printf '%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

# Longest-prefix-first branch match. Returns "" when no branch covers it.
required_for() {
    ver="$1"; best_pref=""; best_min=""
    echo "$THRESHOLDS" | tr ';' '\n' | while IFS= read -r pair; do
        [ -z "$pair" ] && continue
        case "$pair" in
            *:*) pref="${pair%%:*}"; min="${pair##*:}" ;;
            *)   pref=""; min="$pair" ;;          # single global minimum
        esac
        if [ -z "$pref" ]; then
            echo "GLOBAL $min"
        else
            case "$ver" in
                "$pref".*|"$pref") echo "${#pref} $min" ;;
            esac
        fi
    done | sort -rn | head -1 | awk '{print $2}'
}

# Which Ruby "tree" (load-path scope) does this spec belong to, and its ABI?
# Homebrew's Cellar ruby and <prefix>/lib/ruby/gems share a scope on purpose.
abi_of() {
    echo "$1" | sed -nE 's|.*/[Gg]ems/([0-9][0-9.]+)/specifications.*|\1|p'
}
scope_of() {
    s="$1"
    if [ -n "$PORTABLE_ROOT" ]; then
        case "$s" in
            "$PORTABLE_ROOT"/*)
                echo "PORTABLE:$(echo "$s" | sed "s|^$PORTABLE_ROOT/||" | cut -d/ -f1)"; return ;;
        esac
    fi
    case "$s" in
        /Library/Ruby/*) echo "SYSTEM"; return ;;
        */.rbenv/versions/*) echo "RBENV:$(echo "$s" | sed -nE 's|.*/\.rbenv/versions/([^/]+)/.*|\1|p')"; return ;;
    esac
    if [ -n "$BREW_PREFIX" ]; then
        case "$s" in
            "$BREW_PREFIX"/Cellar/ruby/*|"$BREW_PREFIX"/lib/ruby/gems/*|"$BREW_PREFIX"/opt/ruby/*)
                echo "HOMEBREW"; return ;;
        esac
    fi
    echo "OTHER:$(dirname "$(dirname "$s")")"
}
is_default_gem() { case "$1" in */specifications/default/*) return 0 ;; *) return 1 ;; esac; }
# Per-branch thresholds present? Then a patched spec must also match the branch.
THRESH_PER_BRANCH=0
case "$THRESHOLDS" in *:*) THRESH_PER_BRANCH=1 ;; esac

spec_version() { echo "$1" | sed -E "s/^${GEM}-([0-9][0-9A-Za-z.]*)\.gemspec$/\1/"; }

WORK="/tmp/rubygem_$$"; mkdir -p "$WORK"
trap 'rm -rf "$WORK"' EXIT

log "===== remediate-ruby-gem.sh START ====="
log "Host: $(hostname -s)   GEM=$GEM   THRESHOLDS=$THRESHOLDS   PLUGIN=${PLUGIN:-n/a}"

# -----------------------------------------------------------------------
# 0. Homebrew prefix + a non-root user able to run brew/gem
# -----------------------------------------------------------------------
BREW_PREFIX=""
for p in /opt/homebrew /usr/local; do
    [ -x "$p/bin/brew" ] && BREW_PREFIX="$p" && break
done
[ -n "$BREW_PREFIX" ] && log "Homebrew prefix: $BREW_PREFIX" || log "Homebrew not installed."

CONSOLE_USER=$(stat -f "%Su" /dev/console 2>/dev/null || true)
case "$CONSOLE_USER" in ""|root|loginwindow|_mbsetupuser)
    if [ -n "$BREW_PREFIX" ]; then
        CONSOLE_USER=$(stat -f "%Su" "$BREW_PREFIX/bin/brew" 2>/dev/null || true)
    else
        CONSOLE_USER=""
    fi ;;
esac
BREW_USER=""
if [ -n "$CONSOLE_USER" ] && [ "$CONSOLE_USER" != "root" ]; then
    BREW_USER="$CONSOLE_USER"
    log "Acting user for gem operations: $BREW_USER"
else
    log "WARNING: no non-root user found; cannot install gems. Cleanup only."
fi

run_as_user() {
    sudo -u "$BREW_USER" \
        HOME="/Users/$BREW_USER" \
        PATH="$BREW_PREFIX/opt/ruby/bin:$BREW_PREFIX/bin:$BREW_PREFIX/sbin:/usr/bin:/bin" \
        NONINTERACTIVE=1 "$@"
}

# -----------------------------------------------------------------------
# 1. Find every gemspec for this gem, in every Ruby tree we know about
# -----------------------------------------------------------------------
log ""
log "[1] Locating $GEM gemspecs..."
SEARCH_ROOTS="/Library/Ruby/Gems"
PORTABLE_ROOT=""
PORTABLE_CURRENT=""
if [ -n "$BREW_PREFIX" ]; then
    SEARCH_ROOTS="$SEARCH_ROOTS $BREW_PREFIX/lib/ruby/gems $BREW_PREFIX/Cellar $BREW_PREFIX/opt/rbenv"
    PORTABLE_ROOT="$BREW_PREFIX/Library/Homebrew/vendor/portable-ruby"
    if [ -d "$PORTABLE_ROOT" ]; then
        SEARCH_ROOTS="$SEARCH_ROOTS $PORTABLE_ROOT"
        # 'current' symlink when present, else the highest version directory.
        if [ -L "$PORTABLE_ROOT/current" ]; then
            PORTABLE_CURRENT=$(basename "$(readlink "$PORTABLE_ROOT/current")")
        else
            PORTABLE_CURRENT=$(find "$PORTABLE_ROOT" -mindepth 1 -maxdepth 1 -type d 2>/dev/null \
                               | sed "s|.*/||" | grep -E '^[0-9]' | sort -V | tail -1)
        fi
        log "Homebrew portable-ruby root: $PORTABLE_ROOT (current: ${PORTABLE_CURRENT:-unknown})"
    fi
fi
for udir in /Users/*; do
    [ -d "$udir/.rbenv" ] && SEARCH_ROOTS="$SEARCH_ROOTS $udir/.rbenv"
    [ -d "$udir/.gem" ]   && SEARCH_ROOTS="$SEARCH_ROOTS $udir/.gem"
done

: > "$WORK/specs"
for root in $SEARCH_ROOTS; do
    [ -d "$root" ] || continue
    find "$root" -name "${GEM}-*.gemspec" -type f 2>/dev/null >> "$WORK/specs" || true
done
sort -u "$WORK/specs" -o "$WORK/specs"

if [ ! -s "$WORK/specs" ]; then
    log "  No $GEM gemspecs found anywhere. Nothing to remediate."
    log "===== END ====="
    exit 0
fi

VULN=0; UNKNOWN=0; SYSTEM_VULN=0
while IFS= read -r spec; do
    base=$(basename "$spec"); ver=$(spec_version "$base")
    if [ "$ver" = "$base" ]; then log "  ?        $spec  (unparseable version)"; continue; fi
    need=$(required_for "$ver")
    if [ -z "$need" ]; then
        log "  REVIEW   $ver  $spec  [no branch in THRESHOLDS covers this version]"
        UNKNOWN=1
    elif version_ge "$ver" "$need"; then
        log "  OK       $ver  $spec  (>= $need)"
    else
        log "  VULN     $ver  $spec  (< $need)"
        VULN=1
        case "$spec" in /Library/Ruby/*) SYSTEM_VULN=1 ;; esac
    fi
done < "$WORK/specs"

if [ "$VULN" -eq 0 ]; then
    log ""
    log "  No vulnerable $GEM spec present."
    [ "$UNKNOWN" -eq 1 ] && { log "  (Some specs need review -- see REVIEW above.)"; log "===== END ====="; exit 2; }
    log "===== END ====="
    exit 0
fi

# -----------------------------------------------------------------------
# 2. Install a patched gem (unless told not to)
# -----------------------------------------------------------------------
log ""
log "[2] Ensuring a patched $GEM is installed..."
if [ "$NO_INSTALL" = "1" ]; then
    log "  NO_INSTALL=1 -- skipping install; cleanup will only remove specs that"
    log "  already have a patched sibling in the same branch."
elif [ -z "$BREW_USER" ] || [ -z "$BREW_PREFIX" ]; then
    log "  Cannot install (no Homebrew and/or no non-root user)."
elif [ "$DRY_RUN" = "1" ]; then
    log "  [DRY_RUN] Would run: gem install $GEM ; gem cleanup $GEM"
else
    GEMBIN="$BREW_PREFIX/opt/ruby/bin/gem"
    [ -x "$GEMBIN" ] || GEMBIN=$(command -v gem 2>/dev/null || true)
    if [ -n "$GEMBIN" ] && [ -x "$GEMBIN" ]; then
        log "  Using $GEMBIN"
        OUT=$(run_as_user "$GEMBIN" install "$GEM" 2>&1); log "  $OUT"
        OUT=$(run_as_user "$GEMBIN" cleanup "$GEM" 2>&1); log "  cleanup: $OUT"
    else
        log "  No usable gem binary found."
    fi
fi

# -----------------------------------------------------------------------
# 3. Cleanup -- gated per branch on a confirmed patched sibling
# -----------------------------------------------------------------------
log ""
log "[3] Removing vulnerable specs (newest patched copy per Ruby tree is kept)..."
: > "$WORK/specs2"
for root in $SEARCH_ROOTS; do
    [ -d "$root" ] || continue
    find "$root" -name "${GEM}-*.gemspec" -type f 2>/dev/null >> "$WORK/specs2" || true
done
sort -u "$WORK/specs2" -o "$WORK/specs2"
[ "$THRESH_PER_BRANCH" -eq 1 ] && log "  (per-branch thresholds: a patched spec must match the branch too)"

REMOVED=0; KEPT=0
while IFS= read -r spec; do
    [ -f "$spec" ] || continue
    base=$(basename "$spec"); ver=$(spec_version "$base")
    [ "$ver" = "$base" ] && continue
    need=$(required_for "$ver")
    [ -z "$need" ] && continue                       # unknown branch: never delete
    version_ge "$ver" "$need" && continue            # already patched

    # --- classify FIRST; these paths have their own remediation ---
    if is_default_gem "$spec"; then
        log "  DEFAULT  $spec ($ver < $need)"
        log "           A Ruby DEFAULT gem. Never deleted -- it ships with the"
        log "           interpreter and removing it breaks Ruby. Fixed only by"
        log "           updating Ruby itself."
        KEPT=$((KEPT+1)); continue
    fi

    sc=$(scope_of "$spec")
    case "$sc" in
        SYSTEM)
            log "  SYSTEM   $spec ($ver < $need) -- macOS system Ruby."
            log "           Not modified: OS-managed tree. Recast/accept, or migrate off"
            log "           the built-in Ruby."
            KEPT=$((KEPT+1)); continue ;;
        PORTABLE:*)
            prver="${sc#PORTABLE:}"
            if [ "$prver" = "$PORTABLE_CURRENT" ]; then
                log "  BREW-CUR $spec ($ver < $need)"
                log "           CURRENT Homebrew portable-ruby ($prver). Removing it breaks"
                log "           brew and the bundled gem is not user-updatable. Report/recast."
                KEPT=$((KEPT+1)); continue
            fi
            if [ "$DRY_RUN" = "1" ]; then
                log "  [DRY_RUN] Would remove superseded portable-ruby tree $PORTABLE_ROOT/$prver"
                continue
            fi
            log "  BREW-OLD Removing superseded portable-ruby tree: $PORTABLE_ROOT/$prver"
            log "           (current is ${PORTABLE_CURRENT:-unknown}; brew keeps only that one)"
            rm -rf "$PORTABLE_ROOT/$prver" && REMOVED=$((REMOVED+1))
            continue ;;
    esac

    # --- normal tree: is a patched copy loadable by THIS Ruby? ---
    myabi=$(abi_of "$spec")
    mybranch=$(echo "$ver" | cut -d. -f1,2)
    patched_here=0
    patched_what=""
    while IFS= read -r other; do
        [ -f "$other" ] || continue
        overs=$(spec_version "$(basename "$other")")
        [ "$overs" = "$(basename "$other")" ] && continue
        [ "$(scope_of "$other")" = "$sc" ] || continue
        oabi=$(abi_of "$other")
        [ -n "$myabi" ] && [ -n "$oabi" ] && [ "$myabi" != "$oabi" ] && continue
        if [ "$THRESH_PER_BRANCH" -eq 1 ]; then
            [ "$(echo "$overs" | cut -d. -f1,2)" = "$mybranch" ] || continue
        fi
        oneed=$(required_for "$overs")
        [ -z "$oneed" ] && continue
        if version_ge "$overs" "$oneed"; then patched_here=1; patched_what="$overs"; fi
    done < "$WORK/specs2"

    if [ "$patched_here" -eq 0 ]; then
        if [ "$THRESH_PER_BRANCH" -eq 1 ]; then
            log "  KEEP     $spec ($ver < $need) -- no patched ${mybranch}.x in this Ruby"
            log "           tree ($sc); refusing to remove the only $GEM on this branch."
        else
            log "  KEEP     $spec ($ver < $need) -- no patched $GEM in this Ruby tree"
            log "           ($sc); refusing to remove the only copy."
        fi
        KEPT=$((KEPT+1)); continue
    fi
    if [ "$DRY_RUN" = "1" ]; then
        log "  [DRY_RUN] Would remove $spec (patched $patched_what present in $sc)"
        continue
    fi
    log "  REMOVE   $spec ($ver < $need; patched $patched_what present in $sc)"
    rm -f "$spec" && REMOVED=$((REMOVED+1))
    specdir=$(dirname "$spec")
    gemdir="$(dirname "$specdir")/gems/${GEM}-${ver}"
    [ -d "$gemdir" ] && rm -rf "$gemdir" && log "           removed payload: $gemdir"
done < "$WORK/specs2"

# -----------------------------------------------------------------------
# 4. Verify
# -----------------------------------------------------------------------
log ""
log "[4] Final state..."
REMAIN=0; REMAIN_SYSTEM=0
for root in $SEARCH_ROOTS; do
    [ -d "$root" ] || continue
    find "$root" -name "${GEM}-*.gemspec" -type f 2>/dev/null | sort | while IFS= read -r spec; do
        base=$(basename "$spec"); ver=$(spec_version "$base")
        need=$(required_for "$ver")
        if [ -n "$need" ] && ! version_ge "$ver" "$need"; then
            log "  STILL VULNERABLE  $ver  $spec"
            echo x >> "$WORK/remain"
            case "$spec" in */specifications/default/*) echo x >> "$WORK/remain_sys" ;; esac
            case "$spec" in /Library/Ruby/*) echo x >> "$WORK/remain_sys" ;; esac
            if [ -n "$PORTABLE_CURRENT" ]; then
                case "$spec" in
                    *"/portable-ruby/$PORTABLE_CURRENT/"*) echo x >> "$WORK/remain_brewcur" ;;
                esac
            fi
        else
            log "  ok                $ver  $spec"
        fi
    done
done
[ -f "$WORK/remain" ] && REMAIN=1
[ -f "$WORK/remain_sys" ] && REMAIN_SYSTEM=1
[ -f "$WORK/remain_brewcur" ] && REMAIN_SYSTEM=1

log ""
log "Removed: $REMOVED   Kept: $KEPT"
if [ "$DRY_RUN" = "1" ]; then
    log "DRY_RUN=1 -- nothing was changed."
    log "===== END (dry run) ====="
    exit 0
fi
if [ "$REMAIN" -eq 1 ]; then
    if [ "$REMAIN_SYSTEM" -eq 1 ] || [ "$UNKNOWN" -eq 1 ]; then
        log "RESULT: vulnerable specs remain, but only where a human must decide"
        log "        (macOS system Ruby, the CURRENT Homebrew portable-ruby, or a branch"
        log "        not covered by THRESHOLDS)."
        log "===== END (needs a decision) ====="
        exit 2
    fi
    log "RESULT: a vulnerable $GEM spec remains that should have been fixable."
    log "        Check whether the gem install succeeded above."
    log "===== END (not remediated) ====="
    exit 1
fi
log "RESULT: no vulnerable $GEM spec remains."
log "Re-run a Nessus scan to confirm plugin ${PLUGIN:-<n>} clears."
log "===== remediate-ruby-gem.sh END ====="
exit 0
