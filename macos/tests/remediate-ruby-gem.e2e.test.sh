# End-to-end runs of remediate-ruby-gem.sh against a staged macOS system Ruby.
# Run: bash macos/tests/remediate-ruby-gem.e2e.test.sh
#
# ARMB-02 (2026-11-05), plugin 210049:
#   /Library/Ruby/Gems/2.6.0/specifications/rexml-3.2.5.gemspec
# The stock paste ran net-imap only, and a rexml run would only have reported
# the system copy. Stubs: curl (rubygems.org), /usr/bin/gem, /usr/bin/ruby.
set -u
here=$(cd "$(dirname "$0")" && pwd)
script=$(cd "$here/.." && pwd)/remediate-ruby-gem.sh

fail=0
check() {
  name=$1; got=$2; want=$3
  if [ "$got" != "$want" ]; then
    echo "FAIL $name: got '$got' want '$want'"
    fail=1
  else
    echo "OK   $name"
  fi
}
has() { grep -qF -- "$2" "$1" && echo yes || echo no; }

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT

# t = one scenario's sandbox. Stubs read FAKE_* from the environment.
stage() {
  t="$root/$1"
  sys="$t/Library/Ruby/Gems/2.6.0"
  mkdir -p "$sys/specifications/default" "$sys/gems" "$t/bin" "$t/json" "$t/log"
  cat > "$t/bin/curl" <<'EOF'
#!/bin/bash
[ "${FAKE_OFFLINE:-0}" = 1 ] && exit 6
for a in "$@"; do url=$a; done
g=$(basename "$url" .json)
[ -f "$FAKE_JSON/$g.json" ] || exit 22
cat "$FAKE_JSON/$g.json"
EOF
  cat > "$t/bin/gem" <<'EOF'
#!/bin/bash
echo "gem $*" >> "$FAKE_CALLS"
[ "$1" = install ] || exit 0
if [ "${FAKE_GEM_FAIL:-0}" = 1 ]; then
  echo "ERROR:  Could not find a valid gem '$2' (>= 0) in any repository"; exit 2
fi
v=$(cat "$FAKE_JSON/$2.latest")
: > "$FAKE_SYS/specifications/$2-$v.gemspec"
mkdir -p "$FAKE_SYS/gems/$2-$v"
echo "Successfully installed $2-$v"
EOF
  printf '#!/bin/bash\nprintf 2.6.0\n' > "$t/bin/ruby"
  chmod +x "$t/bin/curl" "$t/bin/gem" "$t/bin/ruby"
  printf '[{"authors":"x","metadata":{},"number":"3.4.4","summary":"s","platform":"ruby","ruby_version":">= 2.5.0","prerelease":false},{"authors":"x","metadata":{},"number":"3.3.9","summary":"s","platform":"ruby","prerelease":false}]' > "$t/json/rexml.json"
  echo 3.4.4 > "$t/json/rexml.latest"
}
run() {
  # remaining args: positional args for the script
  PATH="$t/bin:$PATH" FAKE_JSON="$t/json" FAKE_SYS="$sys" FAKE_CALLS="$t/gem.calls" \
    SYS_RUBY_ROOT="$t/Library/Ruby" SYS_GEM_BIN="$t/bin/gem" SYS_RUBY_BIN="$t/bin/ruby" \
    LOG_DIR="$t/log" bash "$script" "$@" > "$t/out" 2>&1
  echo $?
}

# 1. ARMB-02 as reported: latest rexml installed into system Ruby, 3.2.5 removed.
stage armb02
: > "$sys/specifications/rexml-3.2.5.gemspec"; mkdir -p "$sys/gems/rexml-3.2.5"
rc=$(GEMS=rexml run)
check 'ARMB-02 rexml: exit 0' "$rc" 0
check 'ARMB-02: resolved latest from rubygems.org' "$(has "$t/out" 'THRESHOLDS=3.4.4')" yes
check 'ARMB-02: installed with the system gem' "$(has "$t/gem.calls" 'gem install rexml --no-document')" yes
check 'ARMB-02: 3.2.5 spec removed' "$([ -f "$sys/specifications/rexml-3.2.5.gemspec" ] && echo present || echo gone)" gone
check 'ARMB-02: 3.2.5 payload removed' "$([ -d "$sys/gems/rexml-3.2.5" ] && echo present || echo gone)" gone
check 'ARMB-02: 3.4.4 kept' "$([ -f "$sys/specifications/rexml-3.4.4.gemspec" ] && echo present || echo gone)" present
check 'ARMB-02: overall line' "$(has "$t/out" 'OVERALL: exit 0  (per gem: rexml=0;')" yes

# 2. Install fails: never remove the only copy; needs a decision.
stage installfail
: > "$sys/specifications/rexml-3.2.5.gemspec"
rc=$(GEMS=rexml FAKE_GEM_FAIL=1 run)
check 'failed system install: exit 2' "$rc" 2
check 'failed system install: 3.2.5 kept' "$([ -f "$sys/specifications/rexml-3.2.5.gemspec" ] && echo present || echo gone)" present
check 'failed system install: gem error is in the log' "$(has "$t/out" 'Could not find a valid gem')" yes

# 3. rubygems.org unreachable: say so, change nothing.
stage offline
: > "$sys/specifications/rexml-3.2.5.gemspec"
rc=$(GEMS=rexml FAKE_OFFLINE=1 run)
check 'offline: exit 1' "$rc" 1
check 'offline: names the cause' "$(has "$t/out" 'could not read rexml releases from rubygems.org')" yes
check 'offline: nothing installed' "$([ -f "$t/gem.calls" ] && echo called || echo none)" none

# 4. SYSTEM_RUBY=0: report only.
stage nosys
: > "$sys/specifications/rexml-3.2.5.gemspec"
rc=$(GEMS=rexml SYSTEM_RUBY=0 run)
check 'SYSTEM_RUBY=0: exit 2' "$rc" 2
check 'SYSTEM_RUBY=0: no install' "$([ -f "$t/gem.calls" ] && echo called || echo none)" none

# 5. Only an outdated DEFAULT gem: latest mode reports it, a fixed floor flags it.
stage defaultonly
: > "$sys/specifications/default/rexml-3.1.9.gemspec"
rc=$(GEMS=rexml run)
check 'default gem, latest: exit 0' "$rc" 0
check 'default gem, latest: listed OUTDATED' "$(has "$t/out" 'OUTDATED          3.1.9')" yes
check 'default gem never deleted' "$([ -f "$sys/specifications/default/rexml-3.1.9.gemspec" ] && echo present || echo gone)" present
rc=$(run rexml 3.4.2 265895)
check 'default gem, fixed floor (positional): exit 2' "$rc" 2
check 'positional args still set THRESHOLDS' "$(has "$t/out" 'THRESHOLDS=3.4.2   PLUGIN=265895')" yes

# 6. Several gems: worst result wins (webrick has no release data -> 1).
stage multi
: > "$sys/specifications/rexml-3.2.5.gemspec"
rc=$(GEMS="rexml webrick" run)
check 'multi: overall exit 1' "$rc" 1
check 'multi: rexml still fixed' "$([ -f "$sys/specifications/rexml-3.2.5.gemspec" ] && echo present || echo gone)" gone
check 'multi: per-gem summary' "$(has "$t/out" 'per gem: rexml=0 webrick=1;')" yes

# 7. ARMB-02 webrick (2026-11-05): the only outdated copy is a system default
#    gem. Nothing may be installed anywhere -- no install can replace it.
stage webrickdefault
: > "$sys/specifications/default/webrick-1.9.1.gemspec"
printf '[{"authors":"x","metadata":{},"number":"1.9.2","summary":"s","platform":"ruby","prerelease":false}]' > "$t/json/webrick.json"
rc=$(GEMS=webrick run)
check 'webrick default only: exit 0' "$rc" 0
check 'webrick default only: Homebrew install skipped' "$(has "$t/out" 'No outdated copy in the Homebrew Ruby tree')" yes
check 'webrick default only: no gem install at all' "$([ -f "$t/gem.calls" ] && echo called || echo none)" none
check 'webrick default only: listed OUTDATED' "$(has "$t/out" 'OUTDATED          1.9.1')" yes

if [ "$fail" -ne 0 ]; then
  echo "tests failed"
  exit 1
fi
echo "All tests passed"
exit 0
