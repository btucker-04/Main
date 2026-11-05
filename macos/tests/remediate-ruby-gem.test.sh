# Unit tests for remediate-ruby-gem.sh branch floors (plugin 321503).
# Run: RUBY_GEM_SELFTEST=1 bash macos/tests/remediate-ruby-gem.test.sh
#
# ARMB-09 (2026-09-28) ran the stock script and logged GEM=rexml. Plugin
# 321503 is net-imap 0.6.4, fixed at 0.6.4.1. The older 0.6.4 floor would
# treat that spec as already patched.
# Globals assigned here are read by the sourced script's functions.
# shellcheck disable=SC2034
set -eu
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
check_rc() {
  name=$1; want=$2; shift 2
  if "$@"; then got=0; else got=1; fi
  if [ "$got" != "$want" ]; then
    echo "FAIL $name: rc $got want $want"
    fail=1
  else
    echo "OK   $name"
  fi
}

export RUBY_GEM_SELFTEST=1
LOG_DIR=$(mktemp -d); export LOG_DIR
# shellcheck source=/dev/null
. "$script"

# ARMB-02 (2026-11-05): plugin 210049 was rexml, the stock paste ran net-imap only.
check 'default run covers rexml, net-imap per branch, webrick' "$GEMS" 'rexml net-imap=branch webrick'
GEM=net-imap
apply_thresholds '0.4:0.4.24;0.5:0.5.15;0.6:0.6.4.1'
check '0.6.4 floor is 0.6.4.1' "$(required_for 0.6.4)" '0.6.4.1'
check '0.6.4.1 floor is 0.6.4.1' "$(required_for 0.6.4.1)" '0.6.4.1'
check '0.5.14 floor is 0.5.15' "$(required_for 0.5.14)" '0.5.15'
check '0.4.20 floor is 0.4.24' "$(required_for 0.4.20)" '0.4.24'
check 'unknown 0.7 is not covered' "$(required_for 0.7.1)" ''

check_rc '0.6.4 is below 0.6.4.1' 1 version_ge 0.6.4 0.6.4.1
check_rc '0.6.4.1 meets 0.6.4.1' 0 version_ge 0.6.4.1 0.6.4.1
check_rc '0.6.5 meets 0.6.4.1' 0 version_ge 0.6.5 0.6.4.1
check_rc '0.5.14 is below 0.5.15' 1 version_ge 0.5.14 0.5.15
# The old floor would have called 0.6.4 done. That is the bug.
check_rc '0.6.4 meets the old 0.6.4 floor' 0 version_ge 0.6.4 0.6.4

# --- ARMB-09: orphaned gem dir for a Ruby ABI that no longer exists ---------
# Homebrew ruby was upgraded 3.3 -> 4.0. lib/ruby/gems/3.3.0 stayed behind
# with net-imap-0.6.4; gem install wrote 0.6.7 into lib/ruby/gems/4.0.0.
fix=$(mktemp -d)
trap 'rm -rf "$fix"' EXIT
BREW_PREFIX="$fix/opt/homebrew"
mkdir -p "$BREW_PREFIX/Cellar/ruby/4.0.5/lib/ruby/4.0.0"
mkdir -p "$BREW_PREFIX/opt/ruby/lib/ruby/4.0.0"
mkdir -p "$BREW_PREFIX/lib/ruby/gems/3.3.0/specifications"
mkdir -p "$BREW_PREFIX/lib/ruby/gems/4.0.0/specifications"

check_rc 'ABI 4.0.0 has a Cellar ruby keg' 0 homebrew_abi_has_interpreter 4.0.0
check_rc 'ABI 3.3.0 has no keg -> orphan' 1 homebrew_abi_has_interpreter 3.3.0
check_rc 'empty ABI is never an interpreter' 1 homebrew_abi_has_interpreter ''
check 'current ABI reported from opt/ruby' "$(homebrew_current_abi)" '4.0.0'

# A versioned keg (ruby@3.3) keeps the 3.3.0 gem dir alive: must NOT be orphan.
mkdir -p "$BREW_PREFIX/Cellar/ruby@3.3/3.3.6/lib/ruby/3.3.0"
check_rc 'ruby@3.3 keg makes ABI 3.3.0 live again' 0 homebrew_abi_has_interpreter 3.3.0

check 'abi_of ARMB-09 spec path' \
  "$(abi_of /opt/homebrew/lib/ruby/gems/3.3.0/specifications/net-imap-0.6.4.gemspec)" '3.3.0'

# --- ARMB-02: bundled 0.4.9.1 in the Cellar keg, 0.6.7 in the shared dir ---
# Per-branch thresholds need a patched 0.4.x beside 0.4.9.1 before it may go.
# gem install alone only fetches 0.6.7, so step 2a installs '>= 0.4.24, < 0.5'.
check 'branch requirement 0.4' "$(branch_requirement 0.4.9.1)" '>= 0.4.24, < 0.5'
check 'branch requirement 0.5' "$(branch_requirement 0.5.10)" '>= 0.5.15, < 0.6'
check 'branch requirement 0.6' "$(branch_requirement 0.6.4)" '>= 0.6.4.1, < 0.7'
check 'branch requirement uncovered' "$(branch_requirement 0.7.1)" ''

b2="$fix/armb02/opt/homebrew"
BREW_PREFIX="$b2"
PORTABLE_ROOT=""
cellar_spec="$b2/Cellar/ruby/3.3.5/lib/ruby/gems/3.3.0/specifications/net-imap-0.4.9.1.gemspec"
shared="$b2/lib/ruby/gems/3.3.0/specifications"
mkdir -p "$(dirname "$cellar_spec")" "$shared"
: > "$cellar_spec"
: > "$shared/net-imap-0.6.7.gemspec"
SEARCH_ROOTS="$b2/lib/ruby/gems $b2/Cellar"
list="$fix/armb02.list"
collect_specs "$list"
check 'collect_specs finds both specs' "$(wc -l < "$list" | tr -d ' ')" '2'
check 'Cellar and shared dir are one tree' "$(scope_of "$cellar_spec")" "$(scope_of "$shared/net-imap-0.6.7.gemspec")"
check '0.6.7 does not cover the 0.4 branch' "$(patched_sibling_of "$cellar_spec" "$list")" ''

: > "$shared/net-imap-0.4.24.gemspec"
collect_specs "$list"
check 'patched 0.4.24 now covers 0.4.9.1' "$(patched_sibling_of "$cellar_spec" "$list")" '0.4.24'

mkdir -p "$b2/lib/ruby/gems/4.0.0/specifications"
other_abi="$fix/armb02.other"
printf '%s\n' "$cellar_spec" "$b2/lib/ruby/gems/4.0.0/specifications/net-imap-0.4.24.gemspec" > "$other_abi"
: > "$b2/lib/ruby/gems/4.0.0/specifications/net-imap-0.4.24.gemspec"
check 'a different ABI never counts' "$(patched_sibling_of "$cellar_spec" "$other_abi")" ''

# --- Release lookup (latest / branch) ----------------------------------------
# Trimmed from a real rubygems.org /api/v1/versions/net-imap.json response:
# a nested metadata object, a prerelease, and out-of-order numbers.
cat > "$fix/netimap.json" <<'EOF'
[{"authors":"Shugo Maeda","metadata":{"homepage_uri":"https://github.com/ruby/net-imap"},"number":"0.6.8","summary":"Ruby client api","platform":"ruby","rubygems_version":">= 0","ruby_version":">= 3.2.0","prerelease":false,"licenses":["Ruby"]},{"authors":"x","metadata":{},"number":"0.7.0.beta1","summary":"s","platform":"ruby","ruby_version":">= 3.2.0","prerelease":true},{"authors":"x","metadata":{},"number":"0.4.25","summary":"s","platform":"ruby","ruby_version":">= 2.7.3","prerelease":false},{"authors":"x","metadata":{},"number":"0.4.9.1","summary":"s","platform":"ruby","prerelease":false},{"authors":"x","metadata":{},"number":"0.6.10","summary":"s","platform":"ruby","prerelease":false},{"authors":"x","metadata":{},"number":"0.5.15","summary":"s","platform":"ruby","prerelease":false}]
EOF
release_versions < "$fix/netimap.json" > "$fix/netimap.rel"
check 'prereleases are skipped' "$(grep -c beta "$fix/netimap.rel" || true)" '0'
check 'all releases parsed' "$(wc -l < "$fix/netimap.rel" | tr -d ' ')" '5'
check 'latest sorts by version, not text' "$(thresholds_for_spec latest "$fix/netimap.rel")" '0.6.10'
check 'branch floors are the newest per major.minor' \
  "$(thresholds_for_spec branch "$fix/netimap.rel")" '0.4:0.4.25;0.5:0.5.15;0.6:0.6.10'
check 'explicit thresholds pass through' "$(thresholds_for_spec '3.4.2' "$fix/netimap.rel")" '3.4.2'
check 'empty release list resolves to nothing' "$(thresholds_for_spec latest /dev/null)" ''

# --- ARMB-02 plugin 210049: macOS system Ruby rexml ------------------------
GEM=rexml
apply_thresholds '3.4.4' 1
SYS_RUBY_ROOT=/Library/Ruby
printf '%s\n' /Library/Ruby/Gems/2.6.0/specifications/rexml-3.2.5.gemspec > "$fix/sys.list"
check 'outdated non-default system rexml gets a plain install' \
  "$(system_install_requirements "$fix/sys.list" 2.6.0)" 'any'
check 'a gem dir /usr/bin/ruby does not load is left alone' \
  "$(system_install_requirements "$fix/sys.list" 2.7.0)" ''
printf '%s\n' /Library/Ruby/Gems/2.6.0/specifications/default/rexml-3.1.9.gemspec > "$fix/sysdef.list"
check 'a system default gem is never an install target' \
  "$(system_install_requirements "$fix/sysdef.list" 2.6.0)" ''
check 'default gem is not updatable here' \
  "$(unfixable_reason /Library/Ruby/Gems/2.6.0/specifications/default/rexml-3.1.9.gemspec)" 'Ruby default gem'
check 'non-default system gem IS updatable' \
  "$(unfixable_reason /Library/Ruby/Gems/2.6.0/specifications/rexml-3.2.5.gemspec)" ''
GEM=net-imap
apply_thresholds '0.4:0.4.25;0.5:0.5.15;0.6:0.6.8' 1
printf '%s\n' /Library/Ruby/Gems/2.6.0/specifications/net-imap-0.4.9.1.gemspec > "$fix/sysbr.list"
check 'branch mode installs on the vulnerable branch' \
  "$(system_install_requirements "$fix/sysbr.list" 2.6.0)" '>= 0.4.25, < 0.5'

if [ "$fail" -ne 0 ]; then
  echo "tests failed"
  exit 1
fi
echo "All tests passed"
exit 0
