# Unit tests for remediate-ruby-gem.sh branch floors (plugin 321503).
# Run: RUBY_GEM_SELFTEST=1 bash macos/tests/remediate-ruby-gem.test.sh
#
# ARMB-09 (2026-09-28) ran the stock script and logged GEM=rexml. Plugin
# 321503 is net-imap 0.6.4, fixed at 0.6.4.1. The older 0.6.4 floor would
# treat that spec as already patched.
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
# shellcheck source=/dev/null
. "$script"

check 'default gem' "$GEM" 'net-imap'
check 'default plugin' "$PLUGIN" '321503'
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

if [ "$fail" -ne 0 ]; then
  echo "tests failed"
  exit 1
fi
echo "All tests passed"
exit 0
