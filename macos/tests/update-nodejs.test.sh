# Unit tests for update-nodejs.sh brew-log filtering.
# Run: NODE_SELFTEST=1 bash macos/tests/update-nodejs.test.sh
#
# CSMB-036 (2026-09-28): Node was already current, then `brew update` logged
# the portable-ruby progress bar and every new formula and cask.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
script=$(cd "$here/.." && pwd)/update-nodejs.sh

fail=0
check() {
  name=$1; got=$2; want=$3
  if [ "$got" != "$want" ]; then
    printf 'FAIL %s\n got:  %s\n want: %s\n' "$name" "$got" "$want"
    fail=1
  else
    echo "OK   $name"
  fi
}

export NODE_SELFTEST=1
# shellcheck source=/dev/null
. "$script"

sample='==> Updating Homebrew...
==> Downloading https://ghcr.io/v2/homebrew/core/portable-ruby/blobs/sha256:e0088dff
#=#=#
##O#-#
#                                                                          1.9%
####################################                                      50.7%
######################################################################## 100.0%
==> Pouring portable-ruby-4.0.7.arm64_big_sur.bottle.tar.gz
Updated 2 taps (homebrew/core and homebrew/cask).
==> New Formulae
agent-manager: Terminal UI to manage AI coding-agent tmux sessions
go@1.26: Open source programming language
==> New Casks
activitywatch@experimental: Time tracker
amp-app: Coding agent
==> Outdated Formulae
node'

got=$(printf '%s\n' "$sample" | tr '\r' '\n' | filter_brew_output)
want='==> Updating Homebrew...
==> Downloading https://ghcr.io/v2/homebrew/core/portable-ruby/blobs/sha256:e0088dff
==> Pouring portable-ruby-4.0.7.arm64_big_sur.bottle.tar.gz
Updated 2 taps (homebrew/core and homebrew/cask).
(omitted brew catalog: new and deleted formulae/casks)
==> Outdated Formulae
node'
check 'catalog and progress bar are omitted, outdated formulae stay' "$got" "$want"

# Carriage-return progress frames collapse to the same filter.
cr=$(printf '==> Updating Homebrew...\r#=#=#\r############### 21.0%%\rUpdated 1 tap.\n')
got=$(printf '%s' "$cr" | tr '\r' '\n' | filter_brew_output)
want='==> Updating Homebrew...
Updated 1 tap.'
check 'carriage-return progress frames are dropped' "$got" "$want"

# CSMB-036 was on 26.5.0. The pinned floor was 26.3.1, so the script called
# it done. The current 26 line in this index is 26.5.1, and the rc is ignored.
fix=$(mktemp)
trap 'rm -f "$fix"' EXIT
cat > "$fix" <<'JSON'
[
  {"version":"v26.6.0-rc.1"},
  {"version":"v26.5.0"},
  {"version":"v26.3.1"},
  {"version":"v26.5.1"},
  {"version":"v24.17.0"},
  {"version":"v22.23.0"}
]
JSON
check '26 line latest is 26.5.1, not the old floor or the rc' "$(latest_node_release 26 "$fix")" '26.5.1'
check '24 line latest is 24.17.0' "$(latest_node_release 24 "$fix")" '24.17.0'
check '22 line latest is 22.23.0' "$(latest_node_release 22 "$fix")" '22.23.0'

if [ "$fail" -ne 0 ]; then
  echo "tests failed"
  exit 1
fi
echo "All tests passed"
exit 0
