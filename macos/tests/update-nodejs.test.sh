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

if [ "$fail" -ne 0 ]; then
  echo "tests failed"
  exit 1
fi
echo "All tests passed"
exit 0
