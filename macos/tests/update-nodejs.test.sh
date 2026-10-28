# Tests for update-nodejs.sh: brew-log filtering, release lookup, network
# failure detection, and end-to-end runs against a fake Homebrew prefix
# (upgrade, CSMB-011 network outage, transient retry, build error, hung brew,
# unreachable release index).
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

# CSMB-011 (2026-10-27): brew upgrade node while ghcr.io was failing.
csmb011=$(mktemp)
cat > "$csmb011" <<'LOG'
==> Fetching downloads for: node and mongosh
✘ Bottle icu4c@79 (79.1)
Error: Failed to download resource "icu4c@79"
Download failed: https://ghcr.io/v2/homebrew/core/icu4c/79/blobs/sha256:8499235357ff52424e3fcc647a6ce57050af9f10904554df90319e6a088f665d
curl: (56) Recv failure: Connection reset by peer
✘ Bottle node (26.12.1_1)
Error: Failed to download resource "node"
Download failed: https://ghcr.io/v2/homebrew/core/node/blobs/sha256:dc7c3d36f969a6d003096966c2192ab6b893c25898c73d4087be18d67df094b6
curl: (28) SSL connection timeout
Download failed: https://ghcr.io/v2/homebrew/core/icu4c/79/manifests/79.1
curl: (6) Could not resolve host: ghcr.io
LOG
yn() { if "$@"; then echo y; else echo n; fi; }
check 'CSMB-011: ghcr.io failures are network failures' "$(yn is_network_failure "$csmb011")" 'y'
check 'CSMB-011: host named once' "$(network_hosts "$csmb011")" 'ghcr.io'
gitfail=$(mktemp)
printf '%s\n' 'error: RPC failed; curl 92 HTTP/2 stream 5 was not closed cleanly: CANCEL (err 8)' \
  'fetch-pack: unexpected disconnect while reading sideband packet' 'fatal: early EOF' > "$gitfail"
check 'CSMB-011: brew update git disconnect is a network failure' "$(yn is_network_failure "$gitfail")" 'y'
check 'git disconnect names no host' "$(network_hosts "$gitfail")" ''
printf '%s\n' 'curl: (7) Failed to connect to nodejs.org port 443 after 3 ms' 'Could not resolve host: github.com' > "$gitfail"
check 'two hosts in first-seen order' "$(network_hosts "$gitfail")" 'nodejs.org github.com'
printf '%s\n' 'Error: node: An unsatisfied requirement failed this build.' > "$gitfail"
check 'build error is not a network failure' "$(yn is_network_failure "$gitfail")" 'n'
check 'curl 28 is network' "$(yn curl_rc_is_network 28)" 'y'
check 'curl 22 (HTTP error) is not' "$(yn curl_rc_is_network 22)" 'n'
check 'host of url' "$(host_of_url https://nodejs.org/dist/index.json)" 'nodejs.org'
check 'host of url with port' "$(host_of_url http://127.0.0.1:9/index.json)" '127.0.0.1'
rm -f "$csmb011" "$gitfail"

# ----------------------------------------------------------- end to end ----
# Fake Homebrew prefix + sudo/stat shims; brew's behaviour per run comes
# from $S/upgrade (ok | net | net_once | hang | error) and $S/update.
e2e=$(mktemp -d)
trap 'rm -f "$fix"; rm -rf "$e2e"' EXIT
make_fixture() {
  rm -rf "$e2e/run"
  mkdir -p "$e2e/run/shims" "$e2e/run/state" "$e2e/run/logs" "$e2e/run/brew/bin" "$e2e/run/brew/Cellar/node/26.12.0"
  S="$e2e/run/state"; B="$e2e/run/brew"
  : > "$S/calls"; echo ok > "$S/upgrade"; echo ok > "$S/update"
  cat > "$B/bin/brew" <<EOF
#!/bin/bash
echo "brew \$*" >> "$S/calls"
case "\$1" in
  update)
    if [ "\$(cat "$S/update")" = net ]; then
      echo 'error: RPC failed; curl 92 HTTP/2 stream 5 was not closed cleanly: CANCEL (err 8)'
      echo 'fatal: early EOF'; echo 'Error: Fetching /opt/homebrew failed!'; exit 1
    fi
    echo 'Already up-to-date.' ;;
  upgrade)
    mode=\$(cat "$S/upgrade")
    if [ "\$mode" = net_once ]; then echo ok > "$S/upgrade"; mode=net; fi
    case "\$mode" in
      net) echo 'Error: Failed to download resource "node"'
           echo 'Download failed: https://ghcr.io/v2/homebrew/core/node/blobs/sha256:dc7c'
           echo 'curl: (6) Could not resolve host: ghcr.io'; exit 1 ;;
      hang) echo '==> Fetching downloads for: node'; exec sleep 300 ;;
      error) echo 'Error: node: An unsatisfied requirement failed this build.'; exit 1 ;;
    esac
    mkdir -p "$B/Cellar/node/26.12.1_1"; echo '==> Upgrading node 26.12.0 -> 26.12.1_1' ;;
  cleanup) rm -rf "$B/Cellar/node/26.12.0"; echo 'Removing: node 26.12.0' ;;
esac
exit 0
EOF
  printf '#!/bin/bash\n[ "$1" = -u ] && shift 2\nexec env "$@"\n' > "$e2e/run/shims/sudo"
  cat > "$e2e/run/shims/stat" <<'EOF'
#!/bin/bash
[ "$*" = "-f %Su /dev/console" ] && { echo tester; exit 0; }
exec /usr/bin/stat "$@"
EOF
  chmod +x "$B/bin/brew" "$e2e/run/shims/"*
}
run_node() {
  rc=0
  PATH="$e2e/run/shims:$PATH" BREW_PREFIXES="$B" STANDALONE="$e2e/run/none" LOG_DIR="$e2e/run/logs" \
    RETRY_DELAY=1 NODE_SELFTEST=0 "$@" bash "$script" >/dev/null 2>&1 || rc=$?
}
L="$e2e/run/logs/nodejs_update.log"
has() { if grep -qE -- "$1" "$2"; then echo y; else echo n; fi; }

make_fixture
run_node env
check 'upgrade ok -> 0' "$rc" '0'
check 'upgrade ok: new keg, old cleaned' "$(ls "$B/Cellar/node" | tr '\n' ' ')" '26.12.1_1 '
check 'upgrade ok: step log written' "$(has 'Upgrading node' "$e2e/run/logs/nodejs_update_brew_upgrade_node.log")" 'y'
check 'upgrade ok: brew output in main log' "$(has '  ==> Upgrading node 26.12.0 -> 26.12.1_1' "$L")" 'y'

# CSMB-011: brew update and every upgrade attempt fail on the network.
make_fixture; echo net > "$S/update"; echo net > "$S/upgrade"
run_node env
check 'CSMB-011: network failure -> 1' "$rc" '1'
check 'CSMB-011: upgrade retried once' "$(grep -c '^brew upgrade node$' "$S/calls")" '2'
check 'CSMB-011: retry logged' "$(has 'Network error -- retrying once in 1s' "$L")" 'y'
check 'CSMB-011: retry has its own log' "$(has 'Could not resolve host' "$e2e/run/logs/nodejs_update_brew_upgrade_node_retry.log")" 'y'
check 'CSMB-011: RESULT names the network and ghcr.io' "$(has 'RESULT: network failure -- could not reach ghcr.io ' "$L")" 'y'
check 'CSMB-011: cleanup skipped after failed upgrade' "$(grep -c '^brew cleanup' "$S/calls")" '0'
check 'CSMB-011: update failure is a warning only' "$(has 'brew update did not finish cleanly' "$L")" 'y'

make_fixture; echo net_once > "$S/upgrade"
run_node env
check 'transient network error, retry works -> 0' "$rc" '0'
check 'transient: no network RESULT' "$(has 'RESULT: network failure' "$L")" 'n'

make_fixture; echo error > "$S/upgrade"
run_node env
check 'build error -> 1' "$rc" '1'
check 'build error: not retried' "$(grep -c '^brew upgrade node$' "$S/calls")" '1'
check 'build error: generic RESULT' "$(has 'RESULT: a Node.js update did not complete' "$L")" 'y'

make_fixture; echo hang > "$S/upgrade"
run_node env BREW_TIMEOUT=4
check 'hung brew -> 1' "$rc" '1'
check 'hung brew: time limit logged' "$(has 'brew upgrade node hit its 4s limit' "$L")" 'y'
check 'hung brew: not retried' "$(grep -c '^brew upgrade node$' "$S/calls")" '1'
check 'hung brew: sleep killed' "$(pgrep -f 'sleep 300' >/dev/null && echo running || echo gone)" 'gone'

# Official pkg whose release index cannot be reached.
make_fixture; rm -rf "$B/Cellar/node"
printf '#!/bin/bash\necho v24.21.0\n' > "$e2e/run/node"; chmod +x "$e2e/run/node"
rc=0
PATH="$e2e/run/shims:$PATH" BREW_PREFIXES="$B" STANDALONE="$e2e/run/node" LOG_DIR="$e2e/run/logs" \
  NODE_DIST_INDEX="http://127.0.0.1:9/index.json" NODE_SELFTEST=0 bash "$script" >/dev/null 2>&1 || rc=$?
check 'index unreachable -> 1' "$rc" '1'
check 'index unreachable: RESULT names the host' "$(has 'RESULT: network failure -- could not reach 127.0.0.1 ' "$L")" 'y'

if [ "$fail" -ne 0 ]; then
  echo "tests failed"
  exit 1
fi
echo "All tests passed"
exit 0
