# Tests for update-homebrew.sh.
# Run: bash macos/tests/update-homebrew.test.sh
#
# Unit checks for the helpers, then two end-to-end runs against a fake brew
# (shims stand in for sudo / stat / dscl / visudo / sw_vers):
#   1. a .pkg cask (zoom) fails without sudo, a pinned formula stays outdated,
#      upgrade runs BEFORE cleanup and the superseded keg is removed -> exit 2
#   2. CASK_SUDO=1 lets zoom upgrade, and the sudoers grant is gone -> exit 0
set -u
here=$(cd "$(dirname "$0")" && pwd)
script=$(cd "$here/.." && pwd)/update-homebrew.sh

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
check_grep() {
  name=$1; pattern=$2; file=$3
  if grep -qE -- "$pattern" "$file"; then echo "OK   $name"; else echo "FAIL $name (no /$pattern/ in $file)"; fail=1; fi
}
check_nogrep() {
  name=$1; pattern=$2; file=$3
  if grep -qE -- "$pattern" "$file"; then echo "FAIL $name (/$pattern/ found in $file)"; fail=1; else echo "OK   $name"; fi
}

# ---------------------------------------------------------------- unit ----
(
  export HOMEBREW_UPDATE_SELFTEST=1
  # shellcheck source=/dev/null
  . "$script"
  ufail=0
  u() { if [ "$2" != "$3" ]; then printf 'FAIL %s\n got:  %s\n want: %s\n' "$1" "$2" "$3"; ufail=1; else echo "OK   $1"; fi; }

  u 'list_minus drops skipped names' "$(list_minus 'git node zoom' 'zoom' | tr '\n' ' ')" 'git node '
  u 'list_minus with empty skip list' "$(list_minus 'git node' '' | tr '\n' ' ')" 'git node '
  u 'list_minus matches whole words only' "$(list_minus 'node node@22' 'node' | tr '\n' ' ')" 'node@22 '
  u 'list_and keeps pinned outdated' "$(list_and 'git postgresql@14 ruby' "postgresql@14
openssl@3" | tr '\n' ' ')" 'postgresql@14 '
  u 'valid user' "$(valid_macos_user tcindric && echo y || echo n)" 'y'
  u 'root is not a brew user' "$(valid_macos_user root && echo y || echo n)" 'n'
  u 'login window is not a brew user' "$(valid_macos_user loginwindow && echo y || echo n)" 'n'
  u 'sudoers line' "$(sudoers_line tcindric)" 'tcindric ALL=(ALL) NOPASSWD: ALL'

  t=$(mktemp)
  echo 'sudo: a terminal is required to read the password; either use the -S option' > "$t"
  u 'pkg cask needs sudo' "$(cask_failure_reason "$t")" 'needs sudo (.pkg installer) -- set CASK_SUDO=1'
  echo 'Error: It seems there is already an App at /Applications/Slack.app' > "$t"
  u 'existing app mismatch' "$(cask_failure_reason "$t")" "app on disk does not match brew's record -- reinstall the cask by hand"
  echo 'Error: Download failed on Cask zoom with message: curl: (22)' > "$t"
  u 'download failure' "$(cask_failure_reason "$t")" 'download failed -- usually transient, next week'"'"'s run retries'
  rm -f "$t"

  u 'gem mode branch' "$(gem_mode net-imap:branch)" 'branch'
  u 'gem mode default latest' "$(gem_mode rexml)" 'latest'
  u 'gem list parse with default' "$(gem_list_versions 'net-imap (0.6.7, default: 0.4.9.1)' | tr '\n' ' ')" '0.6.7 0.4.9.1 '
  u 'gem list parse drops prerelease' "$(gem_list_versions 'net-imap (0.6.0.pre1, 0.5.15)' | tr '\n' ' ')" '0.5.15 '
  u 'gem list parse of nothing' "$(gem_list_versions '')" ''
  u 'spec version' "$(gem_spec_version net-imap /x/specifications/net-imap-0.4.9.1.gemspec)" '0.4.9.1'
  u 'spec version ignores other gems' "$(gem_spec_version net-imap /x/specifications/net-imap-ext-1.0.gemspec)" ''
  u 'branch requirements' "$(gem_install_requirements branch '0.6.7 0.4.9.1 0.4.20' | tr '\n' '|')" '~> 0.4.0|~> 0.6.0|'
  u 'latest requirement is plain install' "$(gem_install_requirements latest '3.3.9')" ''
  u 'keep newest on branch' "$(gem_keep_version branch '0.4.9.1 0.4.24 0.6.9' 0.4.9.1)" '0.4.24'
  u 'keep newest overall' "$(gem_keep_version latest '3.3.9 3.4.4' 3.3.9)" '3.4.4'
  u 'filter drops catalog and bars' "$(printf '%s\n' '==> Updating Homebrew...' '######## 100.0%' '==> New Formulae' 'foo: bar' '==> Outdated Formulae' 'git' | filter_brew_output | tr '\n' '|')" \
    '==> Updating Homebrew...|(omitted brew catalog: new, renamed and deleted formulae/casks)|==> Outdated Formulae|git|'
  u 'gem mode branch' "$(gem_mode net-imap:branch)" 'branch'
  u 'gem mode default latest' "$(gem_mode rexml)" 'latest'
  u 'gem list parse incl. default' "$(gem_list_versions 'net-imap (0.6.7, 0.4.24, default: 0.4.9.1)' | tr '\n' ' ')" '0.6.7 0.4.24 0.4.9.1 '
  u 'gem list parse drops prerelease' "$(gem_list_versions 'rexml (3.5.0.pre, 3.4.4)' | tr '\n' ' ')" '3.4.4 '
  u 'gem list parse empty' "$(gem_list_versions '')" ''
  u 'spec version' "$(gem_spec_version net-imap /x/specifications/net-imap-0.4.9.1.gemspec)" '0.4.9.1'
  u 'spec version ignores other gems' "$(gem_spec_version net-imap /x/specifications/net-imap-ext-1.0.gemspec)" ''
  u 'branch install reqs' "$(gem_install_requirements branch '0.6.7
0.4.9.1
0.4.20' | tr '\n' '|')" '~> 0.4.0|~> 0.6.0|'
  u 'latest install req is plain' "$(gem_install_requirements latest '3.3.9' | tr '\n' '|')" '|'
  u 'branch keep stays on branch' "$(gem_keep_version branch '0.6.9 0.4.24 0.4.9.1' 0.4.9.1)" '0.4.24'
  u 'branch keep 0.6' "$(gem_keep_version branch '0.6.9 0.6.7 0.4.24' 0.6.7)" '0.6.9'
  u 'latest keep is newest overall' "$(gem_keep_version latest '3.3.9 3.4.4' 3.3.9)" '3.4.4'
  u 'branch keep sorts 0.4.24 above 0.4.9.1' "$(gem_keep_version branch '0.4.9.1 0.4.24' 0.4.9.1)" '0.4.24'

  u 'to_ascii drops the beer mug' "$(printf '\360\237\215\272  /opt/homebrew/Cellar/git/2.51.0\n' | to_ascii)" '  /opt/homebrew/Cellar/git/2.51.0'
  u 'filter output is ascii' "$(printf 'caf\303\251 ok\n' | filter_brew_output)" 'caf ok'
  t=$(mktemp)
  echo "fatal: unable to access 'https://github.com/Homebrew/brew/': Could not resolve host: github.com" > "$t"
  u 'dns failure is transient' "$(is_transient_failure "$t" && echo y || echo n)" 'y'
  echo 'curl: (56) Recv failure: Connection reset by peer' > "$t"
  u 'reset download is transient' "$(is_transient_failure "$t" && echo y || echo n)" 'y'
  echo 'Error: SHA256 mismatch' > "$t"
  u 'checksum mismatch is not retried' "$(is_transient_failure "$t" && echo y || echo n)" 'n'
  { echo 'Error: libfoo: post-install step failed'; echo 'Error: libfoo: post-install step failed'
    echo 'fatal: bad object'; for i in $(seq 1 40); do echo "==> Pouring x$i"; done; echo 'Error: in tail'; } > "$t"
  u 'error lines above the tail, deduped' "$(step_error_lines "$t" 40 | tr '\n' '|')" 'Error: libfoo: post-install step failed|fatal: bad object|'
  echo 'Error: You have not agreed to the Xcode license. Please resolve this by running:' > "$t"
  u 'xcode license detected' "$(xcode_license_blocked "$t" && echo y || echo n)" 'y'
  u 'xcode license not in clt text' "$(clt_outdated "$t" && echo y || echo n)" 'n'
  echo 'Error: Your Command Line Tools are too outdated.' > "$t"
  u 'old CLT detected' "$(clt_outdated "$t" && echo y || echo n)" 'y'
  echo 'Warning: Your Command Line Tools (CLT) are outdated.' > "$t"
  u 'old CLT warning detected' "$(clt_outdated "$t" && echo y || echo n)" 'y'
  echo "Error: It seems the App source '/opt/homebrew/Caskroom/kitty/0.43.1/kitty.app' is not there." > "$t"
  u 'missing app source' "$(cask_failure_reason "$t")" "brew's installed copy of the app is missing -- reinstall the cask (REPAIR_CASKS=1)"
  u 'missing app source detected' "$(cask_app_missing "$t" && echo y || echo n)" 'y'
  rm -f "$t"
  u 'CLT label newest of several' "$(printf '%s\n' 'Software Update found the following new or updated software:' \
    '* Label: Command Line Tools for Xcode-15.3' '	Title: Command Line Tools for Xcode, Version: 15.3' \
    '* Label: Command Line Tools for Xcode-16.2' '* Label: macOS Sequoia 15.7.1-24G231' | clt_update_label)" 'Command Line Tools for Xcode-16.2'
  u 'no CLT label' "$(printf '%s\n' 'No new software available.' | clt_update_label)" ''
  u 'gem dirs for own ABI' "$(gem_dirs_for_abi 3.3.0 /h/.local/share/gem/ruby/4.0.0 /opt/homebrew/lib/ruby/gems/3.3.0 /c/ruby@3.3/3.3.9/lib/ruby/gems/3.3.0 | tr '\n' '|')" \
    '/opt/homebrew/lib/ruby/gems/3.3.0|/c/ruby@3.3/3.3.9/lib/ruby/gems/3.3.0|'
  u 'gem dirs of another ruby' "$(gem_dirs_for_abi 3.3.0 /opt/homebrew/lib/ruby/gems/4.0.0)" ''
  bash -c 'sleep 30 & wait' & tp=$!
  sleep 1
  kids=$(descendants "$tp")
  u 'descendants finds the grandchild' "$([ "$(echo "$kids" | wc -w | tr -d ' ')" -ge 1 ] && echo y || echo n)" 'y'
  kill_tree "$tp"; wait "$tp" 2>/dev/null
  alive=0; for k in $kids; do kill -0 "$k" 2>/dev/null && alive=1; done
  u 'kill_tree stops the whole tree' "$alive" '0'
  exit $ufail
) || fail=1

# ----------------------------------------------------------- end to end ----
fix=$(mktemp -d)
trap 'rm -rf "$fix"' EXIT

make_fixture() {
  rm -rf "$fix/run"; mkdir -p "$fix/run/shims" "$fix/run/state" "$fix/run/logs"
  P="$fix/run/opt/homebrew"
  mkdir -p "$P/bin" "$P/Cellar/git/2.45.0" "$P/Cellar/git/2.51.0" "$P/Cellar/postgresql@14/14.10"
  S="$fix/run/state"
  printf 'git\npostgresql@14\n' > "$S/formulae_outdated"
  printf 'firefox\nzoom\n' > "$S/casks_outdated"
  printf 'postgresql@14\n' > "$S/pinned"
  printf 'git\npostgresql@14\n' > "$S/formulae"
  : > "$S/calls"

  cat > "$fix/run/shims/sudo" <<'EOF'
#!/bin/bash
[ "$1" = "-u" ] && shift 2
exec env "$@"
EOF
  cat > "$fix/run/shims/stat" <<'EOF'
#!/bin/bash
echo testuser
EOF
  cat > "$fix/run/shims/dscl" <<EOF
#!/bin/bash
echo "NFSHomeDirectory: $fix/run"
EOF
  printf '#!/bin/bash\necho 15.7\n' > "$fix/run/shims/sw_vers"
  printf '#!/bin/bash\nexit 0\n' > "$fix/run/shims/visudo"
  # No Xcode and no CLT unless a test installs these shims differently.
  printf '#!/bin/bash\nexit 2\n' > "$fix/run/shims/xcode-select"
  printf '#!/bin/bash\nexit 1\n' > "$fix/run/shims/pkgutil"

  cat > "$P/bin/brew" <<EOF
#!/bin/bash
S="$S"; P="$P"; SUDOERS="$fix/run/sudoers"
echo "\$*" >> "\$S/calls"
echo "\$1 NO_AUTOREMOVE=\${HOMEBREW_NO_AUTOREMOVE:-} NO_EMOJI=\${HOMEBREW_NO_EMOJI:-}" >> "\$S/env"
xcode_error() {
  echo "Error: You have not agreed to the Xcode license. Please resolve this by running:"
  echo "  sudo xcodebuild -license accept"
  exit 1
}
case "\$1 \$2" in
  "update "*)
    if [ -f "\$S/update_dns_once" ]; then
      rm -f "\$S/update_dns_once"
      echo "fatal: unable to access 'https://github.com/Homebrew/brew/': Could not resolve host: github.com"
      echo "Error: Fetching /opt/homebrew failed!"; exit 1
    fi
    [ -f "\$S/xcode_unaccepted" ] && xcode_error
    printf '%s\n' '==> Updating Homebrew...' '######## 100.0%' '==> New Formulae' 'newthing: x' 'Updated 2 taps.'
    exit 0 ;;
  "outdated --formula")
    for n in \$(cat "\$S/formulae_outdated"); do
      case "\$*" in *--verbose*) echo "\$n (1) < 2" ;; *) echo "\$n" ;; esac
    done; exit 0 ;;
  "outdated --cask")
    for n in \$(cat "\$S/casks_outdated"); do
      case "\$*" in *--verbose*) echo "\$n (1) != 2" ;; *) echo "\$n" ;; esac
    done; exit 0 ;;
  "list --pinned") cat "\$S/pinned"; exit 0 ;;
  "list --formula") cat "\$S/formulae"; exit 0 ;;
  "upgrade --formula")
    shift 2
    if [ -f "\$S/formula_error" ]; then
      echo "Error: libfoo: the post-install step did not complete successfully"
      for i in \$(seq 1 45); do echo "==> Pouring bottle \$i"; done
    fi
    for n in "\$@"; do grep -vx "\$n" "\$S/formulae_outdated" > "\$S/t"; mv "\$S/t" "\$S/formulae_outdated"; done
    printf '\360\237\215\272  %s/Cellar/git/2.51.0: 1,700 files\n' "\$P"
    [ -f "\$S/formula_error" ] && exit 1
    exit 0 ;;
  "upgrade --cask")
    n="\${!#}"
    if [ "\$n" = "zoom" ] && [ ! -f "\$SUDOERS" ]; then
      echo "sudo: a terminal is required to read the password"; exit 1
    fi
    if [ "\$n" = "\$(cat "\$S/slow_cask" 2>/dev/null)" ]; then
      bash -c 'sleep 300 & echo \$! > "\$1"; wait' _ "\$S/grandchild"
      exit 0
    fi
    if [ "\$n" = "\$(cat "\$S/missing_app_cask" 2>/dev/null)" ]; then
      echo "Error: It seems the App source '\$P/Caskroom/\$n/0.43.1/\$n.app' is not there."; exit 1
    fi
    grep -vx "\$n" "\$S/casks_outdated" > "\$S/t"; mv "\$S/t" "\$S/casks_outdated"
    exit 0 ;;
  "uninstall --cask") exit 0 ;;
  "install --cask")
    n="\${!#}"
    grep -vx "\$n" "\$S/casks_outdated" > "\$S/t"; mv "\$S/t" "\$S/casks_outdated"
    exit 0 ;;
  "cleanup "*)
    [ -f "\$S/xcode_unaccepted" ] && xcode_error
    rm -rf "\$P/Cellar/git/2.45.0"; exit 0 ;;
esac
exit 0
EOF
  chmod +x "$fix/run/shims/"* "$P/bin/brew"
}

run_script() {
  PATH="$fix/run/shims:$PATH" BREW_PREFIXES="$fix/run/opt/homebrew" LOG_DIR="$fix/run/logs" \
    SUDOERS_FILE="$fix/run/sudoers" "$@" bash "$script" >/dev/null 2>&1
}

make_fixture
run_script env CASK_SUDO=0; rc=$?
L="$fix/run/logs/homebrew_update.log"
check 'run 1 exits 2 (zoom + pinned left)' "$rc" '2'
check_grep 'zoom failure names sudo' 'FAILED   zoom -- needs sudo' "$L"
check_grep 'firefox upgraded' 'OK       firefox' "$L"
check_grep 'pinned formula reported' 'PINNED   postgresql@14' "$L"
check_nogrep 'pinned formula not upgraded' 'upgrade --formula .*postgresql@14' "$S/calls"
check_grep 'casks upgrade without --greedy by default' '^upgrade --cask firefox$' "$S/calls"
check 'superseded git keg removed' "$([ -d "$P/Cellar/git/2.45.0" ] && echo present || echo gone)" 'gone'
check 'current git keg kept' "$([ -d "$P/Cellar/git/2.51.0" ] && echo present || echo gone)" 'present'
up=$(grep -n '^upgrade --formula' "$S/calls" | head -1 | cut -d: -f1)
cl=$(grep -n '^cleanup' "$S/calls" | head -1 | cut -d: -f1)
check 'upgrade runs before cleanup' "$([ -n "$up" ] && [ -n "$cl" ] && [ "$up" -lt "$cl" ] && echo yes || echo no)" 'yes'
check_nogrep 'catalog omitted from main log' 'newthing' "$L"
check_grep 'summary lists what is left' 'Still outdated: .*postgresql@14.*zoom|Still outdated: .*zoom.*postgresql@14' "$L"
check_grep 'cleanup told not to autoremove' '^cleanup NO_AUTOREMOVE=1 NO_EMOJI=1$' "$S/env"
check 'main log is plain ASCII' "$(LC_ALL=C grep -c '[^ -~]' "$L")" '0'
check_grep 'brew success line kept without the emoji' '^\[.*\]     +/.*/Cellar/git/2.51.0: 1,700 files$' "$L"

make_fixture
printf 'zoom\n' > "$S/casks_outdated"
: > "$S/pinned"
run_script env CASK_SUDO=1; rc=$?
L="$fix/run/logs/homebrew_update.log"
check 'run 2 exits 0 with CASK_SUDO=1' "$rc" '0'
check_grep 'zoom upgraded with sudo grant' 'OK       zoom' "$L"
check_grep 'sudo grant logged' 'Temporary passwordless sudo granted to testuser' "$L"
check 'sudoers grant removed afterwards' "$([ -f "$fix/run/sudoers" ] && echo present || echo gone)" 'gone'

make_fixture
run_script env DRY_RUN=1; rc=$?
check 'dry run changes nothing' "$(grep -cE '^(upgrade|cleanup)' "$S/calls")" '0'
check 'dry run exits 2 (things are outdated)' "$rc" '2'

make_fixture
touch "$fix/run/sudoers"
printf '' > "$S/casks_outdated"; printf '' > "$S/formulae_outdated"
run_script env CASK_SUDO=0; rc=$?
check 'leftover sudoers grant from a killed run is removed' "$([ -f "$fix/run/sudoers" ] && echo present || echo gone)" 'gone'
check 'nothing outdated exits 0' "$rc" '0'

# --- first-run findings (2026-10-07..14 fleet logs) ---
# A cask over its limit is stopped with its whole process tree, on time.
make_fixture
printf 'slowcask\nfirefox\n' > "$S/casks_outdated"; : > "$S/formulae_outdated"; : > "$S/pinned"
echo slowcask > "$S/slow_cask"
t0=$(date +%s)
run_script env CASK_TIMEOUT=3; rc=$?
took=$(( $(date +%s) - t0 ))
L="$fix/run/logs/homebrew_update.log"
gc=$(cat "$S/grandchild" 2>/dev/null)
check 'slow cask grandchild was killed' "$([ -n "$gc" ] && ! kill -0 "$gc" 2>/dev/null && echo dead || echo alive)" 'dead'
check 'time limit enforced by the clock' "$([ "$took" -lt 40 ] && echo yes || echo "no (${took}s)")" 'yes'
check_grep 'time limit logged' 'TIME LIMIT \(3s\) reached -- stopping brew' "$L"
check_grep 'the next cask still ran' 'OK       firefox' "$L"
check_grep 'time limit listed as a problem' '  - brew hit its 3s time limit' "$L"
check 'timed-out run exits 2' "$rc" '2'

# The run budget stops everything after it and still writes a SUMMARY.
make_fixture
printf 'slowcask\nfirefox\n' > "$S/casks_outdated"; : > "$S/formulae_outdated"; : > "$S/pinned"
echo slowcask > "$S/slow_cask"
run_script env RUN_BUDGET=6 CASK_TIMEOUT=900; rc=$?
L="$fix/run/logs/homebrew_update.log"
check_grep 'budget stop logged' 'RUN_BUDGET \(6s\) used up -- stopping brew' "$L"
check_nogrep 'no cask after the budget' '^upgrade --cask firefox$' "$S/calls"
check_grep 'budget in the summary' '  - RUN_BUDGET \(6s\) used up' "$L"
check_grep 'summary still written' '===== END =====' "$L"
check 'budget run exits 2' "$rc" '2'

# brew update hits a DNS failure once, the retry succeeds.
make_fixture
: > "$S/casks_outdated"; : > "$S/formulae_outdated"; : > "$S/pinned"
touch "$S/update_dns_once"
run_script env RETRY_DELAY=0; rc=$?
L="$fix/run/logs/homebrew_update.log"
check 'brew update ran twice' "$(grep -c '^update' "$S/calls")" '2'
check_grep 'retry logged' 'network error -- retrying once in 0s' "$L"
check 'recovered update exits 0' "$rc" '0'

# Unaccepted Xcode license and no permission to accept it: update and
# cleanup fail, which must not end in "all current" (ARMB-09, CSPRMB-28).
make_fixture
: > "$S/casks_outdated"; : > "$S/formulae_outdated"; : > "$S/pinned"
touch "$S/xcode_unaccepted"
run_script env ACCEPT_XCODE_LICENSE=0; rc=$?
L="$fix/run/logs/homebrew_update.log"
check 'failed update/cleanup exits 2' "$rc" '2'
check_grep 'update failure listed' '  - .*: brew update failed' "$L"
check_grep 'cleanup failure listed' '  - .*: brew cleanup failed' "$L"
check_grep 'license named in the summary' "  - brew output says the Xcode license is not accepted" "$L"
check_nogrep 'no all-current verdict' 'RESULT: Homebrew, all formulae and all casks are current' "$L"
check_nogrep 'no keg NOTE after a failed cleanup' 'NOTE     ' "$L"

# Full Xcode with an unaccepted license is accepted before brew runs.
make_fixture
: > "$S/casks_outdated"; : > "$S/formulae_outdated"; : > "$S/pinned"
printf '#!/bin/bash\necho /Applications/Xcode.app/Contents/Developer\n' > "$fix/run/shims/xcode-select"
cat > "$fix/run/shims/xcodebuild" <<EOF
#!/bin/bash
echo "xcodebuild \$*" >> "$S/calls"
[ "\$2" = "check" ] && exit 1
exit 0
EOF
chmod +x "$fix/run/shims/xcode-select" "$fix/run/shims/xcodebuild"
run_script env; rc=$?
L="$fix/run/logs/homebrew_update.log"
check_grep 'license accepted as root' '^xcodebuild -license accept$' "$S/calls"
check_grep 'acceptance logged' 'Xcode license accepted' "$L"
check 'accepted license exits 0' "$rc" '0'
run_script env ACCEPT_XCODE_LICENSE=0; rc=$?
check_grep 'report-only names the command' "  - Xcode license not accepted .*sudo xcodebuild -license accept" "$L"
check 'report-only license exits 2' "$rc" '2'

# A pending Command Line Tools update is installed before brew runs.
make_fixture
: > "$S/casks_outdated"; : > "$S/formulae_outdated"; : > "$S/pinned"
printf '#!/bin/bash\nexit 0\n' > "$fix/run/shims/pkgutil"
cat > "$fix/run/shims/softwareupdate" <<EOF
#!/bin/bash
echo "softwareupdate \$*" >> "$S/calls"
if [ "\$1" = "--list" ]; then
  printf '%s\n' 'Software Update found the following new or updated software:' \
    '* Label: Command Line Tools for Xcode-16.2' '	Title: Command Line Tools for Xcode, Version: 16.2' \
    '* Label: Command Line Tools for Xcode-16.4' '* Label: macOS Sequoia 15.7.1-24G231'
fi
exit 0
EOF
chmod +x "$fix/run/shims/pkgutil" "$fix/run/shims/softwareupdate"
run_script env; rc=$?
L="$fix/run/logs/homebrew_update.log"
check_grep 'newest CLT installed' '^softwareupdate --install Command Line Tools for Xcode-16.4 --verbose$' "$S/calls"
cu=$(grep -n '^softwareupdate --install' "$S/calls" | cut -d: -f1)
bu=$(grep -n '^update' "$S/calls" | head -1 | cut -d: -f1)
check 'CLT updated before brew update' "$([ -n "$cu" ] && [ -n "$bu" ] && [ "$cu" -lt "$bu" ] && echo yes || echo no)" 'yes'
check 'CLT update run exits 0' "$rc" '0'
run_script env UPDATE_CLT=0; rc=$?
check_grep 'report-only CLT names the label' "  - Command Line Tools update pending: .*Xcode-16.4" "$L"
check 'report-only CLT exits 2' "$rc" '2'

# A formula batch that exits 1 names the formula that broke it, even when
# the error is far above the copied tail (CSMB-010, CSMB-017).
make_fixture
printf 'git\n' > "$S/formulae_outdated"; : > "$S/casks_outdated"; : > "$S/pinned"
touch "$S/formula_error"
run_script env; rc=$?
L="$fix/run/logs/homebrew_update.log"
check_grep 'early error copied to main log' '\(earlier\) Error: libfoo: the post-install step' "$L"
check_grep 'formula failure in the summary' '  - .*brew upgrade --formula failed: Error: libfoo' "$L"
check 'formula error exits 2' "$rc" '2'

# kitty: brew's app copy is gone -> force-uninstall and install again.
make_fixture
printf 'kitty\n' > "$S/casks_outdated"; : > "$S/formulae_outdated"; : > "$S/pinned"
echo kitty > "$S/missing_app_cask"
run_script env; rc=$?
L="$fix/run/logs/homebrew_update.log"
check_grep 'stale record force-uninstalled' '^uninstall --cask --force kitty$' "$S/calls"
check_grep 'cask installed again' '^install --cask kitty$' "$S/calls"
check_grep 'repair logged' 'REPAIRED kitty' "$L"
check 'repaired cask exits 0' "$rc" '0'
make_fixture
printf 'kitty\n' > "$S/casks_outdated"; : > "$S/formulae_outdated"; : > "$S/pinned"
echo kitty > "$S/missing_app_cask"
run_script env REPAIR_CASKS=0; rc=$?
L="$fix/run/logs/homebrew_update.log"
check_nogrep 'REPAIR_CASKS=0 leaves it' '^uninstall --cask' "$S/calls"
check_grep 'missing app reason' "FAILED   kitty -- brew's installed copy of the app is missing" "$L"
check 'unrepaired cask exits 2' "$rc" '2'

# AUTOREMOVE=1 lets cleanup autoremove again.
make_fixture
: > "$S/casks_outdated"; : > "$S/formulae_outdated"; : > "$S/pinned"
run_script env AUTOREMOVE=1
check_grep 'AUTOREMOVE=1 cleanup may autoremove' '^cleanup NO_AUTOREMOVE= ' "$S/env"

# --- Ruby gems bundled with Homebrew Ruby (CSPRMB-28 / ARMB-02 / ARMB-09) ---
# Keg bundles net-imap 0.5.10 + rexml 3.4.0 (+ a default net-imap 0.5.9);
# the shared gem dir has net-imap 0.4.20 / 0.6.4 and rexml 3.3.9; a 3.3.0
# gem dir from a Ruby brew already upgraded away still holds net-imap 0.4.9.1.
make_fixture
: > "$S/casks_outdated"; : > "$S/formulae_outdated"
KEG="$P/Cellar/ruby/3.4.7/lib/ruby/gems/3.4.0"
SHARED="$P/lib/ruby/gems/3.4.0"
ORPH="$P/lib/ruby/gems/3.3.0"
mkdir -p "$P/Cellar/ruby/3.4.7/lib/ruby/3.4.0" "$KEG/specifications/default" "$SHARED/specifications" \
  "$ORPH/specifications" "$ORPH/gems/net-imap-0.4.9.1" "$P/opt/ruby/bin" "$SHARED/gems/net-imap-0.4.20"
for f in "$KEG/specifications/net-imap-0.5.10" "$KEG/specifications/rexml-3.4.0" \
         "$KEG/specifications/default/net-imap-0.5.9" "$SHARED/specifications/net-imap-0.4.20" \
         "$SHARED/specifications/net-imap-0.6.4" "$SHARED/specifications/rexml-3.3.9" \
         "$ORPH/specifications/net-imap-0.4.9.1"; do : > "$f.gemspec"; done
cat > "$P/opt/ruby/bin/gem" <<EOF
#!/bin/bash
SHARED="$SHARED"; KEG="$KEG"; S="$S"
echo "gem \$*" >> "\$S/calls"
case "\$1" in
  environment) echo "\$SHARED:\$KEG"; exit 0 ;;
  list)
    g="\$2"; out=""
    for f in "\$SHARED"/specifications/\$g-*.gemspec "\$KEG"/specifications/\$g-*.gemspec "\$KEG"/specifications/default/\$g-*.gemspec; do
      [ -f "\$f" ] || continue
      v=\$(basename "\$f" .gemspec); v=\${v#\$g-}
      case "\$f" in */default/*) v="default: \$v" ;; esac
      out="\${out:+\$out, }\$v"
    done
    [ -n "\$out" ] && echo "\$g (\$out)"; exit 0 ;;
  install)
    g="\$2"; req=""
    [ "\$3" = "-v" ] && req="\$4"
    case "\$g|\$req" in
      "net-imap|~> 0.4.0") v=0.4.24 ;;
      "net-imap|~> 0.5.0") v=0.5.15 ;;
      "net-imap|~> 0.6.0") v=0.6.9 ;;
      "rexml|") v=3.4.4 ;;
      *) echo "unexpected install \$g \$req"; exit 1 ;;
    esac
    : > "\$SHARED/specifications/\$g-\$v.gemspec"
    echo "Successfully installed \$g-\$v"; exit 0 ;;
esac
exit 0
EOF
printf '#!/bin/bash\nprintf 3.4.0\n' > "$P/opt/ruby/bin/ruby"
chmod +x "$P/opt/ruby/bin/gem" "$P/opt/ruby/bin/ruby"
run_script env CASK_SUDO=0; rc=$?
L="$fix/run/logs/homebrew_update.log"
present() { [ -f "$1" ] && echo present || echo gone; }
check 'gem run exits 0' "$rc" '0'
check_grep 'net-imap installed per branch' '^gem install net-imap -v ~> 0.4.0 --no-document$' "$S/calls"
check_grep 'net-imap 0.6 branch installed' '^gem install net-imap -v ~> 0.6.0 --no-document$' "$S/calls"
check_grep 'rexml installed latest' '^gem install rexml --no-document$' "$S/calls"
check 'net-imap 0.4.20 removed' "$(present "$SHARED/specifications/net-imap-0.4.20.gemspec")" 'gone'
check 'net-imap 0.4.20 payload removed' "$([ -d "$SHARED/gems/net-imap-0.4.20" ] && echo present || echo gone)" 'gone'
check 'net-imap 0.4.24 kept' "$(present "$SHARED/specifications/net-imap-0.4.24.gemspec")" 'present'
check 'bundled keg net-imap 0.5.10 removed' "$(present "$KEG/specifications/net-imap-0.5.10.gemspec")" 'gone'
check 'net-imap 0.5.15 kept' "$(present "$SHARED/specifications/net-imap-0.5.15.gemspec")" 'present'
check 'default gem never deleted' "$(present "$KEG/specifications/default/net-imap-0.5.9.gemspec")" 'present'
check_grep 'default gem reported' 'DEFAULT  .*net-imap-0.5.9.gemspec' "$L"
check 'net-imap 0.6.4 removed' "$(present "$SHARED/specifications/net-imap-0.6.4.gemspec")" 'gone'
check 'net-imap 0.6.9 kept' "$(present "$SHARED/specifications/net-imap-0.6.9.gemspec")" 'present'
check 'rexml 3.3.9 removed (latest mode)' "$(present "$SHARED/specifications/rexml-3.3.9.gemspec")" 'gone'
check 'bundled keg rexml 3.4.0 removed' "$(present "$KEG/specifications/rexml-3.4.0.gemspec")" 'gone'
check 'rexml 3.4.4 kept' "$(present "$SHARED/specifications/rexml-3.4.4.gemspec")" 'present'
check 'orphaned 3.3.0 spec removed' "$(present "$ORPH/specifications/net-imap-0.4.9.1.gemspec")" 'gone'
check 'orphaned payload removed' "$([ -d "$ORPH/gems/net-imap-0.4.9.1" ] && echo present || echo gone)" 'gone'
check_grep 'summary counts removals' 'Ruby gem specs removed: 6' "$L"
gi=$(grep -n '^gem install' "$S/calls" | head -1 | cut -d: -f1)
cl=$(grep -n '^cleanup' "$S/calls" | head -1 | cut -d: -f1)
check 'gems run after brew cleanup' "$([ -n "$gi" ] && [ -n "$cl" ] && [ "$cl" -lt "$gi" ] && echo yes || echo no)" 'yes'
[ -n "${GEM_RUN_LOG:-}" ] && cp "$L" "$GEM_RUN_LOG"
check_grep 'ruby ABI logged' 'ruby  ruby ABI 3.4.0  gem path: ' "$L"

# ruby@3.3 whose gem reports Ruby 4.0's dirs is skipped, not "fixed" with
# another Ruby's versions; a root-owned gem dir is chowned and a gemspec that
# is a directory is removed (rexml FilePermissionError, ARMB-02 / ARMB-09).
make_fixture
: > "$S/casks_outdated"; : > "$S/formulae_outdated"; : > "$S/pinned"
printf '#!/bin/bash\necho nobody\n' > "$fix/run/shims/stat"
printf '#!/bin/bash\necho "chown $*" >> "%s/calls"\n' "$S" > "$fix/run/shims/chown"
chmod +x "$fix/run/shims/chown"
G4="$P/lib/ruby/gems/4.0.0"
mkdir -p "$P/opt/ruby@3.3/bin" "$P/opt/ruby/bin" "$G4/specifications/rexml-3.4.4.gemspec" "$P/Cellar/ruby/4.0.5/lib/ruby/4.0.0"
: > "$G4/specifications/rexml-3.4.1.gemspec"
for r in "ruby@3.3:3.3.0" "ruby:4.0.0"; do
  rd="$P/opt/${r%%:*}/bin"
  printf '#!/bin/bash\nprintf %s\n' "${r#*:}" > "$rd/ruby"
  cat > "$rd/gem" <<EOF
#!/bin/bash
echo "gem-${r%%:*} \$*" >> "$S/calls"
case "\$1" in
  environment) echo "$G4"; exit 0 ;;
  list) v=""; for f in "$G4"/specifications/rexml-*.gemspec; do [ -f "\$f" ] || continue
          b=\$(basename "\$f" .gemspec); v="\${v:+\$v, }\${b#rexml-}"; done
        [ -n "\$v" ] && echo "rexml (\$v)"; exit 0 ;;
  install) [ -d "$G4/specifications/rexml-3.4.4.gemspec" ] && { echo "ERROR:  While executing gem ... (Gem::FilePermissionError)"; exit 1; }
    : > "$G4/specifications/rexml-3.4.4.gemspec"; exit 0 ;;
esac
exit 0
EOF
  chmod +x "$rd/ruby" "$rd/gem"
done
run_script env RUBY_GEMS=rexml:latest; rc=$?
L="$fix/run/logs/homebrew_update.log"
check_grep 'mismatched ruby@3.3 skipped' "WARNING: ruby@3.3's gem reports another Ruby's gem dirs" "$L"
check_nogrep 'nothing installed through ruby@3.3' '^gem-ruby@3.3 install' "$S/calls"
check_grep 'mismatch in the summary' "  - ruby@3.3: 'gem environment gempath' has no 3.3.0 dir" "$L"
check_grep 'gem dir chowned to the brew user' "^chown -R nobody $G4\$" "$S/calls"
check_grep 'directory gemspec removed' 'FIXED    removed .*rexml-3.4.4.gemspec' "$L"
check_grep 'ruby 4.0 rexml installed' '^gem-ruby install rexml --no-document$' "$S/calls"
check 'old rexml removed' "$(present "$G4/specifications/rexml-3.4.1.gemspec")" 'gone'
check 'mismatch run exits 2' "$rc" '2'

make_fixture
: > "$S/casks_outdated"; : > "$S/formulae_outdated"
mkdir -p "$P/lib/ruby/gems/3.3.0/specifications"
: > "$P/lib/ruby/gems/3.3.0/specifications/net-imap-0.4.9.1.gemspec"
run_script env RUBY_GEMS= CASK_SUDO=0
check 'RUBY_GEMS empty skips the gem step' "$(present "$P/lib/ruby/gems/3.3.0/specifications/net-imap-0.4.9.1.gemspec")" 'present'

if [ "$fail" -ne 0 ]; then
  echo "tests failed"
  exit 1
fi
echo "All tests passed"
exit 0
