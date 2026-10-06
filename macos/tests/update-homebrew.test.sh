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

  u 'filter drops catalog and bars' "$(printf '%s\n' '==> Updating Homebrew...' '######## 100.0%' '==> New Formulae' 'foo: bar' '==> Outdated Formulae' 'git' | filter_brew_output | tr '\n' '|')" \
    '==> Updating Homebrew...|(omitted brew catalog: new, renamed and deleted formulae/casks)|==> Outdated Formulae|git|'
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

  cat > "$P/bin/brew" <<EOF
#!/bin/bash
S="$S"; P="$P"; SUDOERS="$fix/run/sudoers"
echo "\$*" >> "\$S/calls"
case "\$1 \$2" in
  "update "*)
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
    for n in "\$@"; do grep -vx "\$n" "\$S/formulae_outdated" > "\$S/t"; mv "\$S/t" "\$S/formulae_outdated"; done
    exit 0 ;;
  "upgrade --cask")
    n="\${!#}"
    if [ "\$n" = "zoom" ] && [ ! -f "\$SUDOERS" ]; then
      echo "sudo: a terminal is required to read the password"; exit 1
    fi
    grep -vx "\$n" "\$S/casks_outdated" > "\$S/t"; mv "\$S/t" "\$S/casks_outdated"
    exit 0 ;;
  "cleanup "*) rm -rf "\$P/Cellar/git/2.45.0"; exit 0 ;;
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
check_grep 'greedy casks' 'upgrade --cask --greedy firefox' "$S/calls"
check 'superseded git keg removed' "$([ -d "$P/Cellar/git/2.45.0" ] && echo present || echo gone)" 'gone'
check 'current git keg kept' "$([ -d "$P/Cellar/git/2.51.0" ] && echo present || echo gone)" 'present'
up=$(grep -n '^upgrade --formula' "$S/calls" | head -1 | cut -d: -f1)
cl=$(grep -n '^cleanup' "$S/calls" | head -1 | cut -d: -f1)
check 'upgrade runs before cleanup' "$([ -n "$up" ] && [ -n "$cl" ] && [ "$up" -lt "$cl" ] && echo yes || echo no)" 'yes'
check_nogrep 'catalog omitted from main log' 'newthing' "$L"
check_grep 'summary lists what is left' 'Still outdated: .*postgresql@14.*zoom|Still outdated: .*zoom.*postgresql@14' "$L"

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

if [ "$fail" -ne 0 ]; then
  echo "tests failed"
  exit 1
fi
echo "All tests passed"
exit 0
