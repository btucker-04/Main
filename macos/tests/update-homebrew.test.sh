# Tests for update-homebrew.sh.
# Run: bash macos/tests/update-homebrew.test.sh
#
# Unit checks for the helpers, then two end-to-end runs against a fake brew
# (shims stand in for sudo / stat / dscl / visudo / sw_vers):
#   1. a .pkg cask (zoom) fails without sudo, a pinned formula stays outdated,
#      upgrade runs BEFORE cleanup and the superseded keg is removed -> exit 2
#   2. CASK_SUDO=1 lets zoom upgrade, and the sudoers grant is gone -> exit 0
# then one scenario per fleet finding (v2: 2026-10-07..14, v3: ..11-03).
# Shims for curl (network probe), sysctl (sleep/wake) and date (clock jump)
# let a test take the Mac offline or put it to sleep for two hours.
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
# LAST_TICK, OUT_USED and OUTPUT_LIMIT are read by the sourced script.
# shellcheck disable=SC2034
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
  u 'pkg cask needs sudo' "$(cask_failure_reason "$t")" 'needs sudo (.pkg installer) -- add it to CFG_CASK_SUDO'
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

  # --- v3: fleet runs 2026-10-14..11-03 (lines verbatim from Mosyle) ---
  sysctl() { echo '{ sec = 1761650000, usec = 123456 } Tue Oct 28 09:02:00 2026'; }
  u 'sysctl timeval seconds' "$(sysctl_sec kern.waketime)" '1761650000'
  unset -f sysctl
  u 'sleep inside the gap counts from sleeptime' "$(slept_between 1000 9000 1100 8000)" '6900'
  u 'sleep that began before the gap counts from the tick' "$(slept_between 1000 9000 500 8000)" '7000'
  u 'wake before the gap is not ours' "$(slept_between 1000 9000 100 900)" '0'
  u 'unknown sleep/wake counts nothing' "$(slept_between 1000 9000 '' '')" '0'
  sysctl_sec() { case "$1" in kern.sleeptime) echo $(( $(date +%s) - 7190 )) ;; kern.waketime) echo $(( $(date +%s) - 10 )) ;; esac; }
  SLEPT=0; LAST_TICK=$(( $(date +%s) - 7200 )); tick
  u 'tick books a 2h lid-closed sleep' "$([ "$SLEPT" -ge 7175 ] && [ "$SLEPT" -le 7185 ] && echo y || echo "n ($SLEPT)")" 'y'
  aw=$(( $(date +%s) - AWAKE_NOW ))
  u 'awake clock excludes the sleep' "$([ "$aw" -ge "$SLEPT" ] && [ "$aw" -le $(( SLEPT + 1 )) ] && echo y || echo n)" 'y'
  SLEPT=0; LAST_TICK=$(( $(date +%s) - 10 )); tick
  u 'short gap is never sleep' "$SLEPT" '0'
  unset -f sysctl_sec

  t=$(mktemp)
  for m in "Cant connect to the Apple Software Update server, because you are not connected to the internet." \
           "Can$(printf '\342\200\231')t connect to the Apple Software Update server, because you are not connected to the internet." \
           "Didn$(printf '\342\200\231')t get a response from the Apple Software Update server." \
           "The network connection was lost." "A TLS error caused the secure connection to fail."; do
    printf '%s\n' "$m" 'Software Update Tool' '' 'Finding available software' > "$t"
    u "softwareupdate unreachable: ${m%% the *}" "$(LC_ALL=C softwareupdate_unreachable "$t" && echo y || echo n)" 'y'
  done
  printf '%s\n' 'Software Update Tool' 'Finding available software' 'No new software available.' > "$t"
  u 'no new software is not unreachable' "$(softwareupdate_unreachable "$t" && echo y || echo n)" 'n'

  u 'CLT label version (27.x style)' "$(clt_label_version 'Command Line Tools for Xcode 27.2-27.2')" '27.2'
  u 'CLT label version (16.x style)' "$(clt_label_version 'Command Line Tools for Xcode-16.4')" '16.4'
  u 'pkgutil 27.2.0.0.1 covers 27.2' "$(clt_version_covers 27.2.0.0.1.1761100000 27.2 && echo y || echo n)" 'y'
  u 'pkgutil 27.0 does not cover 27.2' "$(clt_version_covers 27.0.0.0.1.1758000000 27.2 && echo y || echo n)" 'n'
  u 'pkgutil 27.10 covers 27.2' "$(clt_version_covers 27.10.0.0.1 27.2 && echo y || echo n)" 'y'
  u 'no pkgutil version covers nothing' "$(clt_version_covers '' 27.2 && echo y || echo n)" 'n'

  # ARMB-09 2026-10-20, brew update reinstalling pkgconf.
  printf '%s\n' '==> Fetching downloads for: pkgconf' '==> Reinstalling pkgconf' '==> make install' \
    'Error: The `brew link` step did not complete successfully' 'The formula built, but is not symlinked into /opt/homebrew' \
    'Could not symlink bin/pkg-config' 'Target /opt/homebrew/bin/pkg-config' 'is a symlink belonging to pkg-config. You can unlink it:' \
    '  brew unlink pkg-config' '==> Summary' '==> Reinstalled pkgconf due to macOS version mismatch' > "$t"
  u 'link failure names formula and owner' "$(link_failures "$t")" 'pkgconf: bin/pkg-config -- /opt/homebrew/bin/pkg-config belongs to pkg-config'
  u 'link-only update error is not a fetch failure' "$(update_fetch_failed "$t" && echo y || echo n)" 'n'
  printf '%s\n' '==> Upgrading python@3.13' '  3.13.17 -> 3.13.18' '==> Pouring python@3.13--3.13.18.arm64_golden_gate.bottle.tar.gz' \
    'Error: The `brew link` step did not complete successfully' 'The formula built, but is not symlinked into /opt/homebrew' \
    'Could not symlink bin/pip3.13' 'Target /opt/homebrew/bin/pip3.13' "already exists. You may want to remove it:" \
    "  rm '/opt/homebrew/bin/pip3.13'" '==> Upgrading zip' > "$t"
  u 'link failure: file already exists' "$(link_failures "$t")" 'python@3.13: bin/pip3.13 -- /opt/homebrew/bin/pip3.13 already exists'
  # CSMB-011 2026-10-28.
  printf '%s\n' '==> Updating Homebrew...' "fatal: unable to access 'https://github.com/Homebrew/brew/': Could not resolve host: github.com" \
    'Error: Fetching /opt/homebrew failed!' 'Failed to download https://formulae.brew.sh/api/internal/packages.arm64_golden_gate.jws.json!' > "$t"
  u 'DNS update failure is a fetch failure' "$(update_fetch_failed "$t" && echo y || echo n)" 'y'
  u 'no link failure in a DNS failure' "$(link_failures "$t")" ''

  # CSMB-026 2026-11-02.
  printf '%s\n' 'Warning: The following taps are not trusted:' '  asmvik/formulae' '  koekeishiya/formulae' '  powershell/tap' \
    'Homebrew is currently ignoring formulae, casks and commands' 'from these taps because tap trust is required.' \
    'Trust installed formulae from these taps with:' '  brew trust --formula asmvik/formulae/yabai' \
    '  brew trust --formula koekeishiya/formulae/skhd' '  brew trust --formula powershell/tap/powershell' \
    'Trust other specific casks and commands with:' '  brew trust --cask <user>/<tap>/<cask>' '  brew trust --command <user>/<tap>/<command>' \
    '  brew trust asmvik/formulae koekeishiya/formulae powershell/tap' > "$t"
  u 'untrusted taps listed' "$(untrusted_taps "$t" | tr '\n' ' ')" 'asmvik/formulae koekeishiya/formulae powershell/tap '
  u 'untrusted installed formulae, no placeholders' "$(untrusted_items "$t" | tr '\n' ' ')" 'asmvik/formulae/yabai koekeishiya/formulae/skhd powershell/tap/powershell '

  # CSMB-020 2026-11-02.
  printf '%s\n' 'Warning: Permission denied @ apply2files - /opt/homebrew/Cellar/python@3.10/3.10.20/Frameworks/x.pyc' \
    'Error: Could not cleanup old kegs! Fix your permissions on:' '  /opt/homebrew/Cellar/python@3.10/3.10.20' \
    'Removing: /opt/homebrew/Cellar/python@3.10/3.10.20... (1,238 files, 21.1MB)' > "$t"
  u 'cleanup permission path' "$(cleanup_permission_paths "$t")" '/opt/homebrew/Cellar/python@3.10/3.10.20'
  rm -f "$t"

  u 'CASK_SUDO=1 covers any cask' "$(cask_sudo_wanted zoom 1 && echo y || echo n)" 'y'
  u 'CASK_SUDO=0 covers none' "$(cask_sudo_wanted zoom 0 && echo y || echo n)" 'n'
  u 'CASK_SUDO list covers a listed cask' "$(cask_sudo_wanted temurin@21 'temurin@21 docker-desktop' && echo y || echo n)" 'y'
  u 'CASK_SUDO list is whole-word' "$(cask_sudo_wanted temurin 'temurin@21 docker-desktop' && echo y || echo n)" 'n'

  # --- v3.1: fleet runs 2026-11-04..05 ---
  # ARMB-02 / CSMB-017: "ruby@4.0 ... gem path: .../Cellar/ruby/4.0.9/..." x3.
  kegs="/opt/homebrew/Cellar/ruby/4.0.9|ruby
"
  u 'alias of a done keg names the first label' "$(keg_seen_as /opt/homebrew/Cellar/ruby/4.0.9 "$kegs")" 'ruby'
  u 'another keg is new' "$(keg_seen_as /opt/homebrew/Cellar/ruby@3.3/3.3.10 "$kegs")" ''
  u 'unresolved keg is never a duplicate' "$(keg_seen_as '' "$kegs")" ''
  # CSMB-036: "No answer from: ghcr.io" ... "OFFLINE: none of github.com formulae.brew.sh ghcr.io".
  hosts='github.com formulae.brew.sh ghcr.io'
  u 'outage spreading to every host is logged' "$(network_change_line "$hosts" ghcr.io "$hosts")" "Now no host answers ($hosts)."
  u 'outage narrowing is logged' "$(network_change_line github.com "$hosts" "$hosts")" 'Now no answer from: github.com'
  u 'unchanged outage logs nothing' "$(network_change_line ghcr.io ghcr.io "$hosts")" ''

  # --- v3.2: fleet runs 2026-10-19..11-12 ---
  # jriegel-mac: "FAILED android-ndk / sage / zulu@11 / zulu@8 -- needs sudo".
  u 'sudo suggestion from CASK_SUDO=0' "$(cask_sudo_suggestion 0 ' android-ndk sage zulu@11 zulu@8')" 'android-ndk sage zulu@11 zulu@8'
  u 'sudo suggestion adds to an existing list' "$(cask_sudo_suggestion 'temurin@21' 'temurin@21 docker-desktop')" 'temurin@21 docker-desktop'
  u 'no suggestion when CASK_SUDO=1' "$(cask_sudo_suggestion 1 'zoom')" ''
  u 'no suggestion without sudo casks' "$(cask_sudo_suggestion 0 ' ')" ''
  m=$(mktemp)
  printf '%s\n' '/opt/homebrew sage 10.7' '/opt/homebrew zulu@8 8.88.0.19' '/usr/local sage 10.6' > "$m"
  u 'memo hit on same cask and version' "$(sudo_memo_has /opt/homebrew sage 10.7 "$m" && echo y || echo n)" 'y'
  u 'memo miss on a new installed version' "$(sudo_memo_has /opt/homebrew sage 10.8 "$m" && echo y || echo n)" 'n'
  u 'memo miss on unknown version' "$(sudo_memo_has /opt/homebrew sage '' "$m" && echo y || echo n)" 'n'
  u 'memo miss on another prefix' "$(sudo_memo_has /usr/local zulu@8 8.88.0.19 "$m" && echo y || echo n)" 'n'
  u 'memo carries other prefixes and untried casks' "$(sudo_memo_untried /opt/homebrew 'zulu@8' "$m" | tr '\n' '|')" '/opt/homebrew zulu@8 8.88.0.19|/usr/local sage 10.6|'
  rm -f "$m"
  tp=$(mktemp -d)
  mkdir -p "$tp/Caskroom/temurin/25.0.1,8" "$tp/Caskroom/temurin/.metadata"
  u 'installed cask version skips .metadata' "$(cask_installed_version "$tp" temurin)" '25.0.1,8'
  u 'no version for a cask not installed' "$(cask_installed_version "$tp" zoom)" ''
  # CSPRMB-21-A: ethereum/ethereum + microsoft/git untrusted, no "brew trust
  # --formula" lines. solidity is installed, but from homebrew/core.
  mkdir -p "$tp/Library/Taps/ethereum/homebrew-ethereum/Formula" "$tp/Library/Taps/microsoft/homebrew-git/Casks" \
    "$tp/Library/Taps/nikitabobko/homebrew-tap/Casks" "$tp/Cellar/solidity/0.8.30" "$tp/Caskroom/aerospace/0.19.2/.x" \
    "$tp/Caskroom/aerospace/.metadata"
  touch "$tp/Library/Taps/ethereum/homebrew-ethereum/Formula/solidity.rb" "$tp/Library/Taps/ethereum/homebrew-ethereum/Formula/cpp-ethereum.rb" \
    "$tp/Library/Taps/microsoft/homebrew-git/Casks/git-credential-manager.rb" "$tp/Library/Taps/nikitabobko/homebrew-tap/Casks/aerospace.rb"
  printf '{"source": {"tap": "homebrew/core", "spec": "stable"}}' > "$tp/Cellar/solidity/0.8.30/INSTALL_RECEIPT.json"
  printf '{"source": {"tap": "nikitabobko/tap"}}' > "$tp/Caskroom/aerospace/.metadata/INSTALL_RECEIPT.json"
  u 'core formula of the same name is not from the tap' "$(tap_installed_items "$tp" ethereum/ethereum)" ''
  u 'uninstalled tap cask is not in use' "$(tap_installed_items "$tp" microsoft/git)" ''
  # CSMB-017 2026-10-28: nikitabobko/tap untrusted, brew lists no cask.
  u 'installed tap cask is found' "$(tap_installed_items "$tp" nikitabobko/tap)" 'cask nikitabobko/tap/aerospace'
  rm "$tp/Cellar/solidity/0.8.30/INSTALL_RECEIPT.json"
  u 'keg without a receipt counts as in use' "$(tap_installed_items "$tp" ethereum/ethereum)" 'formula ethereum/ethereum/solidity'
  u 'tap directory missing' "$(tap_installed_items "$tp" jaketrock/tap)" 'unknown'
  rm -rf "$tp"

  OUTPUT_LIMIT=1000; OUT_USED=0; set_output_phase body
  o=$( for i in $(seq 1 60); do to_stdout "body line $i padded to about forty bytes"; done
       set_output_phase summary; for i in $(seq 1 60); do to_stdout "summary $i"; done
       set_output_phase final; to_stdout 'RESULT: x' )
  u 'body stops at 3/5 of the limit' "$([ "$(printf '%s\n' "$o" | grep -c '^body line')" -le 15 ] && echo y || echo n)" 'y'
  u 'one trim marker per phase' "$(printf '%s\n' "$o" | grep -c 'output trimmed for Mosyle')" '2'
  u 'summary prints after the body is cut' "$(printf '%s\n' "$o" | grep -c '^summary 1$')" '1'
  u 'final line always prints' "$(printf '%s\n' "$o" | tail -n 1)" 'RESULT: x'
  u 'stdout stays under the limit' "$([ "$(printf '%s\n' "$o" | wc -c)" -le 1100 ] && echo y || echo n)" 'y'
  OUTPUT_LIMIT=0
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
  # Network probe: hosts listed in state/net_down do not answer.
  cat > "$fix/run/shims/curl" <<EOF
#!/bin/bash
for a in "\$@"; do u="\$a"; done
h="\${u#https://}"
echo "curl \$h" >> "$S/net_calls"
# state/net_nap = N: Power Nap -- each probe the clock jumps N seconds and
# kern.sleeptime / kern.waketime do not record it.
[ -f "$S/net_nap" ] && echo \$(( \$(cat "$S/clock_offset" 2>/dev/null || echo 0) + \$(cat "$S/net_nap") )) > "$S/clock_offset"
# state/net_up_after = N: the network comes back after N probes.
[ -f "$S/net_up_after" ] && [ "\$(wc -l < "$S/net_calls")" -gt "\$(cat "$S/net_up_after")" ] && exit 0
grep -qx "\$h" "$S/net_down" 2>/dev/null && { echo "curl: (6) Could not resolve host: \$h" >&2; exit 6; }
exit 0
EOF
  # No sleep/wake unless a test writes state/waketime (epoch seconds).
  cat > "$fix/run/shims/sysctl" <<EOF
#!/bin/bash
case "\$2" in
  kern.waketime) [ -f "$S/waketime" ] && echo "{ sec = \$(cat "$S/waketime"), usec = 0 } Tue Oct 28 09:02:00 2026" ;;
  kern.sleeptime) [ -f "$S/sleeptime" ] && echo "{ sec = \$(cat "$S/sleeptime"), usec = 0 } Tue Oct 28 07:08:00 2026" ;;
esac
exit 0
EOF
  # The clock: real time plus state/clock_offset seconds (a simulated sleep).
  cat > "$fix/run/shims/date" <<EOF
#!/bin/bash
off=\$(cat "$S/clock_offset" 2>/dev/null || echo 0)
if [ "\$1" = "+%s" ]; then echo \$(( \$(/bin/date +%s) + off )); exit 0; fi
exec /bin/date "\$@"
EOF

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
nap() {  # the Mac sleeps \$1 seconds: the clock jumps, kern.*time record it
  now=\$(/bin/date +%s); echo "\$1" > "\$S/clock_offset"
  echo \$((now + 1)) > "\$S/sleeptime"; echo \$((now + \$1)) > "\$S/waketime"
}
case "\$1 \$2" in
  "update "*)
    if [ -f "\$S/update_dns_sleep_once" ]; then
      rm -f "\$S/update_dns_sleep_once"
      echo "fatal: unable to access 'https://github.com/Homebrew/brew/': Could not resolve host: github.com"
      echo "Error: Fetching /opt/homebrew failed!"; nap 7200; exit 1
    fi
    if [ -f "\$S/update_link_error" ]; then
      printf '%s\n' '==> Updating Homebrew...' 'Updated 2 taps (homebrew/core and homebrew/cask).' '==> Reinstalling pkgconf' \\
        'Error: The \`brew link\` step did not complete successfully' 'The formula built, but is not symlinked into /opt/homebrew' \\
        'Could not symlink bin/pkg-config' 'Target /opt/homebrew/bin/pkg-config' 'is a symlink belonging to pkg-config. You can unlink it:' \\
        '  brew unlink pkg-config' '==> Reinstalled pkgconf due to macOS version mismatch'
      exit 1
    fi
    if [ -f "\$S/slow_update" ]; then
      bash -c 'sleep 300 & wait'; exit 0
    fi
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
    if [ -f "\$S/untrusted" ]; then
      printf '%s\n' 'Warning: The following taps are not trusted:' '  asmvik/formulae' '  powershell/tap' \\
        'Homebrew is currently ignoring formulae, casks and commands' 'Trust installed formulae from these taps with:' \\
        '  brew trust --formula asmvik/formulae/yabai' '  brew trust --formula powershell/tap/powershell' \\
        '  brew trust --cask <user>/<tap>/<cask>'
    fi
    if [ -f "\$S/untrusted_unused" ]; then
      printf '%s\n' 'Warning: The following taps are not trusted:' 'ethereum/ethereum' 'microsoft/git' \\
        'Homebrew is currently ignoring formulae, casks and commands' 'from these taps because tap trust is required.' \\
        'Untap them with:' 'brew untap ethereum/ethereum microsoft/git' 'Trust specific formulae, casks and commands with:' \\
        'brew trust --formula <user>/<tap>/<formula>' 'brew trust --cask <user>/<tap>/<cask>' 'brew trust --command <user>/<tap>/<command>'
    fi
    for n in "\$@"; do grep -vx "\$n" "\$S/formulae_outdated" > "\$S/t"; mv "\$S/t" "\$S/formulae_outdated"; done
    printf '\360\237\215\272  %s/Cellar/git/2.51.0: 1,700 files\n' "\$P"
    if [ -f "\$S/link_error" ]; then
      printf '%s\n' '==> Upgrading python@3.13' '==> Pouring python@3.13--3.13.18.arm64_golden_gate.bottle.tar.gz' \\
        'Error: The \`brew link\` step did not complete successfully' 'The formula built, but is not symlinked into /opt/homebrew' \\
        'Could not symlink bin/pip3.13' 'Target /opt/homebrew/bin/pip3.13' 'already exists. You may want to remove it:' \\
        "  rm '/opt/homebrew/bin/pip3.13'"
      for i in \$(seq 1 45); do echo "==> Caveats \$i"; done
      exit 1
    fi
    [ -f "\$S/formula_error" ] && exit 1
    exit 0 ;;
  "upgrade --cask")
    n="\${!#}"
    echo "\$n sudoers=\$([ -f "\$SUDOERS" ] && echo y || echo n)" >> "\$S/sudo_seen"
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
    if [ -f "\$S/many_removing" ]; then
      for i in \$(seq 1 400); do echo "Removing: /Users/testuser/Library/Caches/Homebrew/pkg\$i--1.0... (18MB)"; done
    fi
    if [ -f "\$S/cleanup_perm" ]; then
      printf '%s\n' "Warning: Permission denied @ apply2files - \$P/Cellar/python@3.10/3.10.20/x.pyc" \\
        'Error: Could not cleanup old kegs! Fix your permissions on:' "  \$P/Cellar/python@3.10/3.10.20"
      exit 1
    fi
    rm -rf "\$P/Cellar/git/2.45.0"; exit 0 ;;
esac
exit 0
EOF
  chmod +x "$fix/run/shims/"* "$P/bin/brew"
}

run_script() {
  PATH="$fix/run/shims:$PATH" BREW_PREFIXES="$fix/run/opt/homebrew" LOG_DIR="$fix/run/logs" \
    SUDOERS_FILE="$fix/run/sudoers" "$@" bash "$script" >"$fix/run/stdout" 2>&1
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
check_grep 'budget in the summary' '  - RUN_BUDGET \(6s awake\) used up; not run: cask_firefox' "$L"
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
check_grep 'early error copied to main log' '    ! Error: libfoo: the post-install step' "$L"
check_grep 'early error reaches stdout' '    ! Error: libfoo: the post-install step' "$fix/run/stdout"
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

# opt/ruby, opt/ruby@4 and opt/ruby@4.0 all link to Cellar/ruby/4.0.9
# (ARMB-02 / CSMB-017 2026-11-04: each gem installed three times).
make_fixture
: > "$S/casks_outdated"; : > "$S/formulae_outdated"; : > "$S/pinned"
G4="$P/lib/ruby/gems/4.0.0"
RK="$P/Cellar/ruby/4.0.9"
mkdir -p "$RK/bin" "$RK/lib/ruby/4.0.0" "$G4/specifications"
: > "$G4/specifications/rexml-3.4.1.gemspec"
printf '#!/bin/bash\nprintf 4.0.0\n' > "$RK/bin/ruby"
cat > "$RK/bin/gem" <<EOF
#!/bin/bash
echo "gem \$*" >> "$S/calls"
case "\$1" in
  environment) echo "$G4"; exit 0 ;;
  list) v=""; for f in "$G4"/specifications/rexml-*.gemspec; do [ -f "\$f" ] || continue
          b=\$(basename "\$f" .gemspec); v="\${v:+\$v, }\${b#rexml-}"; done
        [ -n "\$v" ] && echo "rexml (\$v)"; exit 0 ;;
  install) : > "$G4/specifications/rexml-3.4.4.gemspec"; exit 0 ;;
esac
exit 0
EOF
chmod +x "$RK/bin/ruby" "$RK/bin/gem"
mkdir -p "$P/opt"
for n in ruby ruby@4 ruby@4.0; do ln -s ../Cellar/ruby/4.0.9 "$P/opt/$n"; done
run_script env RUBY_GEMS=rexml:latest; rc=$?
L="$fix/run/logs/homebrew_update.log"
check 'aliased keg: gem install runs once' "$(grep -c '^gem install rexml' "$S/calls")" '1'
check_grep 'ruby@4 skipped as the same keg' 'ruby@4  same keg as ruby \(.*/Cellar/ruby/4.0.9\) -- already done\.' "$L"
check_grep 'ruby@4.0 skipped as the same keg' 'ruby@4.0  same keg as ruby ' "$L"
check 'old rexml removed through the one keg' "$(present "$G4/specifications/rexml-3.4.1.gemspec")" 'gone'
check 'aliased keg run exits 0' "$rc" '0'

make_fixture
: > "$S/casks_outdated"; : > "$S/formulae_outdated"
mkdir -p "$P/lib/ruby/gems/3.3.0/specifications"
: > "$P/lib/ruby/gems/3.3.0/specifications/net-imap-0.4.9.1.gemspec"
run_script env RUBY_GEMS= CASK_SUDO=0
check 'RUBY_GEMS empty skips the gem step' "$(present "$P/lib/ruby/gems/3.3.0/specifications/net-imap-0.4.9.1.gemspec")" 'present'

# --- v3: fleet runs 2026-10-14..11-03 ---
# Mosyle keeps ~9 KB: 19 outdated formulae, 400 "Removing:" lines and a
# failed cask must still leave the SUMMARY and RESULT on stdout (ARMB-02,
# CSMB-010: cut mid-word in cleanup).
make_fixture
for i in $(seq 1 40); do echo "formula-number-$i"; done > "$S/formulae_outdated"
cp "$S/formulae_outdated" "$S/formulae"; printf 'zoom\n' > "$S/casks_outdated"; : > "$S/pinned"
touch "$S/many_removing" "$S/untrusted"
run_script env; rc=$?
O="$fix/run/stdout"; L="$fix/run/logs/homebrew_update.log"
check 'stdout fits under OUTPUT_LIMIT' "$([ "$(wc -c < "$O")" -le 7300 ] && echo yes || echo "no ($(wc -c < "$O") bytes)")" 'yes'
check_grep 'SUMMARY reaches Mosyle' '================ SUMMARY ================' "$O"
check_grep 'failed cask reason in the SUMMARY' '^\[.*\]   - zoom -- needs sudo' "$O"
check_grep 'RESULT reaches Mosyle' 'RESULT: brew ran, but the items above still need attention' "$O"
check_grep 'END reaches Mosyle' '===== END =====' "$O"
check_nogrep 'cleanup listing kept off stdout' 'Removing: ' "$O"
check_grep 'cleanup tail in the main log file' 'Removing: /Users/testuser/Library/Caches/Homebrew/pkg400--' "$L"
check_grep 'whole cleanup listing in the step log' 'Removing: /Users/testuser/Library/Caches/Homebrew/pkg1--' "$(ls "$fix/run/logs/"homebrew_*_cleanup.log)"
check_grep 'outdated list is one line' '  formulae \(40\): formula-number-1 formula-number-2 ' "$O"
check 'big run exits 2 (zoom)' "$rc" '2'

# CSMB-011 2026-10-28: brew update hit a DNS error, the Mac slept 2h through
# the 60s retry wait, RUN_BUDGET was gone and nothing was upgraded.
make_fixture
: > "$S/casks_outdated"; : > "$S/pinned"
touch "$S/update_dns_sleep_once"
run_script env RETRY_DELAY=0; rc=$?
L="$fix/run/logs/homebrew_update.log"
check 'retry ran after the sleep' "$(grep -c '^update' "$S/calls")" '2'
check_grep 'formulae upgraded after the sleep' '^upgrade --formula git postgresql@14$' "$S/calls"
check_nogrep 'budget not spent by sleep' 'RUN_BUDGET .* used up' "$L"
check_grep 'sleep reported in the summary' 'Mac was asleep 7[0-9]{3}s of ' "$L"
check 'slept-through run exits 0' "$rc" '0'
check_nogrep 'no failure issues after the sleep' '  - .*(failed|time limit)' "$L"

clt_shims() {
  cat > "$fix/run/shims/pkgutil" <<EOF
#!/bin/bash
[ -f "$S/clt_new" ] && echo 'version: 27.2.0.0.1.1761100000' || echo 'version: 27.0.0.0.1.1758000000'
exit 0
EOF
  cat > "$fix/run/shims/softwareupdate" <<EOF
#!/bin/bash
echo "softwareupdate \$*" >> "$S/calls"
if [ "\$1" = "--list" ]; then
  printf '%s\n' 'Software Update found the following new or updated software:' '* Label: Command Line Tools for Xcode 27.2-27.2'
  exit 0
fi
printf '%s\n' 'Installing Command Line Tools for Xcode 27.2' 'Done with Command Line Tools for Xcode 27.2' 'Done.'
touch "$S/clt_new"
[ -f "$S/clt_hang" ] && { bash -c 'sleep 300 & wait'; exit 0; }
echo 5000 > "$S/clock_offset"
exit 0
EOF
  chmod +x "$fix/run/shims/pkgutil" "$fix/run/shims/softwareupdate"
}
# CSMB-036 2026-10-29: softwareupdate printed "Done." and exited while the
# Mac slept; the limit check then "stopped" it and the SUMMARY said failed.
make_fixture
: > "$S/casks_outdated"; : > "$S/formulae_outdated"; : > "$S/pinned"
clt_shims
run_script env; rc=$?
L="$fix/run/logs/homebrew_update.log"
check_grep 'CLT install reported installed' 'Installed Command Line Tools for Xcode 27.2-27.2' "$L"
check_nogrep 'CLT install not reported failed' 'failed to install|TIME LIMIT' "$L"
check 'CLT finished-during-sleep run exits 0' "$rc" '0'
# A CLT install that really hits its limit after installing: pkgutil decides.
make_fixture
: > "$S/casks_outdated"; : > "$S/formulae_outdated"; : > "$S/pinned"
clt_shims; touch "$S/clt_hang"
run_script env BREW_TIMEOUT=3; rc=$?
L="$fix/run/logs/homebrew_update.log"
check_grep 'CLT time limit hit' 'TIME LIMIT \(3s\) reached -- stopping softwareupdate' "$L"
check_grep 'pkgutil confirms the install' 'Installed Command Line Tools for Xcode 27.2-27.2 \(pkgutil reports 27.2.0.0.1' "$L"
check_nogrep 'confirmed CLT is not a problem' '  - softwareupdate hit|failed to install' "$L"
check 'pkgutil-confirmed CLT exits 0' "$rc" '0'

# Software Update server unreachable is "not checked", never "current"
# (CSMB-010 / CSMB-011 / CSMB-017 ... on 2026-10-28).
make_fixture
: > "$S/casks_outdated"; : > "$S/formulae_outdated"; : > "$S/pinned"
printf '#!/bin/bash\necho "version: 27.0.0.0.1"\nexit 0\n' > "$fix/run/shims/pkgutil"
cat > "$fix/run/shims/softwareupdate" <<'EOF'
#!/bin/bash
printf '%s\n' "Can$(printf '\342\200\231')t connect to the Apple Software Update server, because you are not connected to the internet." 'Software Update Tool' '' 'Finding available software'
exit 0
EOF
chmod +x "$fix/run/shims/pkgutil" "$fix/run/shims/softwareupdate"
run_script env; rc=$?
L="$fix/run/logs/homebrew_update.log"
check_nogrep 'unreachable server is not "current"' 'Command Line Tools are current' "$L"
check_grep 'unreachable server is "not checked"' 'Apple Software Update server not reachable -- Command Line Tools not checked' "$L"
check_grep 'not checked noted in the SUMMARY' '^\[.*\] Note: Command Line Tools not checked' "$L"

# Offline at 07:00 (dark wake): stop with OFFLINE, run no brew at all.
make_fixture
printf 'github.com\nformulae.brew.sh\nghcr.io\n' > "$S/net_down"
run_script env NETWORK_WAIT=0; rc=$?
L="$fix/run/logs/homebrew_update.log"
check 'offline run exits 1' "$rc" '1'
check_grep 'offline RESULT' 'RESULT: OFFLINE -- no network' "$L"
check 'offline run calls no brew' "$(grep -c . "$S/calls")" '0'
# Network back after the first probe round: brew runs.
make_fixture
: > "$S/casks_outdated"; : > "$S/formulae_outdated"; : > "$S/pinned"
printf 'github.com\nformulae.brew.sh\nghcr.io\n' > "$S/net_down"
echo 3 > "$S/net_up_after"
run_script env NETWORK_WAIT=60 NETWORK_POLL=1; rc=$?
L="$fix/run/logs/homebrew_update.log"
check_grep 'waited for the network' 'No answer from: github.com formulae.brew.sh ghcr.io -- waiting up to 60s' "$L"
check_grep 'network came back' 'Network OK .* after [0-9]+s' "$L"
check_grep 'brew ran once online' '^update' "$S/calls"
check 'network-recovered run exits 0' "$rc" '0'
# Only ghcr.io blocked: reported, brew still runs.
make_fixture
: > "$S/casks_outdated"; : > "$S/formulae_outdated"; : > "$S/pinned"
printf 'ghcr.io\n' > "$S/net_down"
run_script env NETWORK_WAIT=0; rc=$?
L="$fix/run/logs/homebrew_update.log"
check_grep 'partial outage reported' '  - no answer from ghcr.io at the start' "$L"
check_grep 'brew still ran' '^update' "$S/calls"
check 'partial outage exits 2' "$rc" '2'
# Power Nap between probes (CSMB-026: "OFFLINE ... within 1044s" of a 600s
# wait): unbooked clock jumps do not end the wait before its probe rounds.
make_fixture
: > "$S/casks_outdated"; : > "$S/formulae_outdated"; : > "$S/pinned"
printf 'github.com\nformulae.brew.sh\nghcr.io\n' > "$S/net_down"
echo 400 > "$S/net_nap"
echo 6 > "$S/net_up_after"
run_script env NETWORK_WAIT=3 NETWORK_POLL=1; rc=$?
L="$fix/run/logs/homebrew_update.log"
check_nogrep 'Power Nap is not OFFLINE' 'OFFLINE' "$L"
check_grep 'network came back after the naps' 'Network OK .* after [0-9]+s' "$L"
check 'Power Nap run exits 0' "$rc" '0'
# Still down after every round: OFFLINE names the rounds, and a change in
# which hosts fail is logged (CSMB-036: ghcr.io, then all three).
make_fixture
printf 'ghcr.io\n' > "$S/net_down"
cat > "$fix/run/shims/curl" <<EOF
#!/bin/bash
for a in "\$@"; do u="\$a"; done
h="\${u#https://}"
echo "curl \$h" >> "$S/net_calls"
[ "\$(wc -l < "$S/net_calls")" -gt 3 ] && exit 6
[ "\$h" = ghcr.io ] && exit 6
exit 0
EOF
chmod +x "$fix/run/shims/curl"
run_script env NETWORK_WAIT=2 NETWORK_POLL=1; rc=$?
L="$fix/run/logs/homebrew_update.log"
check_grep 'first outage named' 'No answer from: ghcr.io -- waiting up to 2s' "$L"
check_grep 'spread to every host logged' 'Now no host answers \(github.com formulae.brew.sh ghcr.io\)\.' "$L"
check_grep 'OFFLINE counts probe rounds' 'OFFLINE: none of github.com formulae.brew.sh ghcr.io answered at the last of 3 probe rounds, 1s apart' "$L"
check 'spread outage exits 1' "$rc" '1'
check 'spread outage calls no brew' "$(grep -c . "$S/calls")" '0'

# Steps skipped for the budget are "not run", not "failed" (CSMB-011,
# CSPRMB-21-A: "brew upgrade --formula failed", "gem install ... exit 124").
make_fixture
: > "$S/casks_outdated"; : > "$S/pinned"
touch "$S/slow_update"
run_script env RUN_BUDGET=4; rc=$?
L="$fix/run/logs/homebrew_update.log"
check_grep 'skips listed by step' '  - RUN_BUDGET \(4s awake\) used up; not run: formulae, cleanup' "$L"
check_nogrep 'skipped formulae not called failed' 'brew upgrade --formula failed' "$L"
check_nogrep 'skipped cleanup not called failed' 'brew cleanup failed' "$L"
check 'budget-skipped run exits 2' "$rc" '2'

# brew link failures name the formula (ARMB-02 python@3.13, ARMB-09 pkgconf);
# a link-only brew update error is not "brew update failed".
make_fixture
printf 'git\n' > "$S/formulae_outdated"; : > "$S/casks_outdated"; : > "$S/pinned"
touch "$S/link_error" "$S/update_link_error"
run_script env; rc=$?
L="$fix/run/logs/homebrew_update.log"
check_grep 'python@3.13 link failure in SUMMARY' '  - .*: python@3.13 is installed but not linked \(bin/pip3.13 -- .*/bin/pip3.13 already exists\)' "$L"
check_grep 'pkgconf link failure in SUMMARY' '  - .*: pkgconf is installed but not linked \(bin/pkg-config -- .*belongs to pkg-config\)' "$L"
check_nogrep 'link-only update not "update failed"' 'brew update failed' "$L"
check_nogrep 'link-only upgrade not a generic failure' 'brew upgrade --formula failed' "$L"
check 'link failure exits 2' "$rc" '2'

# Untrusted taps: brew ignores what they installed, so not "all current".
make_fixture
printf 'git\n' > "$S/formulae_outdated"; : > "$S/casks_outdated"; : > "$S/pinned"
touch "$S/untrusted"
run_script env; rc=$?
L="$fix/run/logs/homebrew_update.log"
check_grep 'untrusted taps in SUMMARY' '  - .*: untrusted taps \(asmvik/formulae powershell/tap\) -- brew neither upgrades nor lists asmvik/formulae/yabai powershell/tap/powershell' "$L"
check 'untrusted taps exit 2' "$rc" '2'

# Cleanup stopped by a root-owned keg: chown it, run cleanup again (CSMB-020).
make_fixture
: > "$S/casks_outdated"; : > "$S/formulae_outdated"; : > "$S/pinned"
mkdir -p "$P/Cellar/python@3.10/3.10.20"; touch "$S/cleanup_perm"
printf '#!/bin/bash\necho "chown $*" >> "%s/calls"\nrm -f "%s/cleanup_perm"\n' "$S" "$S" > "$fix/run/shims/chown"
chmod +x "$fix/run/shims/chown"
run_script env; rc=$?
L="$fix/run/logs/homebrew_update.log"
check_grep 'root-owned keg chowned' "^chown -R testuser $P/Cellar/python@3.10/3.10.20\$" "$S/calls"
check 'cleanup ran twice' "$(grep -c '^cleanup' "$S/calls")" '2'
check_nogrep 'fixed cleanup is not a problem' 'brew cleanup failed' "$L"
check 'fixed cleanup exits 0' "$rc" '0'

# CASK_SUDO as a list grants sudo only while those casks upgrade.
make_fixture
printf 'firefox\nzoom\n' > "$S/casks_outdated"; : > "$S/formulae_outdated"; : > "$S/pinned"
run_script env CASK_SUDO=zoom; rc=$?
L="$fix/run/logs/homebrew_update.log"
check 'listed cask had sudo' "$(grep -c '^zoom sudoers=y$' "$S/sudo_seen")" '1'
check 'other cask had no sudo' "$(grep -c '^firefox sudoers=n$' "$S/sudo_seen")" '1'
check_grep 'grant names the cask' 'Temporary passwordless sudo granted to testuser for zoom' "$L"
check 'no grant left behind' "$([ -f "$fix/run/sudoers" ] && echo present || echo gone)" 'gone'
check 'CASK_SUDO list run exits 0' "$rc" '0'

# --- v3.2: fleet runs 2026-10-19..11-12 ---
# A sudo cask is not downloaded again at the same installed version
# (jriegel-mac: android-ndk 438s, sage 496s ... every run, all "needs sudo").
make_fixture
printf 'firefox\nzoom\n' > "$S/casks_outdated"; : > "$S/formulae_outdated"; : > "$S/pinned"
mkdir -p "$P/Caskroom/zoom/6.4.0"
run_script env CASK_SUDO=0; rc=$?
L="$fix/run/logs/homebrew_update.log"
check 'first sudo failure tries the cask' "$(grep -c '^upgrade --cask zoom$' "$S/calls")" '1'
check_grep 'sudo failure names CFG_CASK_SUDO' 'FAILED   zoom -- needs sudo \(.pkg installer\) -- add it to CFG_CASK_SUDO$' "$L"
check_grep 'summary gives the CONFIG line' 'set in the CONFIG block: CFG_CASK_SUDO="zoom"' "$L"
check 'memo records cask and version' "$(cat "$fix/run/logs/casks_needing_sudo")" "$P zoom 6.4.0"
: > "$S/calls"; printf 'firefox\n' >> "$S/casks_outdated"
run_script env CASK_SUDO=0; rc=$?
check 'second run does not download it' "$(grep -c '^upgrade --cask zoom$' "$S/calls")" '0'
check 'other casks still upgrade' "$(grep -c '^upgrade --cask firefox$' "$S/calls")" '1'
check_grep 'skipped cask still listed as failed' '  - zoom -- needs sudo .*not downloaded again: 6.4.0 failed the same way last run' "$L"
check 'skipped sudo cask exits 2' "$rc" '2'
check 'memo kept for the skipped cask' "$(cat "$fix/run/logs/casks_needing_sudo")" "$P zoom 6.4.0"
: > "$S/calls"
run_script env CASK_SUDO=zoom; rc=$?
check 'granting sudo tries it again' "$(grep -c '^upgrade --cask zoom$' "$S/calls")" '1'
check 'upgraded cask leaves the memo' "$([ -f "$fix/run/logs/casks_needing_sudo" ] && echo present || echo gone)" 'gone'
check 'sudo cask upgraded exits 0' "$rc" '0'
make_fixture
printf 'zoom\n' > "$S/casks_outdated"; : > "$S/formulae_outdated"; : > "$S/pinned"
mkdir -p "$P/Caskroom/zoom/6.4.1"
echo "$P zoom 6.4.0" > "$fix/run/logs/casks_needing_sudo"
run_script env CASK_SUDO=0; rc=$?
check 'new installed version is tried again' "$(grep -c '^upgrade --cask zoom$' "$S/calls")" '1'
run_script env CASK_SUDO=0 SKIP_KNOWN_SUDO_CASKS=0; rc=$?
check 'SKIP_KNOWN_SUDO_CASKS=0 always tries' "$(grep -c '^upgrade --cask zoom$' "$S/calls")" '2'

# Untrusted taps with nothing installed from them are a Note (CSPRMB-21-A:
# "untrusted taps (ethereum/ethereum microsoft/git) -- ... what they installed").
make_fixture
printf 'git\n' > "$S/formulae_outdated"; : > "$S/casks_outdated"; : > "$S/pinned"
touch "$S/untrusted_unused"
mkdir -p "$P/Library/Taps/ethereum/homebrew-ethereum/Formula" "$P/Library/Taps/microsoft/homebrew-git/Casks"
touch "$P/Library/Taps/ethereum/homebrew-ethereum/Formula/solidity.rb" "$P/Library/Taps/microsoft/homebrew-git/Casks/git-credential-manager.rb"
run_script env; rc=$?
L="$fix/run/logs/homebrew_update.log"
check_nogrep 'unused taps are not a problem' 'untrusted taps \(' "$L"
check_grep 'unused taps are a note' 'Note: .*: untrusted taps with nothing installed from them \(ethereum/ethereum microsoft/git\) .*brew untap ethereum/ethereum microsoft/git' "$L"
check 'unused untrusted taps exit 0' "$rc" '0'
# A cask from an untrusted tap is named even though brew lists only formulae.
mkdir -p "$P/Caskroom/git-credential-manager/2.6.1"
printf 'git\n' > "$S/formulae_outdated"
run_script env; rc=$?
check_grep 'tap cask named with its trust command' '  - .*: untrusted taps \(microsoft/git\) -- brew neither upgrades nor lists microsoft/git/git-credential-manager. As testuser: brew trust --cask microsoft/git/git-credential-manager; or brew untap <tap>' "$L"
check_grep 'the unused one is still a note' 'Note: .*\(ethereum/ethereum\)' "$L"
check 'tap in use exits 2' "$rc" '2'

if [ "$fail" -ne 0 ]; then
  echo "tests failed"
  exit 1
fi
echo "All tests passed"
exit 0
