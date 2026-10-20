# Tests for remove-apple-pages.sh.
# Run: bash macos/tests/remove-apple-pages.test.sh
#
# Unit checks for the version / volume / ps helpers, then end-to-end runs
# against fake PlistBuddy / mdfind / ps / kill / rm / find / stat / id:
#   CSMB-007 shape (Pages 14.x in /Applications) removed -> 0; copies in
#   Downloads, Trash and a renamed Spotlight-only copy removed; a foreign
#   Pages.app kept; running -> 2 unless FORCE_CLOSE; /Volumes copy reported
#   -> 2; App Management / Full Disk Access denials named -> 2; dry run -> 2.
set -u
here=$(cd "$(dirname "$0")" && pwd)
script=$(cd "$here/.." && pwd)/remove-apple-pages.sh

fail=0
check() {
  if [ "$2" != "$3" ]; then printf 'FAIL %s\n got:  %s\n want: %s\n' "$1" "$2" "$3"; fail=1; else echo "OK   $1"; fi
}
check_grep() {
  if grep -qE -- "$2" "$3"; then echo "OK   $1"; else echo "FAIL $1 (no /$2/ in $3)"; fail=1; fi
}
check_nogrep() {
  if grep -qE -- "$2" "$3"; then echo "FAIL $1 (/$2/ found in $3)"; fail=1; else echo "OK   $1"; fi
}
exists() { if [ -e "$1" ]; then echo present; else echo gone; fi; }

# ---------------------------------------------------------------- unit ----
(
  export PAGES_REMOVE_SELFTEST=1
  # shellcheck source=/dev/null
  . "$script"
  ufail=0
  u() { if [ "$2" != "$3" ]; then printf 'FAIL %s\n got:  %s\n want: %s\n' "$1" "$2" "$3"; ufail=1; else echo "OK   $1"; fi; }
  y() { if "$@"; then echo y; else echo n; fi; }

  u '14.4 below 15.1' "$(y version_lt 14.4 15.1)" 'y'
  u '15.0.1 below 15.1' "$(y version_lt 15.0.1 15.1)" 'y'
  u '15.1 not below 15.1' "$(y version_lt 15.1 15.1)" 'n'
  u '15.1.0 not below 15.1' "$(y version_lt 15.1.0 15.1)" 'n'
  u '15.10 not below 15.9' "$(y version_lt 15.10 15.9)" 'n'
  u '16 not below 15.1' "$(y version_lt 16 15.1)" 'n'
  u 'unreadable version counts as below' "$(y version_lt '' 15.1)" 'y'
  u 'garbage version counts as below' "$(y version_lt 'abc' 15.1)" 'y'
  u '/Volumes path is another volume' "$(y on_other_volume '/Volumes/Backup/Applications/Pages.app')" 'y'
  u '/Applications is not' "$(y on_other_volume '/Applications/Pages.app')" 'n'
  u 'TCC denial recognised' "$(echo 'rm: /Applications/Pages.app: Operation not permitted' | y tcc_denied)" 'y'
  u 'other rm error is not TCC' "$(echo 'rm: x: Directory not empty' | y tcc_denied)" 'n'
  ps_out='  311 /Applications/Pages.app/Contents/MacOS/Pages
  312 /Applications/Pages.app/Contents/XPCServices/Helper.xpc/Contents/MacOS/Pages Helper
  313 /Users/mm/Downloads/Pages 2.app/Contents/MacOS/Pages
  314 /Applications/Numbers.app/Contents/MacOS/Numbers'
  u 'main Pages binaries only, renamed bundle included' "$(echo "$ps_out" | pages_pids_from_ps | tr '\n' ' ')" '311 313 '
  exit $ufail
) || fail=1

# ----------------------------------------------------------- end to end ----
fix=$(mktemp -d)
trap 'rm -rf "$fix"' EXIT
real_find=$(command -v find)
real_rm=$(command -v rm)

make_fixture() {
  "$real_rm" -rf "$fix/run"
  mkdir -p "$fix/run/shims" "$fix/run/state" "$fix/run/logs" "$fix/run/Applications" "$fix/run/Users" "$fix/run/Volumes"
  S="$fix/run/state"; A="$fix/run/Applications"; U="$fix/run/Users"; V="$fix/run/Volumes"
  : > "$S/calls"; : > "$S/mdfind"; : > "$S/running"; : > "$S/rm_deny"; : > "$S/find_deny"
  cat > "$fix/run/shims/PlistBuddy" <<'EOF'
#!/bin/bash
key=${2#Print :}
[ -f "$3" ] || exit 1
sed -n "s/^$key=//p" "$3" | grep . || exit 1
EOF
  printf '#!/bin/bash\ncat "%s/mdfind"\n' "$S" > "$fix/run/shims/mdfind"
  printf '#!/bin/bash\ncat "%s/running"\n' "$S" > "$fix/run/shims/ps"
  cat > "$fix/run/shims/kill" <<EOF
#!/bin/bash
echo "kill \$*" >> "$S/calls"
pid=\${!#}
[ -f "$S/stubborn" ] && exit 0
grep -v "^ *\$pid " "$S/running" > "$S/running.new"; mv "$S/running.new" "$S/running"
EOF
  printf '#!/bin/bash\nexit 0\n' > "$fix/run/shims/sleep"
  printf '#!/bin/bash\necho mmerino\n' > "$fix/run/shims/stat"
  printf '#!/bin/bash\necho 501\n' > "$fix/run/shims/id"
  printf '#!/bin/bash\necho "launchctl $*" >> "%s/calls"\n' "$S" > "$fix/run/shims/launchctl"
  printf '#!/bin/bash\necho "chflags $*" >> "%s/calls"\n' "$S" > "$fix/run/shims/chflags"
  cat > "$fix/run/shims/rm" <<EOF
#!/bin/bash
for a in "\$@"; do
  if [ -n "\$a" ] && grep -qxF -- "\$a" "$S/rm_deny"; then echo "rm: \$a: Operation not permitted" >&2; exit 1; fi
done
exec "$real_rm" "\$@"
EOF
  cat > "$fix/run/shims/find" <<EOF
#!/bin/bash
while IFS= read -r d; do [ -n "\$d" ] && echo "find: \$d: Operation not permitted" >&2; done < "$S/find_deny"
exec "$real_find" "\$@"
EOF
  chmod +x "$fix/run/shims/"*
}
pages_app() {  # path version [bundle id]
  mkdir -p "$1/Contents/MacOS"
  printf 'CFBundleIdentifier=%s\nCFBundleShortVersionString=%s\n' "${3:-com.apple.iWork.Pages}" "$2" > "$1/Contents/Info.plist"
}
# kill is a bash builtin, so a PATH shim never runs; export a function instead.
run_script() (
  kill() { "$fix/run/shims/kill" "$@"; }
  export -f kill
  export fix
  PATH="$fix/run/shims:$PATH" PLISTBUDDY="$fix/run/shims/PlistBuddy" LOG_DIR="$fix/run/logs" \
    SEARCH_ROOTS="$A $U" VOLUMES_PREFIX="$V/" "$@" bash "$script" >/dev/null 2>&1
)
L="$fix/run/logs/remove_apple_pages.log"

# CSMB-007: Pages below 15.1 in /Applications.
make_fixture; pages_app "$A/Pages.app" 14.4
run_script env; rc=$?
check 'CSMB-007 shape removed -> 0' "$rc" '0'
check '/Applications/Pages.app gone' "$(exists "$A/Pages.app")" 'gone'
check_grep 'result says removed' 'RESULT: Apple Pages removed\.' "$L"

make_fixture
run_script env; rc=$?
check 'not installed -> 0' "$rc" '0'
check_grep 'not installed says so' 'RESULT: nothing to remove\.' "$L"

# Copies v1 missed: nested Downloads folder, Trash, renamed Spotlight-only copy.
make_fixture
pages_app "$U/mmerino/Downloads/old apps/Pages.app" 13.2
pages_app "$U/mmerino/.Trash/Pages.app" 14.0
pages_app "$fix/run/elsewhere/Pages 2.app" 12.1
echo "$fix/run/elsewhere/Pages 2.app" > "$S/mdfind"
run_script env; rc=$?
check 'scattered copies removed -> 0' "$rc" '0'
check 'nested Downloads copy gone' "$(exists "$U/mmerino/Downloads/old apps/Pages.app")" 'gone'
check 'Trash copy gone' "$(exists "$U/mmerino/.Trash/Pages.app")" 'gone'
check 'renamed Spotlight-only copy gone' "$(exists "$fix/run/elsewhere/Pages 2.app")" 'gone'

# Found by both Spotlight and the walk: listed once.
make_fixture; pages_app "$A/Pages.app" 14.4; echo "$A/Pages.app" > "$S/mdfind"
run_script env; rc=$?
check 'duplicate discovery listed once' "$(grep -c 'at .*/Applications/Pages.app (will remove)' "$L")" '1'

# Copies inside ~/Library are not walked (containers, caches).
make_fixture; pages_app "$U/mmerino/Library/Containers/x/Pages.app" 14.4
run_script env; rc=$?
check 'Library not walked' "$(exists "$U/mmerino/Library/Containers/x/Pages.app")" 'present'

make_fixture; pages_app "$A/Pages.app" 1.0 com.example.pages
run_script env; rc=$?
check 'foreign Pages.app -> 0' "$rc" '0'
check 'foreign Pages.app kept' "$(exists "$A/Pages.app")" 'present'
check_grep 'foreign Pages.app logged' "SKIPPING .*Pages.app \(bundle id 'com.example.pages'" "$L"

make_fixture; pages_app "$A/Pages.app" 14.4
echo "  311 $A/Pages.app/Contents/MacOS/Pages" > "$S/running"
run_script env; rc=$?
check 'running -> 2' "$rc" '2'
check 'running copy kept' "$(exists "$A/Pages.app")" 'present'
check_grep 'running named in Problems' '  - Pages is running \(pid 311\)' "$L"
run_script env FORCE_CLOSE=1; rc=$?
check 'FORCE_CLOSE=1 quits and removes -> 0' "$rc" '0'
check 'FORCE_CLOSE copy gone' "$(exists "$A/Pages.app")" 'gone'
check_grep 'graceful quit asked as console user' '^launchctl asuser 501 sudo -u mmerino /usr/bin/osascript' "$S/calls"

make_fixture; pages_app "$A/Pages.app" 14.4; touch "$S/stubborn"
echo "  311 $A/Pages.app/Contents/MacOS/Pages" > "$S/running"
run_script env FORCE_CLOSE=1; rc=$?
check 'Pages will not quit -> 2' "$rc" '2'
check 'unquittable copy kept' "$(exists "$A/Pages.app")" 'present'
check_grep 'kill -9 tried' '^kill -9 311' "$S/calls"

# KEEP_FROM_VERSION keeps fixed copies and removes old ones.
make_fixture; pages_app "$A/Pages.app" 15.1; pages_app "$U/mmerino/Applications/Pages.app" 14.4
run_script env KEEP_FROM_VERSION=15.1; rc=$?
check 'KEEP_FROM_VERSION -> 0' "$rc" '0'
check '15.1 copy kept' "$(exists "$A/Pages.app")" 'present'
check '14.4 copy removed' "$(exists "$U/mmerino/Applications/Pages.app")" 'gone'
run_script env; rc=$?
check 'default removes the 15.1 copy too' "$(exists "$A/Pages.app")" 'gone'

make_fixture; pages_app "$V/Backup/Applications/Pages.app" 14.4
echo "$V/Backup/Applications/Pages.app" > "$S/mdfind"
run_script env; rc=$?
check 'other-volume copy -> 2' "$rc" '2'
check 'other-volume copy not deleted' "$(exists "$V/Backup/Applications/Pages.app")" 'present'
check_grep 'other-volume copy in Problems' '  - .*Volumes/Backup/Applications/Pages.app \(Pages 14.4\) is on another volume' "$L"

# App Management refuses the delete.
make_fixture; pages_app "$A/Pages.app" 14.4; echo "$A/Pages.app" > "$S/rm_deny"
run_script env; rc=$?
check 'App Management denial -> 2' "$rc" '2'
check_grep 'App Management named' 'Operation not permitted\. Grant the Mosyle agent App Management' "$L"
check_grep 'immutable-flag retry ran' "^chflags -R nouchg,noschg $A/Pages.app" "$S/calls"
check "denial not double-reported" "$(grep -c 'still present after removal' "$L")" '0'

# Full Disk Access missing: a folder could not be searched.
make_fixture; echo "$U/mmerino/Desktop" > "$S/find_deny"
run_script env; rc=$?
check 'unsearchable folder -> 2' "$rc" '2'
check_grep 'Full Disk Access named' 'refused to let this run search: .*mmerino/Desktop\. Grant the Mosyle agent Full Disk Access' "$L"

make_fixture; pages_app "$A/Pages.app" 14.4
run_script env DRY_RUN=1; rc=$?
check 'dry run with work -> 2' "$rc" '2'
check 'dry run removes nothing' "$(exists "$A/Pages.app")" 'present'
check_grep 'dry run says what it would do' '\[DRY_RUN\] Would remove .*Applications/Pages.app' "$L"
make_fixture
run_script env DRY_RUN=1; rc=$?
check 'dry run with nothing to do -> 0' "$rc" '0'

make_fixture; pages_app "$A/Pages.app" 14.4
run_script env PLISTBUDDY=/nonexistent/PlistBuddy; rc=$?
check 'no PlistBuddy -> 1' "$rc" '1'
check 'no PlistBuddy removes nothing' "$(exists "$A/Pages.app")" 'present'

if [ "$fail" -ne 0 ]; then echo "tests failed"; exit 1; fi
echo "All tests passed"
exit 0
