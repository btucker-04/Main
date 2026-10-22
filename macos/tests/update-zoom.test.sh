# Tests for update-zoom.sh.
# Run: bash macos/tests/update-zoom.test.sh
#
# Unit checks for the version / signature helpers, then end-to-end runs
# against fake curl / defaults / pkgutil / installer / pgrep:
#   csprmb-15-a shape (7.1.0 < latest) upgrades and verifies -> 0; current
#   -> 0 with no download; meeting -> defer 2; bad signature -> 1; installer
#   "succeeds" without changing the app -> 2; old per-user copy removed only
#   after the machine copy is verified.
set -u
here=$(cd "$(dirname "$0")" && pwd)
script=$(cd "$here/.." && pwd)/update-zoom.sh

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

# ---------------------------------------------------------------- unit ----
(
  export ZOOM_UPDATE_SELFTEST=1
  # shellcheck source=/dev/null
  . "$script"
  ufail=0
  u() { if [ "$2" != "$3" ]; then printf 'FAIL %s\n got:  %s\n want: %s\n' "$1" "$2" "$3"; ufail=1; else echo "OK   $1"; fi; }
  y() { if "$@"; then echo y; else echo n; fi; }

  u 'version from CDN url' "$(version_from_url https://cdn.zoom.us/prod/7.2.2.88465/ZoomInstallerIT.pkg)" '7.2.2.88465'
  u 'no version in latest url' "$(version_from_url https://zoom.us/client/latest/ZoomInstallerIT.pkg)" ''
  u 'CFBundleVersion' "$(normalize_zoom_version 7.1.5.70120)" '7.1.5.70120'
  u 'short version with build' "$(normalize_zoom_version '7.1.5 (70120)')" '7.1.5.70120'
  u 'short version without build' "$(normalize_zoom_version '7.0.6')" '7.0.6'
  u 'garbage version' "$(normalize_zoom_version 'unknown')" ''
  u '7.1.0 below 7.2.2' "$(y version_ge 7.1.0.60000 7.2.2.88465)" 'n'
  u '7.2.2 build equal' "$(y version_ge 7.2.2.88465 7.2.2.88465)" 'y'
  u 'newer build is current' "$(y version_ge 7.2.2.90000 7.2.2.88465)" 'y'
  u 'older build is not' "$(y version_ge 7.2.2.80000 7.2.2.88465)" 'n'
  u 'no build compares on N.N.N' "$(y version_ge 7.2.2 7.2.2.88465)" 'y'
  u 'bare build number is not a version' "$(y is_full_version 88465)" 'n'
  u 'N.N.N.build is a version' "$(y is_full_version 7.2.2.88465)" 'y'
  u '7.10 above 7.9' "$(y version_ge 7.10.0.1 7.9.9.9)" 'y'
  # CSPRMB-15-A (2026-10-22): the 7.2.2.88465 package is signed as "Zoom
  # Communications, Inc."; v1 matched the old company name and refused it.
  good='Package "ZoomInstallerIT.pkg":
   Status: signed by a developer certificate issued by Apple for distribution
   Notarization: trusted by the Apple notary service
   Signed with a trusted timestamp on: 2026-10-01 18:21:12 +0000
   Certificate Chain:
    1. Developer ID Installer: Zoom Communications, Inc. (BJ4HAAB9B3)
       Expires: 2030-02-15 20:04:50 +0000
    2. Developer ID Certification Authority
       Expires: 2031-09-17 00:00:00 +0000
    3. Apple Root CA
       Expires: 2035-02-09 21:40:36 +0000'
  u 'CSPRMB-15-A: renamed Zoom signer accepted' "$(echo "$good" | y signature_is_zoom)" 'y'
  u 'signer name extracted' "$(echo "$good" | signer_from_pkgutil)" 'Developer ID Installer: Zoom Communications, Inc. (BJ4HAAB9B3)'
  u 'old Zoom company name still accepted' "$(echo "$good" | sed 's/Zoom Communications/Zoom Video Communications/' | y signature_is_zoom)" 'y'
  u 'Zoom name with another team ID refused' "$(echo "$good" | sed 's/BJ4HAAB9B3/ABCDE12345/' | y signature_is_zoom)" 'n'
  u 'team ID inside a longer name refused' "$(echo "$good" | sed 's/(BJ4HAAB9B3)/(BJ4HAAB9B3) Evil/' | y signature_is_zoom)" 'n'
  u 'Developer ID Application cert refused' "$(echo "$good" | sed 's/Developer ID Installer: Zoom/Developer ID Application: Zoom/' | y signature_is_zoom)" 'n'
  u 'not issued by Apple refused' "$(echo "$good" | sed 's/issued by Apple for distribution/self-signed/' | y signature_is_zoom)" 'n'
  u 'unsigned refused' "$(printf 'Package "x.pkg":\n   Status: no signature\n' | y signature_is_zoom)" 'n'
  exit $ufail
) || fail=1

# ----------------------------------------------------------- end to end ----
fix=$(mktemp -d)
trap 'rm -rf "$fix"' EXIT

make_fixture() {
  rm -rf "$fix/run"; mkdir -p "$fix/run/shims" "$fix/run/state" "$fix/run/logs" "$fix/run/Applications" "$fix/run/Users"
  S="$fix/run/state"; A="$fix/run/Applications"
  : > "$S/calls"
  echo 7.2.2.88465 > "$S/latest"
  echo 7.2.2.88465 > "$S/installs"
  echo good > "$S/signature"
  : > "$S/running"
  printf '#!/bin/bash\necho 15.7\n' > "$fix/run/shims/sw_vers"
  cat > "$fix/run/shims/defaults" <<'EOF'
#!/bin/bash
[ "$1" = read ] || exit 1
sed -n "s/^$3=//p" "$2" | grep . || exit 1
EOF
  cat > "$fix/run/shims/curl" <<EOF
#!/bin/bash
echo "curl \$*" >> "$S/calls"
case " \$* " in
  *" -sIL "*) printf 'https://cdn.zoom.us/prod/%s/ZoomInstallerIT.pkg' "\$(cat "$S/latest")"; exit 0 ;;
esac
while [ \$# -gt 0 ]; do [ "\$1" = -o ] && { echo pkg > "\$2"; exit 0; }; shift; done
exit 1
EOF
  cat > "$fix/run/shims/pkgutil" <<EOF
#!/bin/bash
if [ "\$(cat "$S/signature")" = good ]; then
  printf '%s\n' 'Package "ZoomInstallerIT.pkg":' '   Status: signed by a developer certificate issued by Apple for distribution' \
    '    1. Developer ID Installer: Zoom Communications, Inc. (BJ4HAAB9B3)'
elif [ "\$(cat "$S/signature")" = other ]; then
  printf '%s\n' 'Package "ZoomInstallerIT.pkg":' '   Status: signed by a developer certificate issued by Apple for distribution' \
    '    1. Developer ID Installer: Evil LLC (ABCDE12345)'
else
  printf '%s\n' 'Package "ZoomInstallerIT.pkg":' '   Status: no signature'
fi
EOF
  cat > "$fix/run/shims/installer" <<EOF
#!/bin/bash
echo "installer \$*" >> "$S/calls"
v=\$(cat "$S/installs")
[ -n "\$v" ] && { mkdir -p "$A/zoom.us.app/Contents"; echo "CFBundleVersion=\$v" > "$A/zoom.us.app/Contents/Info.plist"; }
echo "installer: The upgrade was successful."
exit 0
EOF
  cat > "$fix/run/shims/pgrep" <<EOF
#!/bin/bash
case "\$1" in
  -x) grep -qx "\$2" "$S/running" ;;
  -f) grep -qF "\$2" "$S/running" ;;
  *) exec /usr/bin/pgrep "\$@" ;;
esac
EOF
  chmod +x "$fix/run/shims/"*
}
zoom_app() {  # dir version
  mkdir -p "$1/zoom.us.app/Contents"; echo "CFBundleVersion=$2" > "$1/zoom.us.app/Contents/Info.plist"
}
run_script() {
  PATH="$fix/run/shims:$PATH" APP_DIR="$A" USERS_DIR="$fix/run/Users" LOG_DIR="$fix/run/logs" \
    WORK_DIR="$fix/run/work" "$@" bash "$script" >/dev/null 2>&1
}
L="$fix/run/logs/zoom_update.log"

# csprmb-15-a: 7.1.0 is below 7.0.6 / 7.1.5 and below the current release.
make_fixture; zoom_app "$A" 7.1.0.60000
run_script env; rc=$?
check 'old Zoom upgraded and verified -> 0' "$rc" '0'
check_grep 'installer ran on the IT package' '^installer -pkg .*/ZoomInstallerIT.pkg -target /$' "$S/calls"
check_grep 'downloaded the resolved CDN url' 'curl .*https://cdn.zoom.us/prod/7.2.2.88465/ZoomInstallerIT.pkg' "$S/calls"
check_grep 'verified version logged' 'zoom.us.app  7.2.2.88465  OK' "$L"
check 'work dir cleaned up' "$([ -e "$fix/run/work" ] && echo present || echo gone)" 'gone'
cp "$L" "$fix/good.log"

make_fixture; zoom_app "$A" 7.2.2.88465
run_script env; rc=$?
check 'current Zoom -> 0' "$rc" '0'
check_nogrep 'current Zoom downloads nothing' '^curl -fsSL' "$S/calls"
check_nogrep 'current Zoom installs nothing' '^installer' "$S/calls"

# CFBundleVersion holding only a build number falls back to the short version.
make_fixture; mkdir -p "$A/zoom.us.app/Contents"
printf 'CFBundleVersion=88465\nCFBundleShortVersionString=7.1.0 (60000)\n' > "$A/zoom.us.app/Contents/Info.plist"
run_script env; rc=$?
check_grep 'short version used over a bare build number' 'zoom.us.app  7.1.0.60000$' "$L"
check_grep 'bare build number still upgraded' '^installer -pkg' "$S/calls"

make_fixture
run_script env; rc=$?
check 'no Zoom -> 0' "$rc" '0'
check_grep 'no Zoom says so' 'Zoom is not installed' "$L"

make_fixture; zoom_app "$A" 7.1.0.60000; echo CptHost > "$S/running"
run_script env; rc=$?
check 'meeting defers -> 2' "$rc" '2'
check_nogrep 'meeting: no install' '^installer' "$S/calls"
check_grep 'meeting named' 'meeting is in progress \(CptHost\)' "$L"
run_script env FORCE_CLOSE=1; rc=$?
check 'FORCE_CLOSE=1 installs during a meeting' "$rc" '0'

make_fixture; zoom_app "$A" 7.1.0.60000; echo bad > "$S/signature"
run_script env; rc=$?
check 'bad signature -> 1' "$rc" '1'
check_nogrep 'bad signature: no install' '^installer' "$S/calls"
check_grep 'unsigned: pkgutil output logged' 'Status: no signature' "$L"

make_fixture; zoom_app "$A" 7.1.0.60000; echo other > "$S/signature"
run_script env; rc=$?
check 'other team ID -> 1' "$rc" '1'
check_nogrep 'other team ID: no install' '^installer' "$S/calls"
check_grep 'signer named in the problem' 'team BJ4HAAB9B3\); signer: Developer ID Installer: Evil LLC \(ABCDE12345\)' "$L"
check_grep 'good run logs the renamed signer' 'Signature: Developer ID Installer: Zoom Communications, Inc. \(BJ4HAAB9B3\)' "$fix/good.log"

# installer exits 0 but the app did not change: must not report success.
make_fixture; zoom_app "$A" 7.1.0.60000; : > "$S/installs"
run_script env; rc=$?
check 'unchanged app after installer exit 0 -> 2' "$rc" '2'
check_grep 'not verified in the summary' '  - after install .*zoom.us.app is 7.1.0.60000, not 7.2.2.88465' "$L"

make_fixture; zoom_app "$A" 7.1.0.60000; echo "" > "$S/latest"
run_script env; rc=$?
check 'latest unknown -> 1' "$rc" '1'

make_fixture; zoom_app "$A" 7.1.0.60000
run_script env DRY_RUN=1; rc=$?
check 'dry run -> 2' "$rc" '2'
check_nogrep 'dry run installs nothing' '^installer' "$S/calls"

# Old per-user copy: machine copy installed first, then the user copy goes.
make_fixture; zoom_app "$fix/run/Users/mmerino/Applications" 7.0.5.50000
run_script env; rc=$?
check 'per-user only: machine install then removal -> 0' "$rc" '0'
check_grep 'machine copy installed for the per-user case' '^installer -pkg' "$S/calls"
check 'old per-user copy removed' "$([ -e "$fix/run/Users/mmerino/Applications/zoom.us.app" ] && echo present || echo gone)" 'gone'

make_fixture; zoom_app "$A" 7.2.2.88465; zoom_app "$fix/run/Users/mmerino/Applications" 7.0.5.50000
echo "$fix/run/Users/mmerino/Applications/zoom.us.app/Contents/MacOS/zoom.us" > "$S/running"
run_script env; rc=$?
check 'running per-user copy kept -> 2' "$rc" '2'
check 'running per-user copy still there' "$([ -e "$fix/run/Users/mmerino/Applications/zoom.us.app" ] && echo present || echo gone)" 'present'

make_fixture; zoom_app "$A" 7.2.2.88465; zoom_app "$fix/run/Users/mmerino/Applications" 7.0.5.50000
run_script env REMOVE_USER_COPIES=0; rc=$?
check 'REMOVE_USER_COPIES=0 reports -> 2' "$rc" '2'
check_grep 'kept copy listed' '  - .*mmerino/Applications/zoom.us.app is 7.0.5.50000' "$L"

# Machine install fails verification: the per-user copy must survive.
make_fixture; zoom_app "$A" 7.1.0.60000; zoom_app "$fix/run/Users/mmerino/Applications" 7.0.5.50000; : > "$S/installs"
run_script env; rc=$?
check 'unverified machine copy -> 2' "$rc" '2'
check 'user copy kept when machine copy unverified' "$([ -e "$fix/run/Users/mmerino/Applications/zoom.us.app" ] && echo present || echo gone)" 'present'

if [ "$fail" -ne 0 ]; then echo "tests failed"; exit 1; fi
echo "All tests passed"
exit 0
