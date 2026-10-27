# Tests for update-wireshark.sh.
# Run: bash macos/tests/update-wireshark.test.sh
#
# Unit checks for the appcast parser, target choice and signature check
# against Wireshark's real feeds (2026-10-27), then end-to-end runs against
# fake curl / hdiutil / codesign / ditto / defaults / pgrep / mdfind:
#   csmb-059 shape (4.6.x < 4.6.9) replaced and verified -> 0; current -> 0
#   with no download; running -> defer 2 (FORCE_CLOSE=1 stops it); size,
#   SHA-256, DMG version and team ID mismatches -> 1 with nothing changed;
#   per-user copy updated with its owner kept; Spotlight copy elsewhere
#   reported -> 2; dry run -> 2; feed down -> 1.
set -u
here=$(cd "$(dirname "$0")" && pwd)
script=$(cd "$here/.." && pwd)/update-wireshark.sh

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

# https://www.wireshark.org/update/0/Wireshark/4.6.3/macOS/x86-64/en-US/stable.xml
# on 2026-10-27. The arm64 feed is the same without the 4.4.19 item.
FEED_X86='<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">
<channel>
  <title>Wireshark Stable Release</title>
  <link>https://www.wireshark.org/download.html</link>
  <description>The latest stable release of Wireshark.</description>
  <language>en</language>
  <item>
    <title>Version 4.6.9</title>
    <sparkle:minimumSystemVersion>12.0.0</sparkle:minimumSystemVersion>
    <pubDate>Wed, 23 Sep 2026 20:03:42 GMT</pubDate>
    <sparkle:releaseNotesLink>https://www.wireshark.org/update/relnotes/wireshark-4.6.9.html</sparkle:releaseNotesLink>
    <enclosure
      url="https://2.na.dl.wireshark.org/osx/all-versions/Wireshark%204.6.9.dmg"
      sparkle:version="4.6.9" sparkle:shortVersionString="4.6.9"
      sparkle:edSignature="VBYwF2s5vthtIm2og37JqOjvQYYwCpwFtnhafQ9kSvoA0dKtEwecmwOn69+UI6fMSHq/GMuV9JWJqsQmVDISCA==" length="147277050"
      type="application/octet-stream"/>
      <!-- SHA256: 10bd54ccdc3f40457f6a1f0c517bc93703fcb327c4cd4b93002e7a623dacbf38 -->
  </item>
  <item>
    <title>Version 4.4.19</title>
    <sparkle:minimumSystemVersion>11.0.0</sparkle:minimumSystemVersion>
    <pubDate>Wed, 23 Sep 2026 20:04:09 GMT</pubDate>
    <sparkle:releaseNotesLink>https://www.wireshark.org/update/relnotes/wireshark-4.4.19.html</sparkle:releaseNotesLink>
    <enclosure
      url="https://2.na.dl.wireshark.org/osx/all-versions/Wireshark%204.4.19%20Intel%2064.dmg"
      sparkle:version="4.4.19" sparkle:shortVersionString="4.4.19"
      sparkle:edSignature="0l7w6uhwTWzFY/PZh4rnk1tiHvnb0kQig8Hw+ScxRyh6lOjMMUXCcjeznuSWxsQTYT4zb4in1zynA+7936ieCw==" length="69692482"
      type="application/octet-stream"/>
      <!-- SHA256: a16288f645e7dfc471ed62bf93f63caa7cdf73e83b711ae7b496d46b27900a92 -->
  </item>
</channel>
</rss>'
FEED_ARM=$(printf '%s\n' "$FEED_X86" | awk '/^  <item>/ { n++ } n == 2 { if (/^  <\/item>/) n++; next } { print }')

# Wireshark 4.6.9's `codesign -dv --verbose=2` (fields as macOS prints them).
SIG_GOOD='Executable=/Volumes/Wireshark 4.6.9/Wireshark.app/Contents/MacOS/Wireshark
Identifier=org.wireshark.Wireshark
Format=app bundle with Mach-O universal (x86_64 arm64)
CodeDirectory v=20500 size=1234 flags=0x10000(runtime) hashes=27+7 location=embedded
Signature size=9035
Authority=Developer ID Application: Wireshark Foundation (7Z6EMTD2C6)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
Timestamp=Sep 23, 2026 at 3:55:10 PM
Info.plist entries=33
TeamIdentifier=7Z6EMTD2C6
Runtime Version=15.0.0
Sealed Resources version=2 rules=13 files=2410
Internal requirements count=1 size=220'

# ---------------------------------------------------------------- unit ----
(
  export WIRESHARK_UPDATE_SELFTEST=1
  # shellcheck source=/dev/null
  . "$script"
  ufail=0
  u() { if [ "$2" != "$3" ]; then printf 'FAIL %s\n got:  %s\n want: %s\n' "$1" "$2" "$3"; ufail=1; else echo "OK   $1"; fi; }
  y() { if "$@"; then echo y; else echo n; fi; }

  X86=$(printf '%s\n' "$FEED_X86" | appcast_items)
  ARM=$(printf '%s\n' "$FEED_ARM" | appcast_items)
  u 'x86-64 feed: two items' "$(printf '%s\n' "$X86" | wc -l | tr -d ' ')" '2'
  u 'x86-64 feed: 4.6.9 parsed' "$(printf '%s\n' "$X86" | head -n 1)" \
    '4.6.9|12.0.0|https://2.na.dl.wireshark.org/osx/all-versions/Wireshark%204.6.9.dmg|10bd54ccdc3f40457f6a1f0c517bc93703fcb327c4cd4b93002e7a623dacbf38|147277050'
  u 'x86-64 feed: 4.4.19 parsed' "$(printf '%s\n' "$X86" | tail -n 1)" \
    '4.4.19|11.0.0|https://2.na.dl.wireshark.org/osx/all-versions/Wireshark%204.4.19%20Intel%2064.dmg|a16288f645e7dfc471ed62bf93f63caa7cdf73e83b711ae7b496d46b27900a92|69692482'
  u 'arm64 feed: 4.6.9 only' "$(printf '%s\n' "$ARM" | cut -d'|' -f1 | tr '\n' ' ')" '4.6.9 '
  u 'uppercase SHA lowered' "$(printf '<item>\n<enclosure url="u" sparkle:version="1.2.3" length="5"/>\n<!-- SHA256: ABCDEF -->\n</item>\n' | appcast_items)" '1.2.3||u|abcdef|5'
  u 'item without url skipped' "$(printf '<item>\n<title>x</title>\n</item>\n' | appcast_items)" ''

  t() { printf '%s\n' "$1" | pick_target "$2" "$3" | cut -d'|' -f1; }
  u 'csmb-059: 4.6.3 -> 4.6.9' "$(t "$ARM" 4.6.3 15.7)" '4.6.9'
  u '4.4 branch on Intel stays on 4.4' "$(t "$X86" 4.4.10 14.6)" '4.4.19'
  u 'retired 4.2 moves to the newest' "$(t "$X86" 4.2.14 14.6)" '4.6.9'
  u 'no installed version -> newest' "$(t "$X86" '' 14.6)" '4.6.9'
  u 'macOS 11 cannot run 4.6 -> 4.4.19' "$(t "$X86" 4.6.3 11.7.10)" '4.4.19'
  u 'macOS 11 on Apple silicon: nothing' "$(t "$ARM" 4.6.3 11.7.10; echo "rc=$?")" 'rc=1'
  u 'macOS 12.0 meets 12.0.0' "$(t "$ARM" 4.6.3 12.0)" '4.6.9'
  u '4.6.10 above 4.6.9' "$(y version_ge 4.6.10 4.6.9)" 'y'
  u '4.6.3 below 4.6.9' "$(y version_ge 4.6.3 4.6.9)" 'n'
  u 'equal is current' "$(y version_ge 4.6.9 4.6.9)" 'y'
  u '12.0 equals 12.0.0' "$(y version_ge 12.0 12.0.0)" 'y'
  u '11.7.10 below 12.0.0' "$(y version_ge 11.7.10 12.0.0)" 'n'
  u '4.10 above 4.9.20' "$(y version_ge 4.10 4.9.20)" 'y'
  u 'garbage is not a version' "$(y is_version '4.6.9 (v4.6.9-0-g1)')" 'n'

  u 'Wireshark Foundation signature accepted' "$(echo "$SIG_GOOD" | y signature_is_wireshark)" 'y'
  u 'other team ID refused' "$(echo "$SIG_GOOD" | sed 's/7Z6EMTD2C6/ABCDE12345/g' | y signature_is_wireshark)" 'n'
  u 'team ID only on the Authority line refused' "$(echo "$SIG_GOOD" | sed 's/^TeamIdentifier=.*/TeamIdentifier=ABCDE12345/' | y signature_is_wireshark)" 'n'
  u 'ad-hoc signature refused' "$(printf 'Identifier=org.wireshark.Wireshark\nSignature=adhoc\nTeamIdentifier=not set\n' | y signature_is_wireshark)" 'n'
  u 'Apple Development cert refused' "$(echo "$SIG_GOOD" | sed 's/Developer ID Application:/Apple Development:/' | y signature_is_wireshark)" 'n'
  exit $ufail
) || fail=1

# ----------------------------------------------------------- end to end ----
fix=$(mktemp -d)
trap 'rm -rf "$fix"' EXIT

# Feed whose 4.6.9 item points at the fake DMG: real layout, real URL, the
# fake file's size and SHA-256.
write_feed() {  # x86|arm
  dmg_len=$(wc -c < "$S/dmg" | tr -d ' ')
  dmg_sha=$(sha256sum "$S/dmg" | cut -d' ' -f1)
  if [ "$1" = x86 ]; then f="$FEED_X86"; else f="$FEED_ARM"; fi
  printf '%s\n' "$f" | sed -e "s/length=\"147277050\"/length=\"$dmg_len\"/" \
    -e "s/10bd54ccdc3f40457f6a1f0c517bc93703fcb327c4cd4b93002e7a623dacbf38/$dmg_sha/" > "$S/feed.xml"
}

make_fixture() {
  rm -rf "$fix/run"; mkdir -p "$fix/run/shims" "$fix/run/state" "$fix/run/logs" "$fix/run/Applications" "$fix/run/Users"
  S="$fix/run/state"; A="$fix/run/Applications"; export S
  : > "$S/calls"
  echo 'fake wireshark dmg' > "$S/dmg"
  echo 4.6.9 > "$S/dmg_version"
  echo good > "$S/signature"
  : > "$S/running"
  : > "$S/mdfind"
  : > "$S/running_during_download"
  write_feed arm
  printf '#!/bin/bash\necho 15.7\n' > "$fix/run/shims/sw_vers"
  printf '#!/bin/bash\n[ "$2" = hw.optional.arm64 ] && echo 1\n' > "$fix/run/shims/sysctl"
  cat > "$fix/run/shims/stat" <<EOF
#!/bin/bash
[ "\$1 \$2" = "-f %Su:%Sg" ] && { o="\$3/.owner"; [ -f "\$o" ] && cat "\$o" || echo root:admin; exit 0; }
exec /usr/bin/stat "\$@"
EOF
  cat > "$fix/run/shims/chown" <<EOF
#!/bin/bash
echo "chown \$*" >> "$S/calls"
[ "\$1" = -R ] && echo "\$2" > "\$3/.owner"
exit 0
EOF
  cat > "$fix/run/shims/defaults" <<'EOF'
#!/bin/bash
[ "$1" = read ] || exit 1
sed -n "s/^$3=//p" "$2" | grep . || exit 1
EOF
  cat > "$fix/run/shims/curl" <<EOF
#!/bin/bash
echo "curl \$*" >> "$S/calls"
out=""; url=""
while [ \$# -gt 0 ]; do case "\$1" in -o) out="\$2"; shift ;; http*) url="\$1" ;; esac; shift; done
case "\$url" in
  *stable.xml) [ -e "$S/feed_down" ] && exit 22; cp "$S/feed.xml" "\$out" ;;
  *.dmg) [ -s "$S/running_during_download" ] && cat "$S/running_during_download" >> "$S/running"
         cp "$S/dmg" "\$out"; [ -e "$S/tamper" ] && echo x >> "\$out" ;;
  *) exit 22 ;;
esac
exit 0
EOF
  cat > "$fix/run/shims/shasum" <<'EOF'
#!/bin/bash
[ "$1 $2" = "-a 256" ] || exit 1
exec sha256sum "$3"
EOF
  cat > "$fix/run/shims/hdiutil" <<EOF
#!/bin/bash
echo "hdiutil \$*" >> "$S/calls"
case "\$1" in
  attach)
    mp=""; while [ \$# -gt 0 ]; do [ "\$1" = -mountpoint ] && mp="\$2"; shift; done
    mkdir -p "\$mp/Wireshark.app/Contents/MacOS"
    echo "CFBundleShortVersionString=\$(cat "$S/dmg_version")" > "\$mp/Wireshark.app/Contents/Info.plist"
    echo bin > "\$mp/Wireshark.app/Contents/MacOS/Wireshark"
    echo "/dev/disk4s1  Apple_HFS  \$mp" ;;
  detach) rm -rf "\${@: -1}" ;;
esac
exit 0
EOF
  cat > "$fix/run/shims/codesign" <<EOF
#!/bin/bash
echo "codesign \$*" >> "$S/calls"
sig=\$(cat "$S/signature")
case "\$1" in
  --verify) [ "\$sig" = broken ] && { echo 'a sealed resource is missing or invalid' >&2; exit 1; }; exit 0 ;;
  -dv)
    if [ "\$sig" = other ]; then
      printf '%s\n' 'Identifier=org.wireshark.Wireshark' 'Authority=Developer ID Application: Evil LLC (ABCDE12345)' 'TeamIdentifier=ABCDE12345' >&2
    else
      printf '%s\n' "$SIG_GOOD" >&2
    fi ;;
esac
exit 0
EOF
  cat > "$fix/run/shims/ditto" <<EOF
#!/bin/bash
echo "ditto \$*" >> "$S/calls"
cp -R "\$1" "\$2"
EOF
  cat > "$fix/run/shims/pgrep" <<EOF
#!/bin/bash
case "\$1" in
  -f) grep -qF "\$2" "$S/running" && echo 999999 ;;
  *) exec /usr/bin/pgrep "\$@" ;;
esac
EOF
  cat > "$fix/run/shims/mdfind" <<EOF
#!/bin/bash
cat "$S/mdfind"
EOF
  chmod +x "$fix/run/shims/"*
}
ws_app() {  # dir version [owner]
  mkdir -p "$1/Wireshark.app/Contents/MacOS"
  echo "CFBundleShortVersionString=$2" > "$1/Wireshark.app/Contents/Info.plist"
  echo old > "$1/Wireshark.app/Contents/MacOS/Wireshark"
  [ -n "${3:-}" ] && echo "$3" > "$1/Wireshark.app/.owner"
  return 0
}
ver_of() { sed -n 's/^CFBundleShortVersionString=//p' "$1/Contents/Info.plist" 2>/dev/null; }
# `kill` is a builtin, so a PATH shim is never used: an exported function is.
# Only the fake Wireshark pid is intercepted; run_limited's own kills pass through.
kill() {
  case " $* " in
    *" 999999"*)
      echo "kill $*" >> "$S/calls"
      [ -e "$S/term_ignored" ] || : > "$S/running"
      return 0 ;;
  esac
  builtin kill "$@"
}
export -f kill
run_script() {
  PATH="$fix/run/shims:$PATH" APP_DIR="$A" USERS_DIR="$fix/run/Users" LOG_DIR="$fix/run/logs" \
    WORK_DIR="$fix/run/work" QUIT_TIMEOUT=2 \
    "$@" bash "$script" >/dev/null 2>&1
}
L="$fix/run/logs/wireshark_update.log"

# csmb-059 (2026-10-27): Wireshark 4.6.x below 4.6.9 on Apple silicon.
make_fixture; ws_app "$A" 4.6.3
run_script env; rc=$?
check 'csmb-059: 4.6.3 replaced and verified -> 0' "$rc" '0'
check 'csmb-059: app reads 4.6.9' "$(ver_of "$A/Wireshark.app")" '4.6.9'
check_grep 'arm64 feed for the installed version' 'curl .*/update/0/Wireshark/4.6.3/macOS/arm64/en-US/stable.xml' "$S/calls"
check_grep 'DMG from the feed url' 'curl .*https://2.na.dl.wireshark.org/osx/all-versions/Wireshark%204.6.9.dmg' "$S/calls"
check_grep 'mounted read-only, hidden' '^hdiutil attach -nobrowse -readonly -noautoopen -mountpoint ' "$S/calls"
check_grep 'deep strict verify' '^codesign --verify --deep --strict .*/mnt/Wireshark.app$' "$S/calls"
check_grep 'SHA-256 checked' 'SHA-256 matches the feed' "$L"
check_grep 'signer logged' 'Signature: Developer ID Application: Wireshark Foundation \(7Z6EMTD2C6\)' "$L"
check_grep 'verified line' 'Wireshark.app  4.6.9  OK' "$L"
check_grep 'owner restored' "^chown -R root:admin $A/Wireshark.app.new." "$S/calls"
check 'no temp copies left' "$(find "$A" -maxdepth 1 -name 'Wireshark.app.*' | wc -l | tr -d ' ')" '0'
check_grep 'DMG detached' '^hdiutil detach -force ' "$S/calls"
check 'work dir cleaned up' "$([ -e "$fix/run/work" ] && echo present || echo gone)" 'gone'

make_fixture; ws_app "$A" 4.6.9
run_script env; rc=$?
check 'current -> 0' "$rc" '0'
check_nogrep 'current: no DMG download' 'curl .*\.dmg' "$S/calls"
check_grep 'current says so' 'RESULT: Wireshark is current \(4.6.9\)' "$L"

make_fixture
run_script env; rc=$?
check 'not installed -> 0' "$rc" '0'
check_nogrep 'not installed: no feed read' '^curl' "$S/calls"

# Intel Mac on the 4.4 branch stays on 4.4.
make_fixture; ws_app "$A" 4.4.10; echo 4.4.19 > "$S/dmg_version"
sed -i 's/^\[ "\$2" = hw.optional.arm64 \] && echo 1$/exit 1/' "$fix/run/shims/sysctl"
printf '%s\n' "$FEED_X86" | sed -e "s/length=\"69692482\"/length=\"$(wc -c < "$S/dmg" | tr -d ' ')\"/" \
  -e "s/a16288f645e7dfc471ed62bf93f63caa7cdf73e83b711ae7b496d46b27900a92/$(sha256sum "$S/dmg" | cut -d' ' -f1)/" > "$S/feed.xml"
run_script env; rc=$?
check 'Intel 4.4.10 -> 4.4.19 -> 0' "$rc" '0'
check_grep 'x86-64 feed on Intel' 'curl .*/macOS/x86-64/en-US/stable.xml' "$S/calls"
check_grep 'Intel DMG downloaded' 'curl .*Wireshark%204.4.19%20Intel%2064.dmg' "$S/calls"
check 'Intel app reads 4.4.19' "$(ver_of "$A/Wireshark.app")" '4.4.19'

make_fixture; ws_app "$A" 4.6.3; echo "$A/Wireshark.app/Contents/MacOS/Wireshark" > "$S/running"
run_script env; rc=$?
check 'running -> defer 2' "$rc" '2'
check_nogrep 'running: no DMG download' 'curl .*\.dmg' "$S/calls"
check_nogrep 'running: not killed' '^kill' "$S/calls"
check_grep 'running: reason in the summary' '  - .*Wireshark.app 4.6.3 is in use \(pid 999999\); re-run when Wireshark is closed' "$L"
check 'running: app untouched' "$(ver_of "$A/Wireshark.app")" '4.6.3'

make_fixture; ws_app "$A" 4.6.3; echo "$A/Wireshark.app/Contents/MacOS/dumpcap" > "$S/running"
run_script env FORCE_CLOSE=1; rc=$?
check 'FORCE_CLOSE=1 stops it and updates -> 0' "$rc" '0'
check_grep 'FORCE_CLOSE=1 sent TERM' '^kill 999999$' "$S/calls"
check 'FORCE_CLOSE=1 app reads 4.6.9' "$(ver_of "$A/Wireshark.app")" '4.6.9'

make_fixture; ws_app "$A" 4.6.3; echo "$A/Wireshark.app/Contents/MacOS/Wireshark" > "$S/running"; touch "$S/term_ignored"
run_script env FORCE_CLOSE=1; rc=$?
check 'will not stop -> 2' "$rc" '2'
check_grep 'will not stop: KILL tried' '^kill -9 999999$' "$S/calls"
check 'will not stop: app untouched' "$(ver_of "$A/Wireshark.app")" '4.6.3'

make_fixture; ws_app "$A" 4.6.3; echo "$A/Wireshark.app/Contents/MacOS/Wireshark" > "$S/running_during_download"
run_script env; rc=$?
check 'opened during download -> 2' "$rc" '2'
check_nogrep 'opened during download: no copy' '^ditto' "$S/calls"
check 'opened during download: app untouched' "$(ver_of "$A/Wireshark.app")" '4.6.3'

make_fixture; ws_app "$A" 4.6.3; touch "$S/tamper"
run_script env; rc=$?
check 'size mismatch -> 1' "$rc" '1'
check_grep 'size mismatch named' 'the feed says [0-9]+ \(proxy block page or truncated\)' "$L"
check_nogrep 'size mismatch: not mounted' '^hdiutil attach' "$S/calls"

make_fixture; ws_app "$A" 4.6.3; echo 'fake wireshark dmX' > "$S/dmg"
run_script env; rc=$?
check 'SHA-256 mismatch -> 1' "$rc" '1'
check_grep 'SHA mismatch named' 'does not match the feed' "$L"
check_nogrep 'SHA mismatch: not mounted' '^hdiutil attach' "$S/calls"
check 'SHA mismatch: app untouched' "$(ver_of "$A/Wireshark.app")" '4.6.3'

make_fixture; ws_app "$A" 4.6.3; echo 4.6.8 > "$S/dmg_version"
run_script env; rc=$?
check 'DMG holds another version -> 1' "$rc" '1'
check_grep 'DMG version named' "the DMG's Wireshark.app is 4.6.8, not 4.6.9" "$L"
check_nogrep 'wrong DMG: no copy' '^ditto' "$S/calls"
check_grep 'wrong DMG: still detached' '^hdiutil detach -force ' "$S/calls"

make_fixture; ws_app "$A" 4.6.3; echo other > "$S/signature"
run_script env; rc=$?
check 'other team ID -> 1' "$rc" '1'
check_grep 'other signer logged' 'Developer ID Application: Evil LLC \(ABCDE12345\)' "$L"
check_nogrep 'other team ID: no copy' '^ditto' "$S/calls"

make_fixture; ws_app "$A" 4.6.3; echo broken > "$S/signature"
run_script env; rc=$?
check 'signature does not verify -> 1' "$rc" '1'
check_nogrep 'broken signature: no copy' '^ditto' "$S/calls"

make_fixture; ws_app "$A" 4.6.3; touch "$S/feed_down"
run_script env; rc=$?
check 'feed down -> 1' "$rc" '1'
check_grep 'feed problem named' 'could not read the update feed' "$L"

make_fixture; ws_app "$A" 4.6.3
run_script env DRY_RUN=1; rc=$?
check 'dry run -> 2' "$rc" '2'
check_nogrep 'dry run: no DMG download' 'curl .*\.dmg' "$S/calls"
check_grep 'dry run says what it would do' '\[DRY_RUN\] would replace .*Wireshark.app \(4.6.3\) with 4.6.9' "$L"

# Machine copy current, per-user copy old: user copy replaced, owner kept.
U="$fix/run/Users/jdoe/Applications"
make_fixture; ws_app "$A" 4.6.9; ws_app "$U" 4.6.1 jdoe:staff
run_script env; rc=$?
check 'old per-user copy -> 0' "$rc" '0'
check 'per-user copy reads 4.6.9' "$(ver_of "$U/Wireshark.app")" '4.6.9'
check_grep 'per-user owner kept' "^chown -R jdoe:staff $U/Wireshark.app.new." "$S/calls"
check 'machine copy not re-copied' "$(grep -c "^ditto .* $A/" "$S/calls")" '0'

make_fixture; ws_app "$A" 4.6.9; ws_app "$U" 4.6.1 jdoe:staff
run_script env UPDATE_USER_COPIES=0; rc=$?
check 'UPDATE_USER_COPIES=0 reports -> 2' "$rc" '2'
check 'UPDATE_USER_COPIES=0 leaves it' "$(ver_of "$U/Wireshark.app")" '4.6.1'

make_fixture; ws_app "$A" 4.6.9; mkdir -p "$fix/run/Downloads"; ws_app "$fix/run/Downloads" 4.6.2
echo "$fix/run/Downloads/Wireshark.app" > "$S/mdfind"; echo "$A/Wireshark.app" >> "$S/mdfind"
run_script env; rc=$?
check 'old copy elsewhere -> 2' "$rc" '2'
check_grep 'Spotlight copy reported' 'Downloads/Wireshark.app  4.6.2  \(found by Spotlight; reported only\)' "$L"
check_grep 'Spotlight copy in the summary' '  - .*Downloads/Wireshark.app is 4.6.2 \(< 4.6.9\) and is not in /Applications' "$L"
check 'Spotlight copy left alone' "$(ver_of "$fix/run/Downloads/Wireshark.app")" '4.6.2'

# Copy step fails: the old app must stay in place.
make_fixture; ws_app "$A" 4.6.3
printf '#!/bin/bash\necho "ditto $*" >> "%s/calls"\nexit 1\n' "$S" > "$fix/run/shims/ditto"
run_script env; rc=$?
check 'copy failure -> 2' "$rc" '2'
check 'copy failure: old app kept' "$(ver_of "$A/Wireshark.app")" '4.6.3'
check 'copy failure: no temp copy left' "$(find "$A" -maxdepth 1 -name 'Wireshark.app.*' | wc -l | tr -d ' ')" '0'

if [ "$fail" -ne 0 ]; then echo "tests failed"; exit 1; fi
echo "All tests passed"
exit 0
