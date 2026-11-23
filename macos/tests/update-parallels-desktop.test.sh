# Tests for update-parallels-desktop.sh.
# Run: bash macos/tests/update-parallels-desktop.test.sh
#
# Unit checks for the feed parser, target choice, process and VM parsing,
# signature and architecture checks against Parallels' real feeds and DMG
# (2026-11-23), then end-to-end runs against fake curl / hdiutil / codesign /
# file / defaults / ps / sudo and a fake inittool, prlctl and prlsrvctl:
#   armb-09 shape (19.3.0 < 27.0.0) installed with inittool and verified -> 0;
#   current -> 0 with no download; 27.0.x stays on 27 with no major note;
#   ALLOW_MAJOR_UPGRADE=0 -> 2; in use -> defer 2 (FORCE_CLOSE=1 suspends the
#   VM as its owner, never kills it); Intel or old macOS -> 2; proxy page,
#   other team ID, broken signature, wrong DMG build, foreign URL -> 1 with
#   nothing changed; inittool exit 11 -> 2 reboot; inittool losing the app ->
#   old app put back, 1; feeds down -> 1; dry run -> 2.
set -u
# Set by the unit block only; inherited, it would turn every run into a no-op.
unset PARALLELS_UPDATE_SELFTEST
here=$(cd "$(dirname "$0")" && pwd)
script=$(cd "$here/.." && pwd)/update-parallels-desktop.sh

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

# https://update.parallels.com/desktop/v27/parallels/parallels_updates.xml on
# 2026-11-23, with the non-ASCII UpdateName lines and the localized promo URLs
# dropped.
FEED_27='<?xml version="1.0" encoding="UTF-8"?>
<ParallelsUpdates schemaVersion="1.0">
    <Product>
        <ProductName>Parallels Desktop</ProductName>
        <UpdateEnabled>1</UpdateEnabled>
            <Version>
            <Major>27</Major>
            <Minor>1</Minor>
            <SubMinor>0</SubMinor>
            <SubSubMinor>58756</SubSubMinor>
            <StringRepresentation>Sumer</StringRepresentation>

            <!-- update to 27.1.0 version -->

            <Update uuid="desktop.27.1.0.58756.en_US.parallels.mac">
                <UpdateType>0</UpdateType>
                <UpdateName>en_US#Build 58756 is available!</UpdateName>
                <UpdateName>fr_FR#Build 58756 disponible!</UpdateName>
                <UpdateName>cs_CZ#Build 58756 je k dispozici!</UpdateName>
                <UpdatePromoUrl>    </UpdatePromoUrl>
                <UpdatePromoUrl>en_US#https://static.parallels.com/ipn/pd/27/update/upd2710/</UpdatePromoUrl>
                <UpdateDescription></UpdateDescription>
                <FilePath>https://download.parallels.com/desktop/v27/27.1.0-58756/ParallelsDesktop-27.1.0-58756.dmg</FilePath>
                <FileSize>305626.0</FileSize>
                <Status>0</Status>
                <DateTime>2021-09-01</DateTime>
                <Chargeable>0</Chargeable>
                <LocaleName>en_US</LocaleName>
                <DistributorName>parallels</DistributorName>
                <OsType>mac</OsType>
                <Ancestry>
                    <Ancestor>desktop.27.0.0-58628.en_US.parallels.mac</Ancestor>
                    <Ancestor>desktop.27.0.1-58670.en_US.parallels.mac</Ancestor>
                    <Ancestor>desktop.27.0.2-58673.en_US.parallels.mac</Ancestor>
                    <Ancestor>desktop.27.0.3-58680.en_US.parallels.mac</Ancestor>
                </Ancestry>
            </Update> 
        </Version>
    </Product>
</ParallelsUpdates>'
# .../v19/... the same day: 19.4.3-54993 is the last 19 build (armb-09 has 19.3.0-54924).
FEED_19=$(printf '%s\n' "$FEED_27" | sed -e 's#<Major>27<#<Major>19<#' -e 's#<Minor>1<#<Minor>4<#' -e 's#<SubMinor>0<#<SubMinor>3<#' \
  -e 's/58756/54993/g' -e 's#v27/27.1.0#v19/19.4.3#' -e 's/ParallelsDesktop-27.1.0/ParallelsDesktop-19.4.3/' -e 's/27\.1\.0/19.4.3/g' -e '/<Ancestor>/d')
FEED_26=$(printf '%s\n' "$FEED_27" | sed -e 's#<Major>27<#<Major>26<#' -e 's#<Minor>1<#<Minor>5<#' \
  -e 's/58756/57613/g' -e 's#v27/27.1.0#v26/26.5.0#' -e 's/ParallelsDesktop-27.1.0/ParallelsDesktop-26.5.0/' -e 's/27\.1\.0/26.5.0/g' -e '/<Ancestor>/d')

# Parallels Desktop 27.1.0's signer as `codesign -dv --verbose=2` prints it
# (Developer ID and team read from the DMG's prl_client_app certificate).
SIG_GOOD='Executable=/Volumes/Parallels Desktop 27/Parallels Desktop.app/Contents/MacOS/prl_client_app
Identifier=com.parallels.desktop.console
Format=app bundle with Mach-O thin (arm64)
CodeDirectory v=20500 size=91234 flags=0x10000(runtime) hashes=2840+7 location=embedded
Signature size=9012
Authority=Developer ID Application: Parallels International GmbH (4C6364ACXT)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
Timestamp=Oct 17, 2026 at 6:56:56 PM
Info.plist entries=48
TeamIdentifier=4C6364ACXT
Runtime Version=15.0.0
Sealed Resources version=2 rules=13 files=9120
Internal requirements count=1 size=228'

# `file -b` on the DMG's prl_client_app (Linux file 5.x); macOS words it
# "Mach-O 64-bit executable arm64".
FILE_ARM='Mach-O 64-bit arm64 executable, flags:<NOUNDEFS|DYLDLINK|TWOLEVEL|BINDS_TO_WEAK|PIE>'

# ---------------------------------------------------------------- unit ----
(
  export PARALLELS_UPDATE_SELFTEST=1
  # shellcheck source=/dev/null
  . "$script"
  ufail=0
  u() { if [ "$2" != "$3" ]; then printf 'FAIL %s\n got:  %s\n want: %s\n' "$1" "$2" "$3"; ufail=1; else echo "OK   $1"; fi; }
  y() { if "$@"; then echo y; else echo n; fi; }

  u 'v27 feed parsed' "$(printf '%s\n' "$FEED_27" | feed_item)" \
    '27.1.0|58756|https://download.parallels.com/desktop/v27/27.1.0-58756/ParallelsDesktop-27.1.0-58756.dmg'
  u 'v19 feed parsed' "$(printf '%s\n' "$FEED_19" | feed_item)" \
    '19.4.3|54993|https://download.parallels.com/desktop/v19/19.4.3-54993/ParallelsDesktop-19.4.3-54993.dmg'
  u 'SubMinor not read as Minor' "$(printf '<SubMinor>9</SubMinor>\n<Minor>2</Minor>\n<Major>5</Major>\n<SubSubMinor>1</SubSubMinor>\n<FilePath>u</FilePath>\n' | feed_item)" '5.2.9|1|u'
  u 'Cloudflare 404 page: nothing' "$(printf '<!doctype html>\n<title>Not Found</title>\n' | feed_item)" ''
  u 'feed without FilePath: nothing' "$(printf '%s\n' "$FEED_27" | grep -v FilePath | feed_item)" ''

  U27='https://download.parallels.com/desktop/v27/27.1.0-58756/ParallelsDesktop-27.1.0-58756.dmg'
  u 'feed URL accepted' "$(y dmg_url_ok "$U27" 27.1.0 58756)" 'y'
  u 'other build refused' "$(y dmg_url_ok "$U27" 27.1.0 58757)" 'n'
  u 'http refused' "$(y dmg_url_ok "${U27/https/http}" 27.1.0 58756)" 'n'
  u 'other host refused' "$(y dmg_url_ok "https://evil.example/desktop/v27/27.1.0-58756/ParallelsDesktop-27.1.0-58756.dmg" 27.1.0 58756)" 'n'
  u 'look-alike host refused' "$(y dmg_url_ok "https://download.parallels.com.evil.example/ParallelsDesktop-27.1.0-58756.dmg" 27.1.0 58756)" 'n'

  FEEDS=$(printf '19|%s\n26|%s\n27|%s\n' "$(printf '%s\n' "$FEED_19" | feed_item)" "$(printf '%s\n' "$FEED_26" | feed_item)" "$(printf '%s\n' "$FEED_27" | feed_item)")
  t() { printf '%s\n' "$FEEDS" | pick_target "$1" "$2" "$3" | cut -d'|' -f1-2; }
  u 'armb-09: 19.3.0 -> 27.1.0' "$(t 19.3.0 27.0.0 1)" '27.1.0|58756'
  u '19.3.0, majors not allowed -> 3' "$(t 19.3.0 27.0.0 0; echo "rc=$?")" 'rc=3'
  u '27.0.3 stays on 27' "$(t 27.0.3 27.0.0 0)" '27.1.0|58756'
  u '26.x fixed at 26.5 stays on 26' "$(t 26.1.0 26.4.0 0)" '26.5.0|57613'
  u '26.x needing 27 moves to 27' "$(t 26.5.0 27.0.0 1)" '27.1.0|58756'
  u 'nothing >= 28 published -> 1' "$(t 27.1.0 28.0.0 1; echo "rc=$?")" 'rc=1'
  u 'unreadable version -> newest' "$(t '' 27.0.0 0)" '27.1.0|58756'
  u 'installed major without feed -> newest' "$(t 18.1.0 27.0.0 1)" '27.1.0|58756'
  u 'installed major without feed, majors not allowed -> 3' "$(t 18.1.0 27.0.0 0; echo "rc=$?")" 'rc=3'

  u '27.1.0.58756 is current' "$(y version_ge 27.1.0.58756 27.1.0.58756)" 'y'
  u '27.1.0.58755 below 27.1.0.58756' "$(y version_ge 27.1.0.58755 27.1.0.58756)" 'n'
  u '19.3.0 below 27.0.0' "$(y version_ge 19.3.0 27.0.0)" 'n'
  u 'macOS 14.0 meets 14.0' "$(y version_ge 14.0 14.0)" 'y'
  u 'macOS 13.6.9 below 14.0' "$(y version_ge 13.6.9 14.0)" 'n'

  A='/Applications/Parallels Desktop.app'
  PS="  101 root     /Applications/Parallels Desktop.app/Contents/MacOS/Parallels Service.app/Contents/MacOS/prl_disp_service --launchd
  202 jdoe     /Applications/Parallels Desktop.app/Contents/MacOS/prl_client_app
  303 jdoe     /Applications/Parallels Desktop.app/Contents/MacOS/Parallels VM.app/Contents/MacOS/prl_vm_app --openvm /Users/jdoe/Parallels/Windows 11.pvm
  404 asmith   /Applications/Parallels Desktop.app/Contents/MacOS/Parallels Mac VM.app/Contents/MacOS/prl_macvm_app --openvm x
  505 jdoe     /Users/jdoe/Downloads/Parallels Desktop.app/Contents/MacOS/prl_client_app
  606 jdoe     /usr/bin/less /Applications/Parallels Desktop.app/Contents/MacOS/prl_client_app"
  u 'app and both VM kinds found; services, other copies and mentions ignored' \
    "$(printf '%s\n' "$PS" | busy_procs "$A" | tr '\n' ' ')" '202|jdoe|gui 303|jdoe|vm 404|asmith|vm '
  u 'only the service: not busy' "$(printf '%s\n' "$PS" | head -n 1 | busy_procs "$A")" ''

  VMS='{6d0e3e62-7c4f-4a8e-9a43-2b1c3d4e5f60} running
{a1b2c3d4-0000-4000-8000-000000000001} stopped
{a1b2c3d4-0000-4000-8000-000000000002} paused
{a1b2c3d4-0000-4000-8000-000000000003} suspended'
  u 'running and paused VMs only' "$(printf '%s\n' "$VMS" | active_vms | tr '\n' ' ')" \
    '{6d0e3e62-7c4f-4a8e-9a43-2b1c3d4e5f60} {a1b2c3d4-0000-4000-8000-000000000002} '
  u 'a header line is ignored' "$(printf 'UUID STATUS\n{a1b2c3d4-0000-4000-8000-000000000009} running\n' | active_vms)" '{a1b2c3d4-0000-4000-8000-000000000009}'

  u 'Parallels signature accepted' "$(echo "$SIG_GOOD" | y signature_is_parallels)" 'y'
  u 'other team ID refused' "$(echo "$SIG_GOOD" | sed 's/4C6364ACXT/ABCDE12345/g' | y signature_is_parallels)" 'n'
  u 'team ID only on the Authority line refused' "$(echo "$SIG_GOOD" | sed 's/^TeamIdentifier=.*/TeamIdentifier=ABCDE12345/' | y signature_is_parallels)" 'n'
  u 'ad-hoc signature refused' "$(printf 'Identifier=com.parallels.desktop.console\nSignature=adhoc\nTeamIdentifier=not set\n' | y signature_is_parallels)" 'n'

  u 'arm64-only (Linux file)' "$(echo "$FILE_ARM" | macho_archs)" 'arm64'
  u 'arm64-only (macOS file)' "$(echo 'Mach-O 64-bit executable arm64' | macho_archs)" 'arm64'
  u 'universal' "$(echo 'Mach-O universal binary with 2 architectures: [x86_64:Mach-O 64-bit executable x86_64] [arm64e:Mach-O 64-bit executable arm64e]' | macho_archs)" 'arm64 x86_64'
  u 'arm64 runs on arm64' "$(y archs_include arm64 arm64)" 'y'
  u 'arm64-only does not run on Intel' "$(y archs_include arm64 x86_64)" 'n'
  u 'universal runs on Intel' "$(y archs_include 'arm64 x86_64' x86_64)" 'y'

  u 'license key masked' "$(echo 'License: state="valid" key="ABC123-DEF456-GHI789-JKL012-MNO345" edition="pro"' | mask_license)" \
    'License: state="valid" key="<masked>" edition="pro"'
  u 'bare key masked' "$(echo 'serial: ABC123-DEF456-GHI789-JKL012-MNO345' | mask_license)" 'serial: <masked>'
  u 'inittool 11 named' "$(inittool_rc_text 11)" 'installed; reboot required (the old services would not stop)'
  exit $ufail
) || fail=1

# ----------------------------------------------------------- end to end ----
fix=$(mktemp -d)
trap 'rm -rf "$fix"' EXIT

make_fixture() {
  rm -rf "$fix/run"; mkdir -p "$fix/run/shims" "$fix/run/state/feeds" "$fix/run/logs" "$fix/run/Applications"
  S="$fix/run/state"; A="$fix/run/Applications"; P="$A/Parallels Desktop.app"; export S
  : > "$S/calls"
  { printf 'fake parallels dmg'; printf 'koly'; head -c 508 /dev/zero; } > "$S/dmg"
  echo 27.1.0 > "$S/dmg_version"; echo 58756 > "$S/dmg_build"; echo 14.0 > "$S/dmg_minos"
  echo "$FILE_ARM" > "$S/file_out"
  echo good > "$S/signature"
  echo ok > "$S/inittool_mode"
  : > "$S/ps"; : > "$S/vms"; : > "$S/running_during_download"
  echo 'License: state="valid" key="ABC123-DEF456-GHI789-JKL012-MNO345" edition="pro" expiration="2027-03-01"' > "$S/license"
  printf '%s\n' "$FEED_19" > "$S/feeds/v19.xml"
  printf '%s\n' "$FEED_26" > "$S/feeds/v26.xml"
  # v21's URL really serves a stale v20 feed (20.2.1-55876).
  printf '%s\n' "$FEED_19" | sed -e 's#<Major>19<#<Major>20<#' -e 's#<Minor>4<#<Minor>2<#' -e 's#<SubMinor>3<#<SubMinor>1<#' \
    -e 's/54993/55876/g' -e 's/19\.4\.3/20.2.1/g' -e 's#/v19/#/v20/#' > "$S/feeds/v21.xml"
  printf '%s\n' "$FEED_27" > "$S/feeds/v27.xml"
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
  *parallels_updates.xml)
    [ -e "$S/feed_down" ] && exit 6
    m=\$(echo "\$url" | sed -n 's#.*/v\([0-9]*\)/parallels/.*#\1#p')
    [ -f "$S/feeds/v\$m.xml" ] || exit 22
    cp "$S/feeds/v\$m.xml" "\$out" ;;
  *.dmg)
    [ -s "$S/running_during_download" ] && cat "$S/running_during_download" >> "$S/ps"
    cp "$S/dmg" "\$out" ;;
  *) exit 22 ;;
esac
exit 0
EOF
  # The DMG's app, with a fake inittool that does what install_pd does to the
  # target: delete it, copy the bundle, exit with the code under test.
  cat > "$S/inittool" <<EOF
#!/bin/bash
echo "inittool \$*" >> "$S/calls"
t=""; b=""
while [ \$# -gt 0 ]; do case "\$1" in -t) t="\$2"; shift ;; -b) b="\$2"; shift ;; esac; shift; done
case "\$(cat "$S/inittool_mode")" in
  ok) rm -rf "\$t"; cp -R "\$b" "\$t" ;;
  reboot) rm -rf "\$t"; cp -R "\$b" "\$t"; echo 'Services are broken, reboot required ...'; exit 11 ;;
  lost) rm -rf "\$t"; echo "Can't copy bundle to \$t: No space left on device"; exit 1 ;;
  noop) echo 'Fatal: OS version is not supported'; exit 8 ;;
esac
exit 0
EOF
  cat > "$fix/run/shims/hdiutil" <<EOF
#!/bin/bash
echo "hdiutil \$*" >> "$S/calls"
case "\$1" in
  attach)
    mp=""; while [ \$# -gt 0 ]; do [ "\$1" = -mountpoint ] && mp="\$2"; shift; done
    app="\$mp/Parallels Desktop.app"
    mkdir -p "\$app/Contents/MacOS"
    { echo "CFBundleShortVersionString=\$(cat "$S/dmg_version")"; echo "CFBundleVersion=\$(cat "$S/dmg_build")"
      echo "LSMinimumSystemVersion=\$(cat "$S/dmg_minos")"; } > "\$app/Contents/Info.plist"
    echo bin > "\$app/Contents/MacOS/prl_client_app"
    cp "$S/inittool" "\$app/Contents/MacOS/inittool"; chmod +x "\$app/Contents/MacOS/inittool"
    printf '#!/bin/bash\necho "prlsrvctl-new \$*" >> "$S/calls"\ncat "$S/license"\n' > "\$app/Contents/MacOS/prlsrvctl"
    chmod +x "\$app/Contents/MacOS/prlsrvctl"
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
      printf '%s\n' 'Identifier=com.parallels.desktop.console' 'Authority=Developer ID Application: Evil LLC (ABCDE12345)' 'TeamIdentifier=ABCDE12345' >&2
    else
      printf '%s\n' "$SIG_GOOD" >&2
    fi ;;
esac
exit 0
EOF
  printf '#!/bin/bash\ncat "%s/file_out"\n' "$S" > "$fix/run/shims/file"
  cat > "$fix/run/shims/ditto" <<EOF
#!/bin/bash
echo "ditto \$*" >> "$S/calls"
cp -R "\$1" "\$2"
EOF
  cat > "$fix/run/shims/ps" <<EOF
#!/bin/bash
[ "\$*" = "-axo pid=,user=,command=" ] && { cat "$S/ps"; exit 0; }
exec /bin/ps "\$@"
EOF
  cat > "$fix/run/shims/sudo" <<EOF
#!/bin/bash
echo "sudo \$*" >> "$S/calls"
while [ "\$1" = -u ] || [ "\$1" = -H ]; do [ "\$1" = -u ] && shift; shift; done
exec "\$@"
EOF
  chmod +x "$fix/run/shims/"*
}
# The installed app, with the old prlctl / prlsrvctl inside it.
pd_app() {  # version build
  mkdir -p "$P/Contents/MacOS"
  printf 'CFBundleShortVersionString=%s\nCFBundleVersion=%s\n' "$1" "$2" > "$P/Contents/Info.plist"
  cat > "$P/Contents/MacOS/prlctl" <<EOF
#!/bin/bash
echo "prlctl \$*" >> "$S/calls"
case "\$1" in
  list) cat "$S/vms" ;;
  suspend)
    [ -e "$S/suspend_fails" ] && { echo 'Failed to suspend the VM'; exit 1; }
    grep -vF "\$2" "$S/vms" > "$S/vms.t"; mv "$S/vms.t" "$S/vms"
    grep -v 'VM.app/' "$S/ps" > "$S/ps.t"; mv "$S/ps.t" "$S/ps" ;;
esac
exit 0
EOF
  printf '#!/bin/bash\necho "prlsrvctl-old $*" >> "%s/calls"\ncat "%s/license"\n' "$S" "$S" > "$P/Contents/MacOS/prlsrvctl"
  chmod +x "$P/Contents/MacOS/prlctl" "$P/Contents/MacOS/prlsrvctl"
}
ver_of() { sed -n 's/^CFBundleShortVersionString=//p' "$P/Contents/Info.plist" 2>/dev/null; }
gui_running() { echo "999991 jdoe $P/Contents/MacOS/prl_client_app" >> "$S/ps"; }
vm_running() {
  echo "999992 jdoe $P/Contents/MacOS/Parallels VM.app/Contents/MacOS/prl_vm_app --openvm /Users/jdoe/Parallels/Windows 11.pvm" >> "$S/ps"
  echo '{6d0e3e62-7c4f-4a8e-9a43-2b1c3d4e5f60} running' >> "$S/vms"
}
# `kill` is a builtin, so a PATH shim is never used: an exported function is.
# Only the fake app pid is intercepted; run_limited's own kills pass through.
kill() {
  case " $* " in
    *" 99999"[0-9]*)
      echo "kill $*" >> "$S/calls"
      if [ "$1" = -9 ] || [ ! -e "$S/gui_ignores_term" ]; then
        grep -v '^999991 ' "$S/ps" > "$S/ps.t"; mv "$S/ps.t" "$S/ps"
      fi
      return 0 ;;
  esac
  builtin kill "$@"
}
export -f kill
run_script() {
  PATH="$fix/run/shims:$PATH" APP_DIR="$A" LOG_DIR="$fix/run/logs" WORK_DIR="$fix/run/work" \
    BACKUP_DIR="$fix/run/backup" OS_VERSION=15.7 HOST_ARCH=arm64 QUIT_TIMEOUT=2 \
    "$@" bash "$script" >/dev/null 2>&1
}
L="$fix/run/logs/parallels_update.log"

# armb-09 (2026-11-23): Parallels Desktop 19.3.0 on Apple silicon, plugin 347968.
make_fixture; pd_app 19.3.0 54924
run_script env; rc=$?
check 'armb-09: 19.3.0 -> 27.1.0 -> 0' "$rc" '0'
check 'armb-09: app reads 27.1.0' "$(ver_of)" '27.1.0'
check_grep 'installed major feed read' 'curl .*/desktop/v19/parallels/parallels_updates.xml' "$S/calls"
check_grep 'probed past 27' 'curl .*/desktop/v33/parallels/parallels_updates.xml' "$S/calls"
check_nogrep 'not past the lookahead' 'curl .*/desktop/v34/' "$S/calls"
check_grep 'missing majors skipped quietly' '  feed v26: 26.5.0 build 57613' "$L"
check_grep "v21's stale v20 feed skipped, not a failure" '  feed v21: serves 20.2.1 \(another major.s feed\); skipped' "$L"
check_grep 'DMG from the feed url' 'curl .*https://download.parallels.com/desktop/v27/27.1.0-58756/ParallelsDesktop-27.1.0-58756.dmg' "$S/calls"
check_grep 'mounted read-only, hidden' '^hdiutil attach -nobrowse -readonly -noautoopen -mountpoint ' "$S/calls"
check_grep 'deep strict verify' '^codesign --verify --deep --strict .*/mnt/Parallels Desktop.app$' "$S/calls"
check_grep 'signer logged' 'Signature: Developer ID Application: Parallels International GmbH \(4C6364ACXT\)' "$L"
check_grep "Parallels' inittool from the DMG" "^inittool install -t $P -b .*/mnt/Parallels Desktop.app -s$" "$S/calls"
check_grep 'license read before' '^prlsrvctl-old info --license' "$S/calls"
check_grep 'license read after' '^prlsrvctl-new info --license' "$S/calls"
check_grep 'license key masked' 'License \(before\): License: state="valid" key="<masked>"' "$L"
check_nogrep 'license key not in the log' 'ABC123-DEF456' "$L"
check_grep 'major upgrade noted' 'moved from Parallels Desktop 19 to 27. A perpetual 19 key' "$L"
check_grep 'verified line' 'Parallels Desktop.app  27.1.0 build 58756  OK' "$L"
check_grep 'result' 'RESULT: Parallels Desktop is current \(27.1.0 build 58756\)' "$L"
check 'backup removed' "$([ -e "$fix/run/backup" ] && echo present || echo gone)" 'gone'
check_grep 'DMG detached' '^hdiutil detach -force ' "$S/calls"
check 'work dir cleaned up' "$([ -e "$fix/run/work" ] && echo present || echo gone)" 'gone'

make_fixture; pd_app 27.1.0 58756
run_script env; rc=$?
check 'current -> 0' "$rc" '0'
check_nogrep 'current: no DMG download' 'curl .*\.dmg' "$S/calls"
check_grep 'current says so' 'RESULT: Parallels Desktop is current \(27.1.0 build 58756\)' "$L"

make_fixture
run_script env; rc=$?
check 'not installed -> 0' "$rc" '0'
check_nogrep 'not installed: no feed read' '^curl' "$S/calls"

make_fixture; pd_app 27.0.3 58680
run_script env; rc=$?
check '27.0.3 -> 27.1.0 -> 0' "$rc" '0'
check_nogrep '27.0.3: no v26 probe below the installed major' 'curl .*/desktop/v26/' "$S/calls"
check_nogrep '27.0.3: no major note' 'moved from Parallels Desktop' "$L"

make_fixture; pd_app 19.3.0 54924
run_script env ALLOW_MAJOR_UPGRADE=0; rc=$?
check 'ALLOW_MAJOR_UPGRADE=0 -> 2' "$rc" '2'
check_nogrep 'ALLOW_MAJOR_UPGRADE=0: no download' 'curl .*\.dmg' "$S/calls"
check_grep 'ALLOW_MAJOR_UPGRADE=0: reason' 'Parallels Desktop 19 has no build >= 27.0.0; only a newer major does' "$L"

make_fixture; pd_app 27.1.0 58756
run_script env MIN_VERSION=28.0.0; rc=$?
check 'no fixed build published -> 2' "$rc" '2'
check_grep 'no fixed build named' 'no Parallels Desktop build >= 28.0.0 in the feeds v27..v34' "$L"

make_fixture; pd_app 19.3.0 54924; touch "$S/feed_down"
run_script env; rc=$?
check 'feeds down -> 1' "$rc" '1'
check_grep 'feeds problem named' 'could not read the update feeds: v19\(curl 6\)' "$L"
check 'feeds down: app untouched' "$(ver_of)" '19.3.0'

make_fixture; pd_app 19.3.0 54924; echo '<!doctype html><title>Blocked by policy</title>' > "$S/feeds/v19.xml"
run_script env; rc=$?
check 'proxy page as a feed -> 1' "$rc" '1'
check_grep 'proxy feed named' 'v19\(unreadable\)' "$L"

make_fixture; pd_app 19.3.0 54924; sed -i 's#https://download.parallels.com/desktop/v27/#https://mirror.example.com/desktop/v27/#' "$S/feeds/v27.xml"
run_script env; rc=$?
check 'foreign DMG URL -> 1' "$rc" '1'
check_nogrep 'foreign DMG URL: no download' 'curl .*\.dmg' "$S/calls"

make_fixture; pd_app 19.3.0 54924; gui_running
run_script env; rc=$?
check 'app open -> defer 2' "$rc" '2'
check_nogrep 'app open: no DMG download' 'curl .*\.dmg' "$S/calls"
check_nogrep 'app open: not killed' '^kill' "$S/calls"
check_grep 'app open: reason in the summary' '  - Parallels Desktop 19.3.0 is in use \(app open: 1, VM processes: 0 \(user: jdoe\)\)' "$L"

make_fixture; pd_app 27.0.3 58680; gui_running
run_script env; rc=$?
check 'fixed 27.0.3 in use -> 0 (newer build waits)' "$rc" '0'
check_grep 'fixed in use: note' 'newer build 27.1.0-58756 available; not installed while Parallels Desktop is in use' "$L"

make_fixture; pd_app 19.3.0 54924; gui_running; vm_running
run_script env FORCE_CLOSE=1; rc=$?
check 'FORCE_CLOSE=1: VM suspended, app quit, installed -> 0' "$rc" '0'
check_grep 'VM suspended as its owner' '^sudo -u jdoe -H .*/prlctl suspend \{6d0e3e62-7c4f-4a8e-9a43-2b1c3d4e5f60\}$' "$S/calls"
check_grep 'app sent TERM' '^kill 999991$' "$S/calls"
check_nogrep 'VM never killed' '^kill .*999992' "$S/calls"
check 'suspend before inittool' "$(grep -nE '^(prlctl suspend|inittool)' "$S/calls" | cut -d: -f2 | cut -d' ' -f1-2 | tr '\n' ',')" 'prlctl suspend,inittool install,'
check 'FORCE_CLOSE=1 app reads 27.1.0' "$(ver_of)" '27.1.0'

make_fixture; pd_app 19.3.0 54924; vm_running; touch "$S/suspend_fails"
run_script env FORCE_CLOSE=1; rc=$?
check 'VM will not suspend -> 2' "$rc" '2'
check_nogrep 'VM will not suspend: not killed' '^kill' "$S/calls"
check_nogrep 'VM will not suspend: no inittool' '^inittool' "$S/calls"
check 'VM will not suspend: app untouched' "$(ver_of)" '19.3.0'

make_fixture; pd_app 19.3.0 54924; gui_running; touch "$S/gui_ignores_term"
run_script env FORCE_CLOSE=1; rc=$?
check 'app ignores TERM with no VM -> KILL, installed -> 0' "$rc" '0'
check_grep 'app KILLed' '^kill -9 999991$' "$S/calls"

make_fixture; pd_app 19.3.0 54924; echo "999991 jdoe $P/Contents/MacOS/prl_client_app" > "$S/running_during_download"
run_script env; rc=$?
check 'opened during download -> 2' "$rc" '2'
check_nogrep 'opened during download: no inittool' '^inittool' "$S/calls"
check 'opened during download: app untouched' "$(ver_of)" '19.3.0'

make_fixture; pd_app 19.3.0 54924
run_script env HOST_ARCH=x86_64; rc=$?
check 'Intel Mac, arm64-only build -> 2' "$rc" '2'
check_grep 'Intel reason' 'Parallels Desktop 27.1.0 runs on arm64 only and this Mac is x86_64' "$L"
check_nogrep 'Intel: no inittool' '^inittool' "$S/calls"

make_fixture; pd_app 19.3.0 54924
run_script env OS_VERSION=13.6.9; rc=$?
check 'macOS 13.6.9 below 14.0 -> 2' "$rc" '2'
check_grep 'macOS reason' 'needs macOS 14.0 or later; this Mac runs 13.6.9' "$L"
check_nogrep 'old macOS: no inittool' '^inittool' "$S/calls"

make_fixture; pd_app 19.3.0 54924; echo '<html>blocked</html>' > "$S/dmg"
run_script env; rc=$?
check 'proxy page as the DMG -> 1' "$rc" '1'
check_grep 'not a disk image named' 'not a disk image \(no UDIF trailer' "$L"
check_nogrep 'proxy DMG: not mounted' '^hdiutil attach' "$S/calls"

make_fixture; pd_app 19.3.0 54924; echo 58755 > "$S/dmg_build"
run_script env; rc=$?
check 'DMG holds another build -> 1' "$rc" '1'
check_grep 'DMG build named' "the DMG's Parallels Desktop.app is 27.1.0-58755, not 27.1.0-58756" "$L"
check_nogrep 'wrong DMG: no inittool' '^inittool' "$S/calls"
check_grep 'wrong DMG: still detached' '^hdiutil detach -force ' "$S/calls"

make_fixture; pd_app 19.3.0 54924; echo other > "$S/signature"
run_script env; rc=$?
check 'other team ID -> 1' "$rc" '1'
check_grep 'other signer logged' 'Developer ID Application: Evil LLC \(ABCDE12345\)' "$L"
check_nogrep 'other team ID: no inittool' '^inittool' "$S/calls"

make_fixture; pd_app 19.3.0 54924; echo broken > "$S/signature"
run_script env; rc=$?
check 'signature does not verify -> 1' "$rc" '1'
check_nogrep 'broken signature: no inittool' '^inittool' "$S/calls"

make_fixture; pd_app 19.3.0 54924; echo reboot > "$S/inittool_mode"
run_script env; rc=$?
check 'inittool 11 -> 2 reboot' "$rc" '2'
check 'inittool 11: app reads 27.1.0' "$(ver_of)" '27.1.0'
check_grep 'inittool 11: result' 'RESULT: Parallels Desktop 27.1.0-58756 installed; reboot required' "$L"

make_fixture; pd_app 19.3.0 54924; echo lost > "$S/inittool_mode"
run_script env; rc=$?
check 'inittool loses the app -> 1' "$rc" '1'
check 'inittool loses the app: old app put back' "$(ver_of)" '19.3.0'
check_grep 'inittool output in the log' "\| Can't copy bundle to .*No space left on device" "$L"
check_grep 'restore named' 'the old 19.3.0 was put back' "$L"
check 'restore: backup gone' "$([ -e "$fix/run/backup" ] && echo present || echo gone)" 'gone'

make_fixture; pd_app 19.3.0 54924; echo noop > "$S/inittool_mode"
run_script env; rc=$?
check 'inittool changes nothing -> 1' "$rc" '1'
check_grep 'not current named' 'reads 19.3.0-54924 after inittool \(macOS too old or a system tool is missing\), not 27.1.0-58756' "$L"
check 'inittool changes nothing: backup gone' "$([ -e "$fix/run/backup" ] && echo present || echo gone)" 'gone'

make_fixture; pd_app 19.3.0 54924
run_script env DRY_RUN=1; rc=$?
check 'dry run -> 2' "$rc" '2'
check_nogrep 'dry run: no DMG download' 'curl .*\.dmg' "$S/calls"
check_grep 'dry run says what it would do' '\[DRY_RUN\] would install 27.1.0-58756 over 19.3.0-54924 with inittool' "$L"

if [ "$fail" -ne 0 ]; then echo "tests failed"; exit 1; fi
echo "All tests passed"
exit 0
