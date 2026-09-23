# Unit tests for update-golang.sh branch-latest lookup (plugin 327411).
# Run: GO_SELFTEST=1 bash macos/tests/update-golang.test.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
script=$(cd "$here/.." && pwd)/update-golang.sh
fix=$(mktemp -d)
trap 'rm -rf "$fix"' EXIT

cat > "$fix/dl.json" <<'JSON'
[
  {"version":"go1.27.1","stable":true,"files":[
    {"filename":"go1.27.1.darwin-arm64.tar.gz","kind":"archive","sha256":"aaa111"}
  ]},
  {"version":"go1.26.5","stable":true,"files":[
    {"filename":"go1.26.5.darwin-arm64.tar.gz","kind":"archive","sha256":"bbb265"},
    {"filename":"go1.26.5.darwin-amd64.tar.gz","kind":"archive","sha256":"bbbamd"}
  ]},
  {"version":"go1.26.3","stable":true,"files":[
    {"filename":"go1.26.3.darwin-arm64.tar.gz","kind":"archive","sha256":"old263"}
  ]},
  {"version":"go1.25.14","stable":true,"files":[
    {"filename":"go1.25.14.darwin-arm64.tar.gz","kind":"archive","sha256":"ccc2514"},
    {"filename":"go1.25.14.darwin-amd64.tar.gz","kind":"archive","sha256":"cccamd"}
  ]},
  {"version":"go1.25.12","stable":true,"files":[
    {"filename":"go1.25.12.darwin-arm64.tar.gz","kind":"archive","sha256":"old2512"}
  ]},
  {"version":"go1.25.10","stable":true,"files":[
    {"filename":"go1.25.10.darwin-arm64.tar.gz","kind":"archive","sha256":"old2510"}
  ]},
  {"version":"go1.25rc1","stable":false,"files":[
    {"filename":"go1.25rc1.darwin-arm64.tar.gz","kind":"archive","sha256":"rcbad"}
  ]}
]
JSON

fail=0
check() {
  name=$1; got=$2; want=$3
  if [ "$got" != "$want" ]; then
    echo "FAIL $name: got '$got' want '$want'"
    fail=1
  else
    echo "OK   $name"
  fi
}

export GO_SELFTEST=1
export GO_DL_JSON="$fix/dl.json"
# shellcheck source=/dev/null
. "$script"

check '1.25.10 -> latest 1.25.14 (plugin 327411 floor is 1.25.12)' \
  "$(required_fixed_for 1.25.10)" '1.25.14'
check '1.25.12 still below branch tip' "$(required_fixed_for 1.25.12)" '1.25.14'
check '1.25.14 already at tip' "$(required_fixed_for 1.25.14)" '1.25.14'
check '1.26.3 -> 1.26.5' "$(required_fixed_for 1.26.3)" '1.26.5'
check '1.27.0 stays on 1.27 (does not jump)' "$(required_fixed_for 1.27.0)" '1.27.1'
check 'unknown 1.21 has no dynamic tip' "$(required_fixed_for 1.21.13)" ''
check 'empty version' "$(required_fixed_for '')" ''

check 'sha arm64 1.25.14' "$(go_tarball_sha256 go1.25.14.darwin-arm64.tar.gz)" 'ccc2514'
check 'sha amd64 1.26.5' "$(go_tarball_sha256 go1.26.5.darwin-amd64.tar.gz)" 'bbbamd'
check 'sha missing file' "$(go_tarball_sha256 go1.25.14.linux-amd64.tar.gz)" ''
check 'never use RC hash' "$(go_tarball_sha256 go1.25rc1.darwin-arm64.tar.gz)" 'rcbad'

# RC is listed but required_fixed_for must ignore it when picking 1.25 tip
# (already covered: 1.25.10 -> 1.25.14 not rc)

branch_of=$(go_branch_of 1.25.10)
check 'go_branch_of 1.25.10' "$branch_of" '1.25'

if [ "$fail" -ne 0 ]; then
  echo "$fail test(s) failed"
  exit 1
fi
echo "All tests passed"
exit 0
