# AGENTS.md

## Cursor Cloud specific instructions

### What this repo is
This repository is a collection of **standalone system-remediation scripts**, not a
buildable application. There is no package manager, build system, automated test
suite, or CI config. Two platforms:

- `windows/` — PowerShell (`.ps1`), deployed via Endpoint Central (runs as SYSTEM).
- `macos/` — bash 3.2-compatible (`.sh`), deployed via Mosyle (runs as root).
- `*/superseded/` — kept for reference/rollback; prefer the replacement noted in each script header.

Read `README.md` for the deployment conventions and cross-cutting lessons; script
headers document plugin IDs, exit-code meanings, and per-script quirks.

### Development toolchain (installed by the environment update script)
There are no project dependencies to install. "Development readiness" for this repo
means being able to **author and lint the scripts**. The update script installs:
`shellcheck`, `bash`, `pwsh` (PowerShell), and the `PSScriptAnalyzer` module.

### Lint / validate (the build/test analog for this repo)
There is no `build`/`test`/`run` — the equivalent workflow is syntax-check + lint:

- bash syntax: `bash -n macos/<script>.sh`
- bash lint:   `shellcheck -s bash macos/*.sh macos/superseded/*.sh`
- ps1 syntax:  parse with `[System.Management.Automation.Language.Parser]::ParseFile(...)` via `pwsh`
- ps1 lint:    `pwsh -NoProfile -Command "Invoke-ScriptAnalyzer -Path ./windows -Recurse"`

Gotchas:
- `shellcheck` and `PSScriptAnalyzer` **exit non-zero / report findings by design**
  (unused vars, `Write-Host`, trap-function "unreachable" false positives, etc.).
  These are style/warning findings, **not** build failures — every script parses cleanly.
- Do not "fix" these lint findings unless explicitly asked; they are intentional in
  many scripts (e.g. `Write-Host` for Endpoint Central logging, bare `&& || ` patterns).

### Running the scripts (important caveats)
- These scripts **target Windows/macOS and mutate a real machine** (registry, installed
  apps, launchd/services, gem trees). They cannot be run end-to-end on the Linux VM and
  must never be pointed at this VM as if it were a target host.
- The platform-independent *core logic* of some scripts can still be exercised on Linux.
  `macos/remediate-ruby-gem.sh` is the best example: it supports `DRY_RUN=1` (report only,
  delete nothing) and `NO_INSTALL=1` (skip `gem install`). It discovers `<gem>-*.gemspec`
  files under known Ruby trees (incl. `/Users/*/.rbenv`, `/Users/*/.gem`), so you can
  create a synthetic spec tree and run it with `DRY_RUN=1 NO_INSTALL=1` to verify the
  version-comparison and per-branch threshold logic without touching a real system.
- macOS-only commands (`stat -f`, `scutil`, `defaults`, `sw_vers`, `pmset`, `hdiutil`)
  behave differently or print noise on Linux `coreutils` — e.g. `stat -f` prints
  filesystem info instead of the file owner. This is cosmetic and does not affect the
  portable logic; full runtime fidelity requires an actual macOS/Windows host.
