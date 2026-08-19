# CompoSecure Remediation Scripts

Vulnerability remediation scripts for CompoSecure's mixed Windows/macOS fleet, built against Tenable Vulnerability Management findings and deployed via **Endpoint Central** (Windows) or **Mosyle** (macOS).

Scripts are organized by platform. Each targets one or more Tenable findings; script headers document the plugin ID(s), affected hosts (where known), exit codes, and any environment-specific quirks that shaped the implementation.

## Layout

```
windows/              PowerShell scripts, deployed via Endpoint Central
windows/superseded/   retained for reference/rollback; prefer the replacement noted in each header
macos/                bash scripts (3.2-compatible), deployed via Mosyle
macos/superseded/     retained for reference/rollback; prefer the replacement noted in each header
```

## Deployment conventions

**Windows (Endpoint Central)**
- Execute from Repository, `-File` invocation only — never inline `-Command` strings. EC has been observed mangling `$variables` and introducing smart quotes in inline commands; every script here avoids that by keeping all logic in the file and taking arguments as plain switches with no `$` or quote characters.
- Script arguments are bare switches (e.g. `-RemoveOrphanedRegistrations`), which pass through EC's argument field without alteration.
- **Success exit codes should be configured as `0,3010`** in EC's "Specify exit code(s)" field. `3010` means the operation succeeded and a reboot is required — it is not a failure. Exit `2` is deliberately excluded from success in most scripts here; it means a human needs to make a decision (an SDK or hosting bundle pinning a framework, a host needing a reboot before proceeding, an agent linked with no scan group, etc.), and having those surface as "failed" in EC is the correct, intentional signal.
- Logs write to `C:\Logs\CompoSecure\`.
- Native executables (`msiexec.exe`, etc.) are invoked by full path with `-NoNewWindow` rather than as a bare filename — `Start-Process -FilePath 'msiexec.exe'` resolves through ShellExecute and fails under EC's SYSTEM context with "No application is associated with the specified file."

**macOS (Mosyle)**
- bash 3.2-compatible throughout (no `mapfile`/`readarray`) — Mosyle's runtime.
- `HOME` is explicitly defaulted (`HOME="${HOME:-/var/root}"`) since Mosyle runs scripts as root with no `HOME` set.
- Console-user detection falls back to the Homebrew owner when no one is logged in, so scripts still work on an unattended machine.
- **Mosyle passes no environment variables.** Scripts that take configuration (e.g. `remediate-ruby-gem.sh`) expose a `CONFIG` block at the top of the file to edit before deploying, with environment-variable overrides supported for local/terminal use.
- Logs write to `/var/log/composecure/`.

## Cross-cutting lessons (apply across multiple scripts)

- **Tenable often keys findings on file/folder presence, not on what a package manager reports.** Updating a Ruby gem, a .NET runtime, or similar often leaves the *old* artifact on disk in a separate location (a Homebrew Cellar spec, a side-by-side .NET version folder) even after the update succeeds — the finding won't clear until that artifact is actually removed. Scripts here separate "update" from "cleanup" but run both, gated on confirming the update actually landed first.
- **A vendor tool's exit code is not proof it did the work.** Observed directly: a WiX-based installer with registered dependents can skip its own uninstall and still return success; Adobe's Remote Update Manager can exit 0 while leaving an app on its old version. Scripts verify by re-reading the actual state (installed version, registry entry, file presence) rather than trusting the exit code.
- **"Is the app running?" must match the app's own main binary, not any process under its install path.** Background helpers, XPC services, and crash reporters run persistently whether or not the application itself is open; matching them as a running-app signal can block an update indefinitely on every machine that has the app installed.
- **Per-user installs are invisible to SYSTEM/root-context deployment.** Apps installed under a user's own profile (`%LOCALAPPDATA%`, `~/Applications`-style per-user installs) can't be reliably queried or updated by a script running as SYSTEM/root — the deployment tool will typically report "Not Applicable." These need either user-context execution or a machine-level reinstall path.
- **Version comparisons must be scoped per release branch/major, not global.** Independent release lines (e.g. a library fixed at 0.4.24 on its 0.4 branch, 0.5.14 on 0.5, 0.6.4 on 0.6) each have their own fixed version — comparing a version against a single global minimum can misjudge which artifacts are actually safe to remove.
- **Prefer prefix/pattern-based configuration over exhaustive per-host lists.** A hostname-to-value lookup table goes stale the moment a new machine is added; a small set of pattern rules plus a short list of explicit exceptions covers new machines automatically and is far easier to keep in sync.

## Naming exceptions

Two scripts keep their original names rather than following the Verb-Noun/expanded-abbreviation
pattern used elsewhere, by explicit decision during review:

- `windows/NessusAgent_CleanReinstall.ps1` (not renamed to a Verb-Noun form)
- `windows/Update-OfficeC2R.ps1` (kept the `C2R` abbreviation rather than spelling out Click-to-Run)

## Superseded scripts

Scripts in a `superseded/` folder remain for historical reference and rollback but should not be used for new deployments. Each superseded script's header names its replacement and why it was replaced (typically: consolidated into one parameterized script covering a whole family of findings, e.g. several Ruby-gem-specific scripts were replaced by one generic gem remediator).

## Diagnostics

Several scripts are read-only diagnostics (`Get-*` on Windows, no-mutation scripts on macOS) rather than remediations. These are safe to run at any time and are meant to be run *before* a remediation attempt when the cause of a finding isn't immediately clear (e.g. confirming whether a .NET version is held by an SDK dependency before assuming a cleanup script's refusal is a bug).

## Disclaimer

These scripts were built iteratively against specific findings and hosts in one environment. Review each script's header and test in a non-production scope before wide deployment — several are documented as having been revised after a real deployment surfaced a bug (subshell scoping issues, incorrect assumptions about a vendor tool's behavior, etc.); those revision notes are kept in place deliberately as a record of what failed and why.
