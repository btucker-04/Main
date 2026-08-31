# Script Arguments Reference

A per-script list of the arguments each remediation/diagnostic script accepts, with a brief description of what each one does. Defaults are shown where the script defines one.

For deployment conventions (Endpoint Central / Mosyle), exit-code meanings, and cross-cutting design notes, see the top-level [`README.md`](../README.md).

## How arguments are passed

- **Windows (PowerShell / Endpoint Central):** arguments are real PowerShell `param()` entries. They are passed as bare switches (e.g. `-DryRun`) or named values (e.g. `-TargetVersion 1.30.80`). EC invokes scripts with `-File`, so pass switches only (no `$` or quotes). Most scripts that change state accept `-DryRun` (or `-WhatIf`) to preview.
- **macOS (bash / Mosyle):** **Mosyle passes no environment variables.** Scripts that take configuration expose either an in-script `CONFIG`/constant block you edit before deploying, and/or read environment variables when run from a terminal. A few also accept positional arguments. Each script below notes which mechanism it uses.
- Wherever a script reads a value as `${VAR:-default}` it is listed as an **environment variable**; where it is a plain top-of-file assignment it is listed as an **in-script constant** (edit before deploying — it cannot be overridden at runtime under Mosyle).

---

# Windows (`windows/`)

## Update-VisualStudio.ps1
Updates every installed Visual Studio instance to the latest build of its channel.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-ForceCloseVS` | switch | off | Close a running `devenv.exe` before updating that instance instead of skipping it. Can lose unsaved work. |
| `-DryRun` | switch | off | Report the instances found and the intended actions without changing anything. |

## Update-Wsl2.ps1
Updates WSL2 via `wsl --update --web-download`. **No arguments.**

## Update-WinGet.ps1
Updates WinGet / App Installer (Microsoft.DesktopAppInstaller) via the AppX/DISM layer.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-TargetVersion` | string | `1.30.80` | Minimum acceptable version (the fix for CVE-2026-68821). |
| `-InstallerPath` | string | `''` | Path to a staged `Microsoft.DesktopAppInstaller*.msixbundle`. If empty, searches beside the script then `C:\`, then downloads from `https://aka.ms/getwinget`. |
| `-DryRun` | switch | off | Report current version and the resolved installer without installing. |

## Update-ThirdPartyAppBundle.ps1
Bundle remediation (Notepad++, Cursor, Office C2R) for the cspc-100 profile.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-RemoveCursor` | switch | off | Remove per-user Cursor install(s) entirely instead of just notifying the user. |
| `-ForceCloseApps` | switch | off | Kill `notepad++.exe` / `Cursor.exe` if running instead of skipping the component. |
| `-SkipNotepadPP` | switch | off | Skip the Notepad++ component. |
| `-SkipCursor` | switch | off | Skip the Cursor component. |
| `-SkipOffice` | switch | off | Skip the Office Click-to-Run component. |
| `-DryRun` | switch | off | Log every action without changing anything. |

## Update-OracleJava8.ps1
Updates Oracle Java SE 8 JRE to 8u491+ from a staged installer.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-InstallerPath` | string | `''` | Full path to `jre-8u491(or later)-windows-x64.exe`. Defaults to the first `jre-8u*-windows-x64.exe` found beside the script (then `C:\`). Never downloads. |
| `-ForceCloseJava` | switch | off | Kill running `java.exe` / `javaw.exe` before installing. Default is to abort (exit 2) if Java is running so a human decides. |
| `-DryRun` | switch | off | Report what would happen without changing anything. |

## Update-OfficeC2R.ps1
Channel-agnostic Office Click-to-Run updater.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-WaitMinutes` | int | `0` | Minutes to poll for the reported version to advance. `0` = fire and exit without waiting. |
| `-ForceAppShutdown` | bool | `$true` | Force-close open Office apps so the update finalizes immediately. Pass `-ForceAppShutdown:$false` to stage in the background and finalize only when the user closes Office. |

## Update-DellBios.ps1
Stages a model-appropriate Dell BIOS update via Dell Command | Update, with firmware safety guards.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-BiosPassword` | string | `''` | BIOS admin/setup password, if one is set. Without it the flash can fail (often silently) on protected systems. |
| `-MinBatteryPercent` | int | `30` | Minimum battery charge required on laptops before flashing (desktops on AC pass automatically). |
| `-RebootAfter` | switch | off | Restart immediately after staging so the flash applies and BitLocker resumes promptly. |
| `-DryRun` | switch | off | Scan and report only; does not suspend BitLocker and does not flash. |

## Update-DotNetRuntimes.ps1
Patches every installed .NET runtime channel to its latest build and prunes superseded versions.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-DryRun` | switch | off | Preview all phases without downloading, installing, uninstalling, or deleting. |
| `-RemoveStaleFolders` | switch | off | Delete superseded version folders that survive uninstall with no Installer dependency references (guarded by an in-use test). |
| `-AbortOnPendingReboot` | switch | off | Exit 3010 immediately when a reboot is pending, instead of running installs that may roll back. |
| `-RemoveSupersededSdks` | switch | off | Remove superseded .NET SDKs within a major (keeps the newest). Guarded by a `global.json` pin scan. Build-environment change. |
| `-RemoveOrphanedRegistrations` | switch | off | Uninstall ARP registrations with no runtime payload backing them — a whole major with zero payload anywhere (inventory hygiene), or a specific flavor/arch/major with zero payload even though that major exists elsewhere on the host (this second case clears a real version finding; Tenable plugin 326863 reads the ARP `DisplayVersion` directly). |

## Update-NodeJS.ps1
Updates the Program Files Node.js MSI install, staying on its major line.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-TargetVersion` | string | `''` | Explicit version to install (e.g. `22.23.0`). Default is resolved from the installed major line via the advisory's fixed-version map. |
| `-InstallerPath` | string | `''` | Full path to a staged Node MSI. If empty, searches beside the script then `C:\`, then downloads from nodejs.org. |
| `-ForceCloseNode` | switch | off | Kill running `node.exe` before installing. Default aborts (exit 2) if Node is running. |
| `-DryRun` | switch | off | Report what would happen without changing anything. |

## Update-Chrome.ps1
Downloads and installs the latest Chrome enterprise MSI.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-DryRun` | switch | off | Report actions (download, close, install) without performing them. |
| `-MinVersion` | string | `149.0.7827.53` | Minimum acceptable Chrome version (the higher of the two plugin thresholds); the install is verified against it. |

## Get-DriveInventory.ps1
Read-only drive/storage inventory. **No arguments.**

## Stop-NessusAgentService.ps1
Pre-install helper that stops the Nessus Agent service before an MSI upgrade. **No arguments.** Requires administrator.

## NessusAgent_CleanReinstall.ps1
Full teardown + reinstall of a broken Nessus Agent, with optional relink.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-MsiPath` | string | `''` | Path to the Nessus Agent MSI. If empty, searches the script directory then `C:\` for `NessusAgent-*.msi`, preferring the architecture-matching, highest-versioned file. |
| `-LinkKey` | string | embedded CompoSecure key | Tenable linking key used to relink after install. |
| `-LinkGroups` | string | `''` | Agent group(s) for relink. If empty, groups are resolved per-host from the embedded prefix-rule/override map. |
| `-LinkHost` | string | `sensor.cloud.tenable.com` | Tenable manager host. |
| `-NoLink` | switch | off | Install without linking (skip the relink step). |
| `-DryRun` | switch | off | Log every action without changing anything. |

## Repair-NessusAgent.ps1
Checks agent state and fixes only what is broken (installs if missing, ensures service running, links/relinks).

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-LinkKey` | string | embedded CompoSecure key | Tenable linking key. |
| `-LinkHost` | string | `sensor.cloud.tenable.com` | Tenable manager host. |
| `-LinkGroups` | string | `''` | Agent group(s) to join. If empty, resolved from the prefix-rule/override map; a host that resolves to no group exits 2. |
| `-ForceRelink` | switch | off | Unlink and relink even if the agent reports healthy. |

## Set-NessusAgentLink.ps1
Relinks the agent with group preservation (Windows).

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-LinkKey` | string | embedded CompoSecure key | Tenable linking key. |
| `-LinkHost` | string | `sensor.cloud.tenable.com` | Tenable manager host. |
| `-FallbackGroups` | string | `''` | Groups to use for a host not in the embedded map. If empty, such a host is skipped (exit 2) rather than relinked with no group. |

## Get-NessusAgentState.ps1
Read-only triage returning a single verdict token. **No arguments.**

## Get-NessusAgentInstallDiagnostics.ps1
Read-only diagnostic collection for a failed agent install (1603/1612). **No arguments.**

## Remove-Msxml5.ps1
Removes the orphaned MSXML5 DLL (quarantines for rollback).

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-WhatIf` | switch | off | Preview only (provided via `SupportsShouldProcess`); shows what would be unregistered/quarantined without changing anything. `-Confirm` is likewise available. |

## Repair-UnquotedServicePath.ps1
Quotes service `ImagePath` values that contain unquoted spaces. Requires administrator.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-WhatIf` | switch | off | Preview only (via `SupportsShouldProcess`); reports the services it would fix without writing to the registry. |

## Remove-DotNetEolChannel.ps1
Removes an end-of-support .NET runtime channel (default major 6).

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-Major` | int | `6` | The .NET major channel to remove. Local/terminal use (do not pass a valued parameter through EC). |
| `-DotNet9` | switch | off | Shorthand for `-Major 9`; a bare switch that survives EC's argument field. |
| `-Force` | switch | off | Proceed even if a non-Microsoft (or other-major) product holds a WiX dependency on this channel. Will break that app — confirm with the owner first. |
| `-RemoveStaleFolders` | switch | off | After uninstall, delete leftover `shared\`/`host\fxr\` folders and orphan Package Cache installers for this major when no live dependent remains. |
| `-DryRun` | switch | off | Report what would be removed; change nothing. |

## Remove-3DViewer.ps1
Removes the Microsoft 3D Viewer Store app.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-CleanOrphanedProfiles` | switch | off | Remove on-disk profiles whose SID no longer resolves to an account (deleted users), then retry package removal. Only unloaded, non-special profiles are touched. |
| `-DryRun` | switch | off | Report what would be removed without removing anything. |

## Fix-InsecureServicePermissions.ps1
Tightens loose `Users` ACLs on the flagged SolidWorks service directories.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-DryRun` | switch | off | Show current ACLs and what would change, without modifying anything. |

## Get-DotNetDependencyReferences.ps1
Read-only: lists MSI dependency providers holding references on old .NET versions.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-VersionMatch` | string | `10.0.3` | Version string to match in provider key names. |

## Get-DotNetArtifactInventory.ps1
Read-only: classifies where each .NET version exists (live / cache-only / orphan). **No arguments.**

## Get-VisualStudioInstallerLogs.ps1
Read-only: dumps the tail of recent Visual Studio installer logs. **No arguments.**

## Update-ClaudeCode.ps1
Remediates per-user Claude Code installs (plugin 322792 / CVE-2026-54316). Because Claude Code lives under the user's own profile, SYSTEM cannot update it directly; the default mode stages the update into that user's `RunOnce` so it runs as them at next logon.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-TargetVersion` | string | `2.1.163` | Minimum acceptable version (the fix for CVE-2026-54316). |
| `-RemoveClaudeCode` | switch | off | Remove the per-user install(s) outright instead of staging an update. Immediate and verifiable, but destructive to that user's tool. |
| `-NotifyUser` | switch | off | Also send a console message to any logged-on user so the next-logon update isn't a surprise. |
| `-DryRun` | switch | off | Report every install found and the intended action without changing anything. |

## Get-AppxBundleContents.ps1
Read-only: reports which version(s) an `.msixbundle`/`.msix` actually contains, so a staged installer can be verified before or after provisioning. Note the bundle's own Identity version is *not* the app version.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-BundlePath` | string | `''` | Path to the `.msixbundle`/`.msix` to inspect. If empty, searches beside the script then `C:\` for `Microsoft.DesktopAppInstaller*.msixbundle`. |
| `-TargetVersion` | string | `1.30.80` | Version the contained application packages are judged against (the fix for plugin 334617 / CVE-2026-68821). |
| `-ExpectedName` | string | `Microsoft.DesktopAppInstaller` | Package Identity name to sanity-check, so a completely wrong artifact is called out. |

## windows/superseded/Repair-NessusAgentOrphanInstall.ps1
Superseded by `NessusAgent_CleanReinstall.ps1`. Retained for reference.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-MsiPath` | string | `''` | Path to the Nessus Agent MSI. If empty, searches beside the script, then `C:\NessusAgent-11.2.0-x64.msi`. |

---

# macOS (`macos/`)

> Reminder: Mosyle passes no environment variables. For Mosyle deployment, set values in the script's `CONFIG`/constant block. Environment variables and positional arguments below apply to local/terminal runs.

## set-nessus-agent-link.sh
Relinks the Nessus Agent with per-host group preservation. Configuration is via **in-script constants** (edit before deploying — not environment-overridable as written).

| Constant | Default | Description |
|----------|---------|-------------|
| `LINK_KEY` | embedded CompoSecure key | Tenable linking key. |
| `LINK_HOST` | `sensor.cloud.tenable.com` | Tenable manager host. |
| `FALLBACK_GROUPS` | `''` | Groups for a host not matched by the prefix map. If empty, such a host is skipped (exit 2) rather than linked with no group. |

## repair-nessus-agent.sh
Checks agent state and fixes only what is broken. Reads **environment variables** (usable from a terminal).

| Environment variable | Default | Description |
|----------------------|---------|-------------|
| `LINK_KEY` | embedded CompoSecure key | Tenable linking key. |
| `LINK_HOST` | `sensor.cloud.tenable.com` | Tenable manager host. |
| `LINK_GROUPS` | `''` | Override group resolution with an explicit group set. If empty, resolved from the prefix map. |
| `FORCE_RELINK` | `0` | Set `1` to unlink and relink even if the agent reports healthy. |

## update-adobe-rum.sh
Generic Adobe updater via Remote Update Manager. Reads **environment variables**.

| Environment variable | Default | Description |
|----------------------|---------|-------------|
| `TARGETS` | `''` | Semicolon-separated `NamePattern=MinVersion` pairs; any listed app still below its minimum makes the run fail (exit 1). |
| `SAP_CODES` | `''` (unfiltered) | Comma-separated SAP codes to target specific Adobe products (e.g. `PHSP,ILST`). Falls back to unfiltered unless `NO_FALLBACK=1`. |
| `FORCE_CLOSE` | `0` | Set `1` to quit running Adobe apps instead of aborting (exit 2). |
| `NO_FALLBACK` | `0` | Set `1` to not retry unfiltered when a targeted call fails. |
| `DRY_RUN` | `0` | Set `1` to inventory + run `RUM --action=list` only; install nothing. |
| `IGNORE_HELPERS` | `1` | Set `0` to treat Adobe background helper/XPC processes as blockers (strict behavior). |

## remediate-ruby-gem.sh
Generic vulnerable-gem remediator. Accepts, in precedence order, **positional args > environment variables > in-script `CONFIG` block**.

| Positional | Environment | CONFIG default | Description |
|-----------|-------------|----------------|-------------|
| `$1` | `GEM` | `CFG_GEM="rexml"` | Gem name (required). |
| `$2` | `THRESHOLDS` | `CFG_THRESHOLDS="3.4.2"` | Either a single minimum (`3.4.2`) or per-branch `prefix:minimum` pairs (`0.4:0.4.24;0.5:0.5.14;0.6:0.6.4`) (required). |
| `$3` | `PLUGIN` | `CFG_PLUGIN="265895"` | Plugin ID, for the log header only. |
| — | `NO_INSTALL` | `CFG_NO_INSTALL="0"` | Set `1` to clean up only; never install a patched gem. |
| — | `DRY_RUN` | `CFG_DRY_RUN="0"` | Set `1` to report only, delete nothing. |

Example (terminal): `./remediate-ruby-gem.sh net-imap "0.4:0.4.24;0.5:0.5.14;0.6:0.6.4" 313278`

## update-claude-code.sh
Updates per-user Claude Code installs under `/Users/*/.local/bin/claude` (plugin 322792 / CVE-2026-54316). Runs `claude update` as each owning user via `sudo -u`, which works even when that user is not logged in. Reads **environment variables**, with an in-script `CONFIG` block for Mosyle.

| Environment variable | CONFIG default | Description |
|----------------------|----------------|-------------|
| `TARGET_VERSION` | `CFG_TARGET_VERSION="2.1.163"` | Minimum acceptable version. |
| `ONLY_USER` | `CFG_ONLY_USER=""` | Restrict to a single account; empty means every user with an install. |
| `DRY_RUN` | `CFG_DRY_RUN="0"` | Set `1` to report only and change nothing. |

## update-golang.sh
Updates Go (official tree + Homebrew; per-user managers report-only). Reads **environment variables**, with an in-script `CONFIG` block for Mosyle.

| Environment variable | CONFIG default | Description |
|----------------------|----------------|-------------|
| `DRY_RUN` | `CFG_DRY_RUN="0"` | Set `1` to report only; change nothing. |
| `FORCE_CLOSE` | `CFG_FORCE_CLOSE="0"` | Set `1` to terminate running Go toolchain processes before swapping `/usr/local/go`. Default refuses to swap under a running compile. |

## get-mac-reboot-reason.sh
Read-only diagnostic explaining the last restart. Reads one **environment variable**.

| Environment variable | Default | Description |
|----------------------|---------|-------------|
| `LOOKBACK_DAYS` | `30` | How many days back to search logs / panic reports (also the fallback window when the boot epoch cannot be parsed). |

## mac-update-force-after-1day.sh
Notifies of pending macOS updates and force-installs after a grace period. Configuration is via **in-script constants** (edit before deploying).

| Constant | Default | Description |
|----------|---------|-------------|
| `DEFER_SECONDS` | `86400` (24h) | Grace period a pending update may be deferred before it is force-installed. |
| `GRACE_SECONDS` | `300` (5 min) | On-screen warning window before the forced install starts. |
| `DRY_RUN` | `false` | Set `true` to log every action but never actually install/reboot. |
| `STATE_FILE` | `/var/db/.cs_update_first_seen` | Where the first-seen timestamp is recorded. |

## mac-update-notify.sh
Prompts the logged-in user to install pending macOS updates. **No arguments.**

## update-intellij.sh
Updates IntelliJ IDEA to the fixed version (force-closes a running IDE). **No runtime arguments** (target version is an in-script constant `TARGET_VERSION`).

## update-nodejs.sh
Updates Node.js across Homebrew / official pkg (per-user managers report-only). **No runtime arguments** (fixed versions are in-script constants `FIX_22`/`FIX_24`/`FIX_26`).

## update-powershell.sh
Updates PowerShell to the fixed version. **No arguments** (self-escalates via `sudo`; target is the in-script constant `FIXED_VERSION`).

## macos/superseded/*
Retained for reference/rollback; prefer the replacements noted in each header (the Ruby-gem scripts are superseded by `remediate-ruby-gem.sh`; `update-photoshop.sh` by `update-adobe-rum.sh`).

- `superseded/ruby-netimap-cellar-cleanup.sh` — **No arguments** (thresholds are in-script constants).
- `superseded/ruby-netimap-update.sh` — **No arguments** (thresholds are in-script constants).
- `superseded/remediate-rexml.sh` — **No arguments** (self-escalates via `sudo`; fixed version is a constant).
- `superseded/cleanup-rexml-gemspec.sh` — **No arguments** (self-escalates via `sudo`; fixed version is a constant).
- `superseded/update-photoshop.sh` — reads **environment variables** `FORCE_CLOSE` (default `0`, quit a running Photoshop) and `NO_FALLBACK` (default `0`, keep the run Photoshop-only instead of retrying `RUM` unfiltered).
