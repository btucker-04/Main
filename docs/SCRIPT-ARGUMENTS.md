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
Updates WSL to the current release via `wsl --update --web-download`. **No arguments and no minimum version.** A completed update is success. The version `wsl` prints (`Updating ... to version: 2.7.14`) is logged when present. An unreadable Appx version after exit 0 is a warning, not a failure — under SYSTEM that read often comes back empty and must not be treated as `0.0.0`.

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

The Notepad++ component pins 8.9.6.1, which no longer clears plugin 327203 (< 8.9.7). For Notepad++ use `Update-NotepadPlusPlus.ps1`, or run this bundle with `-SkipNotepadPP`.

## Update-NotepadPlusPlus.ps1
Updates every installed Notepad++ to the **latest release**, resolved at run time from where `github.com/notepad-plus-plus/notepad-plus-plus/releases/latest` redirects (no pinned version, no REST API rate limit). Clears plugins 327203 (< 8.9.7), 318684 (< 8.9.6.1), 299664 (< 8.9.2) and later ones. Finds installs in both Program Files folders and in any Notepad++ uninstall entry's `InstallLocation`. It upgrades each install in place with the installer for that install's architecture (x64, x86 or arm64, read from `notepad++.exe`), using the release MSI for MSI-managed x64 installs. Before running an installer it checks the PE or MSI header, the SHA-256 in the release's `checksums.sha256`, and an Authenticode signature from `CN=NOTEPAD++`. It defers while `notepad++.exe` is running and messages the user. Success is judged by re-reading the file version. Offline or Zscaler-blocked hosts: stage `npp.<ver>.Installer.x64.exe` (or `.Installer.exe` for x86) in Dependency Files or `C:\`. Exit `0` = all current or not installed, `2` = deferred / not verified / dry run with work, `1` = no target version, or download / checksum / signature failed.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-ForceClose` | switch | off | Kill running `notepad++.exe` before installing (Notepad++ usually restores unsaved tabs from its session backup, but that is a user setting). |
| `-DryRun` | switch | off | Report what would be installed and change nothing. |
| `-TargetVersion` | string | latest release | Install a specific version (e.g. `8.9.8.1`). Not needed for EC; leave blank. |

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
| `-LeaveUpdatesDisabled` | switch | off | If `UpdatesEnabled` is False, report it and exit `2` instead of temporarily overriding it. |
| `-NotifyMinutes` | int | `0` | Warn the signed-in user N minutes before open Office apps are force-closed: a message box (`msg.exe`) lists the open apps, then the script waits N minutes before triggering the update. Skipped when no Office app is open, and ignored with `-ForceAppShutdown:$false`. `0` = no warning. |
| `-NotifyMessage` | string | (built-in) | Custom warning text. Default names the open apps and the delay. |

## Get-OfficeC2RState.ps1
Read-only check for an Office C2R finding that stays open after `Update-OfficeC2R.ps1` (which only launches the update and exits 0). Reports the file versions of the Office binaries on disk (what Tenable reads) in both Program Files roots, for C2R and MSI layouts. Alongside them it reports C2R's `VersionToReport`, the channel, `UpdatesEnabled` / `UpdateToVersion`, the GPO and cloud-policy update settings, running Office apps, and error lines from the newest C2R logs in `C:\Windows\Temp`. Prints one `VERDICT:` line and appends a row to `C:\Logs\CompoSecure\OfficeC2RState.csv`. The verdicts, most severe first: `NOT_C2R`, `LEFTOVER_FILES`, `PINNED_TARGET`, `UPDATES_DISABLED`, `CUSTOM_SOURCE`, `PENDING_APPLY` (a newer build is downloaded in `Updates\UpdatesReadyToApply` but not applied because Office apps are open), `NOT_FINALIZED`, `BELOW_EXPECTED`, `CONSISTENT`. `Updates\*Time` values are decoded to UTC dates in the log. Exit `0` = report written, `1` = could not create the log folder.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-ExpectVersion` | string | none | Fixed build from the Tenable finding (e.g. `16.0.20228.20190`). Any active Office binary below it is reported as `BELOW_EXPECTED`. |

## Remediate-OfficeMacroSecurity.ps1
Plugins 123459 and 123461 (replaces `Disable-OfficeVbaProjectAccess.ps1`). Fixes the Office Trust Center macro settings Tenable flags, for every Office app and version: `AccessVBOM` nonzero → `0` (VBA project access), `VBAWarnings` `1` (enable all macros) → `2` (disable with notification, the Office default), and Outlook `Level` `1` → `2`. Stricter values (`VBAWarnings` 3/4) are left alone. Covers HKLM (both registry views), every local user profile, and the Default profile new accounts copy.

Users' hives that are already loaded (signed in, left mounted by an earlier script, or loaded under a different key) are found through `HKLM\SYSTEM\CurrentControlSet\Control\hivelist` and written through the key that holds them, so `reg load` never hits the "in use" error for them. `reg load` is only used for hives that are not loaded anywhere; if it still fails (the file is held open by something other than the registry), the script logs the loaded hives and registers an Active Setup component (`CompoSecure-OfficeMacroSecurity`) that runs the same fix once as each user at their next sign-in. The script relaunches itself in 64-bit PowerShell when EC starts it as 32-bit, so 64-bit Office's HKLM settings are read. Group Policy / Intune values (`SOFTWARE\Policies\...`) are reported, not changed, unless `-EnforcePolicy`. Exit `0` = nothing flagged remains, `2` = still flagged in a policy value or a hive could not be opened, `1` = a write failed.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-EnforcePolicy` | switch | off | Also write per-user policy values (`AccessVBOM` 0, `VBAWarnings` 2, Outlook `Level` 2) for Office 16.0 (Excel, Word, PowerPoint, Access, Outlook, Visio, Project, Publisher). Greys out the options so users cannot change them back, and overwrites local policy values. A real GPO/Intune policy still wins at its next refresh. |
| `-DryRun` | switch | off | Report what would change without writing anything. |

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
| `-RemoveSupersededSdks` | switch | off | First installs the current SDK patch for every (major, arch) present — x86 included — then removes superseded .NET SDKs within a major (keeps the newest). Guarded by a `global.json` pin scan. Build-environment change. |
| `-RemoveOrphanedRegistrations` | switch | off | Uninstall ARP registrations with no runtime payload backing them — a whole major with zero payload anywhere, or a specific flavor/arch/major with zero payload even though that major exists elsewhere on the host. Both cases can clear a real version finding, not just tidy inventory: plugin 326863 and the "Security Update for Microsoft .NET Core" plugin family both read the ARP `DisplayVersion` directly. |
| `-InstallSuccessorMajor` | switch | off | For each EOL major found installed, or one within 180 days of its end of support, also install the mapped successor major (`$EolSuccessorMajor`; currently 8 → 10 and 9 → 10) alongside it — purely additive, never removes or retargets anything. Does not clear the SEoL finding by itself; apps must still be recompiled or opt into `"rollForward": "LatestMajor"` before they use the new major. |
| `-RemoveRetiredMajor` | switch | off | Implies `-InstallSuccessorMajor`. After verification (Phase 4), removes the EOL or near-EOL major, such as .NET 8, by running `Remove-DotNetEolChannel.ps1 -DotNet<N> -RemoveStaleFolders`. Stage that script as a Dependency File. It runs only when the successor is on disk for every flavor/arch that had the old major, and the rest of the run succeeded with no reboot pending. It refuses, with exit 2, when any of these is found: an app `*.runtimeconfig.json` that targets the old major without `rollForward` `Major`/`LatestMajor` (scanned in Program Files, ProgramData, `C:\inetpub`, user AppData and `.dotnet\tools`), an SDK or hosting bundle of that major, or a non-Microsoft WiX holder (checked by the removal script). |

Exit for `Update-DotNetRuntimes.ps1`: `0` = done, `3010` = reboot needed, `1` = failed, `2` = updates done but `-RemoveRetiredMajor` refused and a human decides. Keep EC success codes `0,3010`.

## Update-NodeJS.ps1
Updates the Program Files Node.js MSI install to the latest release of its installed major line, looked up at run time from `https://nodejs.org/dist/index.json`. No pinned target version; if nodejs.org is unreachable, the newest staged `node-v<major>.x.y-<arch>.msi` is used.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-TargetVersion` | string | `''` | Explicit version to install (e.g. `22.23.3`), for a deliberate pin or major jump. Default: the latest release of the installed major line. |
| `-InstallerPath` | string | `''` | Full path to a staged Node MSI. If empty, searches beside the script then `C:\`, then downloads from nodejs.org. |
| `-ForceCloseNode` | switch | off | Kill running `node.exe` before installing. Default aborts (exit 2) if Node is running. |
| `-DryRun` | switch | off | Report what would happen without changing anything. |

## Update-Chrome.ps1
Downloads and installs the latest Chrome enterprise MSI.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-DryRun` | switch | off | Report actions (download, close, install) without performing them. |
| `-MinVersion` | string | `149.0.7827.53` | Minimum acceptable Chrome version (the higher of the two plugin thresholds); the install is verified against it. |

## Update-CitrixWorkspace.ps1
Upgrades Citrix Workspace app (CWA) from a staged installer (target: 2607 LTSR) and moves the machine from .NET 8 to .NET 10. CWA 2409 through 2507.1 LTSR CU2 need the x86 .NET Desktop Runtime 8.x; 2607 LTSR needs 10.0.9 or later, so upgrading CWA is what lets .NET 8 (end of support 2026-11-10) be removed.

The script installs the x86 .NET Desktop Runtime 10 first when it is missing. It uses a staged `windowsdesktop-runtime-10.*-win-x86.exe` if present, otherwise downloads it from `aka.ms`, so the CWA installer never needs `downloadplugins.citrix.com`. It then runs the CWA installer with `/silent AutoUpdateCheck=disabled EnableCEIP=False` and verifies the new version in Add/Remove Programs. Finally it reports what still needs .NET 8: a CWA older than 26.7, or any app whose `*.runtimeconfig.json` binds to an 8.x shared framework without `rollForward: LatestMajor`. The scan covers Program Files and per-user `AppData\Local\Programs`. An app only counts when a .NET 8 runtime it can load is installed: the same framework, and the same architecture as the `.exe` beside its runtimeconfig. For example, an x64 app on a machine with only x86 .NET 8 is listed as "Not a blocker". The CWA install is allowed 60 minutes. An installer that reports no exit code is judged by the version check. It relaunches as 64-bit under the 32-bit EC agent.

**Architecture selection:** stage the 32-bit and 64-bit (and optionally ARM64) installers together; the script picks one per machine.
- 32-bit Windows always gets 32-bit.
- An existing 64-bit or ARM64 CWA keeps its architecture, since Citrix does not support going back to 32-bit.
- An existing 32-bit CWA stays 32-bit unless `-MigrateTo64Bit` is passed.
- A machine without CWA gets the native build, or 32-bit if that is the only one staged.

The installed architecture comes from CWA's install folder (`Program Files (x86)` means 32-bit), falling back to whether its uninstall entry is under WOW6432Node. A staged installer's architecture comes from its file name (`ARM64`, then `x64`/`amd64`/`64bit`), otherwise the executable's PE header, otherwise 32-bit; each file's detected architecture is logged. A switch to 64-bit at the same version is reported (exit 2), because Citrix's installer will not change architecture without a version change: uninstall the 32-bit build first.

Dependency files: the CWA installer(s) (required), plus optionally the .NET 10 x86 installer and `Remove-DotNetEolChannel.ps1`. Exit `0` = done, `3010` = done with reboot needed, `2` = deferred (open Citrix session) or .NET 8 still needed with `-RemoveDotNet8`, `1` = failed. Log: `C:\Logs\CompoSecure\CitrixWorkspace_<timestamp>.log`.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-InstallerPath` | string | `''` | Full path to one CWA installer, used as-is. Default: choose among the `CitrixWorkspace*.exe` files beside the script, then `C:\` (see architecture selection). Local use; in EC, stage the files. |
| `-MigrateTo64Bit` | switch | off | Replace a 32-bit CWA with the native 64-bit build (x64, or ARM64 on ARM devices) during the upgrade. Default keeps a 32-bit install 32-bit. Check for 32-bit third-party virtual channel add-ons first. |
| `-InstallIfMissing` | switch | off | Install CWA where it is not installed. Default upgrades existing installs only. |
| `-ForceClose` | switch | off | Close open Citrix sessions (`wfica32`, `CDViewer`) and CWA processes instead of deferring (exit 2). Disconnects the user. |
| `-AutoUpdate` | switch | off | Keep Citrix auto-update on, limited to LTSR cumulative updates (`AutoUpdateCheck=auto AutoUpdateStream=LTSR`). Default turns it off so EC controls the version. |
| `-SkipThirdPartyVCCheck` | switch | off | Pass `/SkipThirdPartyVCCheck`. Only for a 64-bit installer replacing a 32-bit CWA, where the silent install otherwise pauses or fails on 32-bit third-party virtual channel add-ons. Confirm none are in use. |
| `-ForceInstall` | switch | off | Pass `/forceinstall` (Citrix's cleanup-and-reinstall) for a retry after a failed upgrade. |
| `-SkipDotNetPrestage` | switch | off | Do not install .NET 10 x86 first; let the CWA installer download it. |
| `-RemoveDotNet8` | switch | off | When nothing still needs .NET 8, run the staged `Remove-DotNetEolChannel.ps1 -DotNet8 -RemoveStaleFolders` (also removes the swidtag and Package Cache leftovers Tenable reads). Blocked (exit 2) on a CWA below 26.7, without .NET 10 x86, or when a .NET 8 app is found; skipped after a failed upgrade. |
| `-DryRun` | switch | off | Report what would happen without changing anything (passes `-DryRun` to the remover too). |

## Update-VCRedist.ps1
Updates the Microsoft Visual C++ 2015-2022 (v14) runtimes to Microsoft's **latest**, and clears the broken Windows Installer registrations that block that upgrade.

On CSPRLT-94 (2026-10-26), "Microsoft Visual C++ 2022 X86 Minimum Runtime - 14.42.34433" had lost its cached `.msi`. Every upgrade, repair or uninstall failed with MSI 1714 / System Error 1612, so Citrix Workspace's prerequisite step exited 101603. Run this script first, then `Update-CitrixWorkspace.ps1`.

How it works:
- **Broken registrations:** a VC++ runtime MSI whose `LocalPackage` is missing, or a v14 bundle whose `BundleCachePath` is missing. Every key involved is exported to `C:\Logs\CompoSecure\VCRedist_backup_<timestamp>\` before anything is deleted (undo with `reg import`). Only Windows Installer's records are removed; the runtime DLLs stay, so apps keep working.
- **Target:** `vc_redist.<arch>.exe` staged beside the script or in `C:\`, else downloaded from `https://aka.ms/vc14/vc_redist.<arch>.exe`. That is Microsoft's current permalink; the older `aka.ms/vs/17/release` link stops at the VS 2022 build 14.44. There is no pinned version; the target is that file's own version. The file must have an MZ header and a Valid Authenticode signature from `O=Microsoft Corporation`.
- **Install:** for each architecture below the target, whose registration was cleared, or whose bundle is registered without its Minimum Runtime MSI. It first waits up to 10 minutes for Windows Installer to be idle. On 1618 (another install in progress) it logs the installer processes running and retries, up to 3 attempts.
- **Verify:** by re-reading Add/Remove Programs and the registrations. The version that counts is the Minimum Runtime MSI's, because a bundle entry can stay registered after its MSIs failed. `vcruntime140.dll` versions are logged before and after.
- **Unsupported 2005-2013 runtimes** are listed, and removed only with `-RemoveUnsupported`.

Exit `0` = current, `3010` = reboot needed, `2` = dry run with work / another install in progress / unsupported removal failed, `1` = no verified installer, or an install or cleanup failed.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-SkipBrokenCleanup` | switch | off | Report broken registrations but leave them. The upgrade of that architecture will then fail with 1714 / 1612. |
| `-InstallMissing` | switch | off | Also install the v14 runtime for architectures that have none (x86 and x64; plus arm64 on ARM64 Windows). |
| `-RemoveUnsupported` | switch | off | Uninstall Visual C++ 2005, 2008, 2010, 2012 and 2013 runtimes. Apps built against them stop working; use only where Tenable flags them and nothing needs them. A cache-less one has its registration cleared instead (its DLLs stay). |
| `-DryRun` | switch | off | Report what would be cleared, installed or removed; change nothing. |

## Remove-CitrixWorkspaceLegacy.ps1
Removes old Citrix Workspace app / Citrix Receiver copies that `Update-CitrixWorkspace.ps1` can't see: per-user installs and leftover files. Use it when Tenable reports an old Citrix Workspace version (for example plugin 207238, CTX691485) but the Update script logs `Citrix Workspace : not installed (machine-wide)`. That was the case on CSPRLT-94 on 2026-10-15.

**What it checks:** anything below 26.7 (the fleet target) is old. It looks in:
- machine uninstall entries (both registry views);
- every user's uninstall entries, including unloaded profiles, whose `NTUSER.DAT` is loaded temporarily;
- the `wfica32.exe`/`wfica.exe` binaries in `Program Files\Citrix\ICA Client`, `Program Files (x86)\Citrix\ICA Client` and each profile's `AppData\Local\Citrix\ICA Client`;
- the `Citrix\PluginPackages\XenAppSuite\ICA_Client` version key.

**What it removes:**
- **Per-user installs:** uninstalled with their own `TrolleyExpress.exe /uninstall /cleanup /silent`. Anything left behind is then deleted: the user's ICA Client, SelfService and AuthManager folders, the uninstall entry, and startup (Run) entries pointing into the folder.
- **Leftover machine files with no machine uninstall entry:** `ICA Client`, `SelfServicePlugin` and `AuthManager` under `Program Files\Citrix`, plus the PluginPackages key. Other Citrix products are not touched.
- **An old machine-wide install:** left for `Update-CitrixWorkspace.ps1` to upgrade (exit 2), unless `-IncludeMachineInstall` is passed.

An open Citrix session defers the run (exit 2) unless `-ForceClose`. Citrix will not install machine-wide over a per-user install, so `-ReinstallMachineWide` removes the per-user copy first and then runs the staged `Update-CitrixWorkspace.ps1 -InstallIfMissing`.

Dependency files: none for removal. With `-ReinstallMachineWide`, also stage `Update-CitrixWorkspace.ps1`, the CWA installers and optionally the .NET 10 x86 installer. Exit `0` = nothing old left, `3010` = reboot needed, `2` = deferred or old machine install left for the upgrade, `1` = failed or still present. Log: `C:\Logs\CompoSecure\CitrixWorkspaceLegacy_<timestamp>.log`.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-ForceClose` | switch | off | Close open Citrix sessions and CWA processes instead of deferring. |
| `-IncludeMachineInstall` | switch | off | Also uninstall an old machine-wide CWA (normally upgraded by `Update-CitrixWorkspace.ps1`). |
| `-ReinstallMachineWide` | switch | off | After cleanup, run the staged `Update-CitrixWorkspace.ps1 -InstallIfMissing` (passes `-ForceClose` and `-DryRun` through). |
| `-DryRun` | switch | off | Report what would happen; change nothing. |

## Install-SqlExpress2022.ps1
Installs SQL Server 2022 Express from staged offline media. It does not remove an older SQL Server; use `Remove-UnsupportedSqlServer.ps1` for plugin 64784. Stage `SQLEXPR_x64_ENU.exe` (Express Core) or `SQLEXPRADV_x64_ENU.exe` (Express Advanced, needed for `FullText`/`PolyBase`), taken from `SQL2022-SSEI-Expr.exe` > Download Media. The script extracts the package to `C:\Windows\Temp\SQLEXPR2022`, checks that `setup.exe` is version 16.x (SQL Server 2019 Express uses the same file name), and runs setup quietly. Setup runs as SYSTEM under EC, so it adds the `-SqlSysAdmins` accounts as sysadmins rather than the current user.

Stage a `SQLServer2022-KB<number>-x64.exe` cumulative update or GDR alongside the media. If several are staged, the highest KB number is used. A new install gets it slipstreamed (`/UPDATEENABLED=True /UPDATESOURCE`). An existing 2022 instance on an older build gets it with `/ACTION=Patch`. The RTM build (16.0.1000.6) is vulnerable, so always stage the current update. Without an update, setup runs with `/UPDATEENABLED=False`.

An existing instance of the same name is handled as follows:
- **SQL Server 2022:** left alone, apart from the staged update.
- **Older (for example 2019, `MSSQL15`):** reported (exit 2) unless `-UpgradeExisting` is passed.
- **Newer than 2022:** left alone.

A pending reboot defers the run (exit 2), because setup's RebootRequiredCheck rule would fail. Setup also needs .NET Framework 4.7.2 or later.

After installing, the script checks that the instance is registered as `MSSQL16.<name>`, logs its build, and checks that the service (`MSSQL$<name>`) is running. It copies the Final result and Exit message from setup's `Summary.txt` (`C:\Program Files\Microsoft SQL Server\160\Setup Bootstrap\Log`) into its own log. It relaunches as 64-bit under the 32-bit EC agent.

Dependency files: the Express package (required) and optionally the update. Exit `0` = installed or already present, `3010` = done with reboot needed, `2` = deferred (pending reboot) or an older instance needs `-UpgradeExisting`, `1` = failed. Log: `C:\Logs\CompoSecure\SqlExpress2022_<timestamp>.log`.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-InstanceName` | string | `SQLEXPRESS` | Instance to install. `MSSQLSERVER` installs the default instance. |
| `-Features` | string | `SQLEngine` | Comma-separated setup features. `FullText`/`PolyBase` need the Advanced package. |
| `-SqlSysAdmins` | string | `BUILTIN\Administrators` | Comma-separated Windows accounts or groups made sysadmin. |
| `-SaPassword` | string | `''` | Enables mixed-mode authentication with this `sa` password. Masked in the log, but visible in EC's script arguments; prefer Windows authentication. |
| `-EnableTcp` | switch | off | Enable TCP/IP (off by default for Express). The firewall is not changed. |
| `-TcpPort` | int | `0` | Fixed TCP port; implies `-EnableTcp`. `0` = dynamic. |
| `-DataDir` | string | `''` | Root folder for database files (`/INSTALLSQLDATADIR`). |
| `-MediaPath` | string | `''` | Full path to the package, an extracted media folder, or its `setup.exe`. Default: the `SQLEXPR*.exe` beside the script, then `C:\`. |
| `-UpgradeExisting` | switch | off | Upgrade an older instance of the same name in place (`/ACTION=Upgrade`). Back up its databases first. |
| `-IgnorePendingReboot` | switch | off | Install despite a pending reboot (`/SKIPRULES=RebootRequiredCheck`). |
| `-DryRun` | switch | off | Report what would happen without changing anything. |

## Remove-UnsupportedSqlServer.ps1
Removes end-of-support SQL Server database engine instances and LocalDB (Tenable plugin 64784, Microsoft SQL Server Unsupported Version Detection). Installing a newer SQL Server does not clear 64784, because the old engine stays installed alongside it until it is uninstalled. On CSLT-135, 64784 stayed active after the 2022 Express install.

As of 2026-10-14, SQL Server 2016 (extended support ended 2026-07-14) and earlier are unsupported. 2017 is supported until 2027-10-12. Supported instances, such as a 2022 Express install, are never touched.

What the script checks and removes:
- **Engine instances:** read from both registry views, so 32-bit instances (registered under WOW6432Node) are found too. Each unsupported instance is uninstalled with its own `setup.exe` from `<Program Files>\Microsoft SQL Server\<NNN>\Setup Bootstrap`, using `/Q /ACTION=Uninstall /FEATURES=SQL /INSTANCENAME=<name>`.
- **LocalDB:** found from `Local DB\Installed Versions` and removed through its MSI. Any running LocalDB `sqlservr.exe` is stopped first.
- **Leftover engine packages:** for example Database Engine Services, Common Files, Setup, RsFx, VSS Writer and Browser for that year. These are removed with `msiexec /x`, which also covers an instance whose `setup.exe` is missing or fails.
- **Client libraries are kept:** Native Client, ODBC / OLE DB, Management Objects, CLR Types and Management Studio. Other apps load them, and 64784 does not report them.

An unsupported instance with user database files in its DATA folder is not removed: the run exits 2 unless `-AllowUserDatabases` is passed. Uninstall keeps those files on disk either way. The script finishes by re-reading the inventory. It relaunches as 64-bit under the 32-bit EC agent.

Exit `0` = nothing unsupported left, `3010` = removed, reboot needed, `2` = blocked by user databases, `1` = failed or still installed. Log: `C:\Logs\CompoSecure\RemoveUnsupportedSql_<timestamp>.log`, with one MSI log per package.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-AllowUserDatabases` | switch | off | Remove an unsupported instance even if its DATA folder has user databases. The files stay on disk, so they can be attached to the supported instance. |
| `-KeepLocalDB` | switch | off | Leave unsupported LocalDB versions installed. |
| `-KeepSharedComponents` | switch | off | Skip removing the leftover engine packages. |
| `-DryRun` | switch | off | Report what would be removed; change nothing. |

## Get-DriveInventory.ps1
Read-only drive/storage inventory. **No arguments.**

## Stop-NessusAgentService.ps1
Pre-install helper that stops the Nessus Agent service before an MSI upgrade. **No arguments.** Requires administrator.

## NessusAgent_CleanReinstall.ps1
Full teardown + reinstall of a broken Nessus Agent, with optional relink.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-MsiPath` | string | `''` | Path to the Nessus Agent MSI. Leave empty in Endpoint Central: upload `NessusAgent-*.msi` as a Dependency File (EC extracts it into `$PSScriptRoot`). If empty, searches `$PSScriptRoot` then `C:\`, preferring the architecture-matching, highest-versioned file. Do not pass a quoted path as an EC argument. |
| `-LinkKey` | string | embedded CompoSecure key | Tenable linking key used to relink after install. |
| `-LinkGroups` | string | `''` | Agent group(s) for relink. If empty, groups are resolved per-host from the embedded prefix-rule/override map. |
| `-LinkHost` | string | `sensor.cloud.tenable.com` | Tenable manager host. |
| `-NoLink` | switch | off | Install without linking (skip the relink step). |
| `-WaitForInstallerMinutes` | int | `0` | How long to wait for a concurrent Windows Installer operation (`Global\_MSIExecute` held) to finish before giving up with exit 2. `0` checks once. Nothing is torn down while waiting, so raising this is safe; keep it under the EC script timeout. |
| `-IgnoreConcurrentMsi` | switch | off | Tear down even though another install holds the installer mutex. **Dangerous:** the teardown is destructive, so a reinstall that then fails with 1618 leaves the host with no agent. Use only when the mutex holder is known to be stuck. |
| `-DryRun` | switch | off | Log every action without changing anything. |

The pre-flight tests whether the installer mutex is *held*, not merely whether it exists — an idle `msiexec` service process keeps the object alive, which previously made the check report "install in progress" permanently (CSLT-192).

## Repair-NessusAgent.ps1
Checks agent state and fixes only what is broken (installs if missing, ensures service running, links/relinks).

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-LinkKey` | string | embedded CompoSecure key | Tenable linking key. |
| `-LinkHost` | string | `sensor.cloud.tenable.com` | Tenable manager host. |
| `-LinkGroups` | string | `''` | Agent group(s) to join. If empty, resolved from the prefix-rule/override map; a host that resolves to no group exits 2. |
| `-ForceRelink` | switch | off | Unlink and relink even if the agent reports healthy. |
| `-ResetTenableTag` | switch | off | On HTTP 409 duplicate-identity, delete `HKLM:\SOFTWARE\Tenable\TAG` and link as a new agent. Off by default: a 409 exits 2 with the diagnosis instead of probing DNS/TCP/TLS. The stale Tenable record keeps a license seat until deleted (Sensors > Agents). |

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
Removes an end-of-support .NET runtime channel. With no `-DotNetN` switch the target is major 6. Multiple `-DotNetN` switches in one run are processed independently.

Inventory and verification cover ARP, `shared\`/`host\fxr\`/`sdk\` folders, `dotnet --list-runtimes`, **SWID tags** (`<root>\swidtag`) and **host binary file versions**. The last two matter when an uninstall returns 1612 (cached MSI missing) and removes no files: the ARP key can end up stripped while a four-part file version such as `6.0.18.32522` still satisfies plugin 172179 (CSLT-020). `<root>\dotnet.exe` is the shared muxer and is never deleted — repair or reinstall the newest .NET Host instead.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-Major` | int | `6` | The .NET major channel to remove. Local/terminal use only (do not pass a valued parameter through EC). Ignored when any `-DotNetN` switch is set. |
| `-DotNet5` | switch | off | Remove the .NET 5 channel. Bare switch for EC. |
| `-DotNet6` | switch | off | Remove the .NET 6 channel. Bare switch for EC. Same as the no-switch default; use it when combining with other majors. |
| `-DotNet7` | switch | off | Remove the .NET 7 channel. Bare switch for EC. |
| `-DotNet8` | switch | off | Remove the .NET 8 channel. Bare switch for EC. .NET 8 is in support until 2026-11-10; the script warns and proceeds. |
| `-DotNet9` | switch | off | Remove the .NET 9 channel. Bare switch for EC. |
| `-Force` | switch | off | Proceed even if a non-Microsoft (or other-major) product holds a WiX dependency on this channel. Will break that app — confirm with the owner first. |
| `-RemoveStaleFolders` | switch | off | After uninstall, delete leftover `shared\`/`host\fxr\` folders, SWID tags, versioned `hostfxr.dll` files, and orphan Package Cache installers for this major when no live *foreign* dependent remains. Never deletes `<root>\dotnet.exe`. |
| `-DryRun` | switch | off | Report what would be removed; change nothing. |

## Remove-3DViewer.ps1
Removes the Microsoft 3D Viewer Store app.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-CleanOrphanedProfiles` | switch | off | Remove on-disk profiles whose SID no longer resolves to an account (deleted users), then retry package removal. Only unloaded, non-special profiles are touched. |
| `-DryRun` | switch | off | Report what would be removed without removing anything. |

## Fix-InsecureServicePermissions.ps1
Tightens loose Everyone / Users / Domain Users / Authenticated Users ACLs on **discovered** service-executable directories (Nessus plugin 65057). Default run walks `HKLM:\SYSTEM\CurrentControlSet\Services`, skips Windows / Defender / WindowsApps, and only changes the folder that contains the `.exe` (e.g. swissQprint `...\mariadb-<ver>\bin`, not the vendor tree). Empty EC arguments = full discovery. Optional `-Service MariaDB` limits the run to that service (recommended first pass on OT / shop-floor hosts).

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-DryRun` | switch | off | Show current ACLs and what would change, without modifying anything. |
| `-Path` | string | `''` | Semicolon-separated extra directories to consider in addition to discovery. |
| `-Service` | string | `''` | Semicolon-separated service-name filter (registry / Win32 name, wildcards allowed). Empty = all non-protected services. |
| `-IncludeMicrosoft` | switch | off | Also consider services under Windows / Defender / WindowsApps (normally skipped). |

## Get-DotNetDependencyReferences.ps1
Read-only: lists MSI dependency providers holding references on old .NET versions.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-VersionMatch` | string | `10.0.3` | Version string to match in provider key names. |

## Get-DotNetArtifactInventory.ps1
Read-only: classifies where each .NET version exists (`LIVE` / `CACHE-ONLY` / `FILE-ONLY` / `REGISTERED-NO-PAYLOAD` / orphaned cache). Cross-references `dotnet --list-runtimes`, `shared\` folders, `host\fxr`, ARP, Package Cache, **SWID tags** and **host binary file versions**. `FILE-ONLY` is the CSLT-020 state: no runtime folder and no cached installer, but a SWID tag or `dotnet.exe`/`hostfxr.dll` file version still reports the version to plugin 172179. Run this first when an SEoL finding will not clear. **No arguments.**

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

## Repair-ZscalerAgent.ps1
Diagnoses and applies bounded remediation (start/restart the critical services only) for a Zscaler Client Connector that has stopped checking in. Emits exactly one machine-parseable line to stdout for fleet aggregation, plus a full evidence log per run.

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `-Format` | string (`Kv`/`Csv`/`Json`) | `Kv` | Output shape for the single result line. |
| `-IncludeHeader` | switch | off | Emit a CSV header row before the data row (ignored for Kv/Json). Leave off for fleet runs — add the header once at the collector. |
| `-ServiceWaitSeconds` | int | `45` | Seconds to wait for a service to reach `Running` after a start/restart. |
| `-CheckInStaleMinutes` | int | `60` | Minutes of ZCC log inactivity after which check-in is treated as STALE. |
| `-TextFieldMaxLength` | int | `160` | Truncation ceiling for free-text fields, so one chatty host cannot blow up a fleet report row. |

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

## get-nessus-agent-version.sh
Read-only. Reports every Nessus Agent version the Mac can self-report (running binaries, `pkgutil` receipts, bundle plists, leftover trees) and names whichever source disagrees. Written for CSPRIM-08 (plugin 326953 / TNS-2026-18), where the finding said 11.2.0 at `/Library/NessusAgent` while Sensors > Agents showed 11.2.3. Reads **environment variables**, with an in-script `CFG_*` block for Mosyle. Changes nothing.

| Environment variable | CONFIG default | Description |
|----------------------|----------------|-------------|
| `FIXED_VERSION` | `CFG_FIXED_VERSION="11.2.1"` | Version floor each source is judged against. |
| `AGENT_ROOT` | `CFG_AGENT_ROOT="/Library/NessusAgent"` | Agent install root. |
| `DEEP_SCAN` | `CFG_DEEP_SCAN="0"` | Set `1` to also search `/Applications`, `/opt` and `/usr/local` for stray agent binaries (slower). |

Exit codes: `0` PATCHED (every source current — a finding is stale Tenable-side data) / `1` VULNERABLE (running binary below the floor) / `2` STALE_METADATA (binaries current, another source still reports old) / `3` NOT_INSTALLED. The last line is machine-parseable: `NESSUS_AGENT_VERSION|host=..|running=..|floor=..|verdict=..|stale_sources=..`.

## repair-nessus-agent.sh
Checks agent state and fixes only what is broken. Reads **environment variables** (usable from a terminal).

| Environment variable | Default | Description |
|----------------------|---------|-------------|
| `LINK_KEY` | embedded CompoSecure key | Tenable linking key. |
| `LINK_HOST` | `sensor.cloud.tenable.com` | Tenable manager host. |
| `LINK_GROUPS` | `''` | Override group resolution with an explicit group set. If empty, resolved from the prefix map. |
| `FORCE_RELINK` | `0` | Set `1` to unlink and relink even if the agent reports healthy. |
| `RESET_TENABLE_TAG` | `0` | Set `1` to recover from an HTTP 409 duplicate-identity link rejection by deleting `/private/etc/tenable_tag` (agent regenerates one) and retrying the link. Off by default: the host then links as a **new** agent and the stale record stays in Tenable holding a license seat until a human deletes it (Sensors > Agents). Without this, a 409 exits 2 with the diagnosis. |

## update-adobe-rum.sh
Generic Adobe updater via Remote Update Manager. Reads **environment variables**, with in-script `CFG_*` defaults for Mosyle (which cannot pass env at deploy). A terminal-set variable wins over `CFG_*`.

| Environment variable | Default | Description |
|----------------------|---------|-------------|
| `TARGETS` | `''` | Semicolon-separated `NamePattern=MinVersion` pairs; any listed app still below its minimum makes the run fail (exit 1). |
| `SAP_CODES` | `''` (unfiltered) | Comma-separated SAP codes to target specific Adobe products (e.g. `PHSP,ILST`). Falls back to unfiltered unless `NO_FALLBACK=1`. |
| `FORCE_CLOSE` | `CFG_FORCE_CLOSE="0"` | Set `1` to quit running Adobe apps instead of aborting (exit 2). |
| `KILL_STALE_RUM` | `CFG_KILL_STALE_RUM="1"` | Set `1` (default) to SIGTERM/SIGKILL a live `RemoteUpdateManager` that is still running after `WAIT_FOR_RUM_SECONDS` **and** whose `ps` elapsed age is `>= STALE_RUM_SECONDS`. Younger processes are treated as concurrent jobs and deferred (exit 2). `DRY_RUN=1` never kills. A lock with **no** process still requires a reboot. |
| `WAIT_FOR_RUM_SECONDS` | `CFG_WAIT_FOR_RUM_SECONDS="120"` | Seconds to wait for an already-running RUM to exit before considering a kill. |
| `STALE_RUM_SECONDS` | `CFG_STALE_RUM_SECONDS="600"` | Minimum `ps etime` (seconds) before a live RUM is treated as hung. Default 10 minutes so a just-started Mosyle/manual download is not killed. |
| `NO_FALLBACK` | `CFG_NO_FALLBACK="0"` | Set `1` to not retry unfiltered when a targeted call fails. |
| `DRY_RUN` | `CFG_DRY_RUN="0"` | Set `1` to inventory + run `RUM --action=list` only; install nothing. |
| `IGNORE_HELPERS` | `CFG_IGNORE_HELPERS="1"` | Set `0` to treat Adobe background helper/XPC processes as blockers (strict behavior). |

On a Mac with only Acrobat/Reader installed, RUM's `No new updates are available` with Return Code (2) is treated as nothing offered (`END (nothing offered)`, exit 2), not a failure. Its `Failed to initialize the HDPIM module` log lines are expected there. When a Creative Cloud app is installed, the same HDPIM failure is reported as the blocker. For Bridge (plugin 331360): `TARGETS="Bridge 2026=16.0.6;Bridge 2025=15.1.7"`.

## remediate-ruby-gem.sh
Generic vulnerable-gem remediator. Accepts, in precedence order, **positional args > environment variables > in-script `CONFIG` block**.

| Positional | Environment | CONFIG default | Description |
|-----------|-------------|----------------|-------------|
| `$1` | `GEM` | `CFG_GEM="net-imap"` | Gem name (required). |
| `$2` | `THRESHOLDS` | `CFG_THRESHOLDS="0.4:0.4.24;0.5:0.5.15;0.6:0.6.4.1"` | Either a single minimum (`3.4.2`) or per-branch `prefix:minimum` pairs (required). Plugin 321503 floors: 0.5.15 and 0.6.4.1. The older 313278 floor of `0.6.4` treats the installed 0.6.4 spec as already fixed. |
| `$3` | `PLUGIN` | `CFG_PLUGIN="321503"` | Plugin ID, for the log header only. |
| — | `NO_INSTALL` | `CFG_NO_INSTALL="0"` | Set `1` to clean up only; never install a patched gem. |
| — | `DRY_RUN` | `CFG_DRY_RUN="0"` | Set `1` to report only, delete nothing. |

Example (terminal): `./remediate-ruby-gem.sh net-imap "0.4:0.4.24;0.5:0.5.15;0.6:0.6.4.1" 321503`

A stock Mosyle paste uses the CONFIG block. To remediate rexml instead, set `CFG_GEM="rexml"`, `CFG_THRESHOLDS="3.4.2"`, `CFG_PLUGIN="265895"` before deploying.

Cleanup is gated on a patched sibling in the **same Ruby tree and ABI** (`gem install` writes only to the current Ruby). A Homebrew gem dir whose ABI no longer has any `Cellar/ruby*` keg (e.g. `lib/ruby/gems/3.3.0` left behind after ruby moved to 4.0) is logged `ORPHAN` and its vulnerable spec removed: nothing can load it and no patched sibling can ever appear there (ARMB-09). A gem dir whose interpreter still exists is left alone (`KEEP`).

## update-claude-code.sh
Updates per-user Claude Code installs under `/Users/*/.local/bin/claude` (plugin 322792 / CVE-2026-54316). Runs `claude update` as each owning user via `sudo -u`, which works even when that user is not logged in. Reads **environment variables**, with an in-script `CONFIG` block for Mosyle.

| Environment variable | CONFIG default | Description |
|----------------------|----------------|-------------|
| `TARGET_VERSION` | `CFG_TARGET_VERSION="2.1.163"` | Minimum acceptable version. |
| `ONLY_USER` | `CFG_ONLY_USER=""` | Restrict to a single account; empty means every user with an install. |
| `DRY_RUN` | `CFG_DRY_RUN="0"` | Set `1` to report only and change nothing. |

## update-golang.sh
Updates Go (official tree + Homebrew; per-user managers report-only). Each install stays on its current **N.M** line and is raised to the latest **stable** patch for that line from `https://go.dev/dl/?mode=json&include=all` (plugin 327411: 1.25.x stays 1.25.x). Unversioned Homebrew `go` is not `brew upgrade`d (it would jump minors). Reads **environment variables**, with an in-script `CONFIG` block for Mosyle.

| Environment variable | CONFIG default | Description |
|----------------------|----------------|-------------|
| `DRY_RUN` | `CFG_DRY_RUN="0"` | Set `1` to report only; change nothing. |
| `FORCE_CLOSE` | `CFG_FORCE_CLOSE="0"` | Set `1` to terminate running Go toolchain processes before swapping `/usr/local/go`. Default refuses to swap under a running compile. |
| `GO_DL_URL` | `CFG_GO_DL_URL` (`include=all` catalog) | Catalog URL. Override only for an internal mirror. |
| `GO_DL_JSON` | empty | Path to a cached catalog JSON (tests / air-gapped). When set to an existing file, the network fetch is skipped. |

## update-gstreamer.sh
Upgrades Homebrew GStreamer to >= 1.28.5 and removes leftover Cellar kegs (plugins 326245 / 326246). Reads **environment variables**, with an in-script `CONFIG` block for Mosyle.

| Environment variable | CONFIG default | Description |
|----------------------|----------------|-------------|
| `DRY_RUN` | `CFG_DRY_RUN="0"` | Set `1` to report only; change nothing. |
| `FORCE_CLOSE` | `CFG_FORCE_CLOSE="0"` | Set `1` to TERM `gst-launch` / `gst-play` helpers before replacing kegs. Default continues anyway. |
| `NO_INSTALL` | `CFG_NO_INSTALL="0"` | Set `1` to skip `brew upgrade` and only do inventory + keg cleanup. Use after upgrading the keg by hand. |
| `BREW_TIMEOUT` | `CFG_BREW_TIMEOUT="2700"` | Per-brew-step wall-clock limit in seconds; `0` disables. `gstreamer` bundles `gst-plugins-rs`, so a source build runs for hours — stopping on our own terms keeps the log and exit code meaningful instead of being killed by Mosyle. Remaining brew steps are skipped once one step hits the limit. |
| `BREW_USER` | auto (console user, else `brew` owner) | Force the account `brew` runs as. `brew` refuses to run as root, and console-user detection has no answer at the login window. |
| `BREW_PREFIX` | auto `/opt/homebrew` or `/usr/local` | Override Homebrew prefix (tests). |

Each `brew` invocation streams to its own `/var/log/composecure/gstreamer_brew_<step>.log`, so a killed run still shows how far brew got.

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

## update-homebrew.sh
Weekly Homebrew maintenance: `brew update`, upgrade every outdated formula and cask, then `brew cleanup` to remove superseded `Cellar/<formula>/<version>` kegs and old portable-ruby trees (the leftovers Tenable keeps reporting after an upgrade). Then keeps the gems bundled with Homebrew Ruby (net-imap, rexml) current and deletes their stale copies, which brew never touches. Maintains both `/opt/homebrew` and an Intel `/usr/local` prefix (under Rosetta). brew runs as the owner of each prefix. Casks upgrade one at a time and failures are named with a reason. Reads **environment variables**, with an in-script `CONFIG` block for Mosyle. Before brew runs it accepts an unaccepted Xcode license and installs a pending Command Line Tools update. Time limits are wall-clock and stop the whole process tree; a step that fails on a network error is retried once. Failed steps are listed under "Problems" in the summary. Exit `0` = all current, `2` = something still outdated (failed / pinned / skipped) or a step failed / timed out, `1` = a prefix could not be maintained.

| Environment variable | CONFIG default | Description |
|----------------------|----------------|-------------|
| `DRY_RUN` | `CFG_DRY_RUN="0"` | Set `1` to list what is outdated and change nothing. |
| `GREEDY` | `CFG_GREEDY="0"` | Set `1` to also upgrade casks that auto-update themselves (Chrome, Slack, Zoom...). Off by default: those apps keep themselves current and rarely appear in Tenable. |
| `CASK_SUDO` | `CFG_CASK_SUDO="0"` | Set `1` to give the brew user passwordless sudo for the duration of the run (a `/etc/sudoers.d` drop-in, validated with `visudo`, removed on exit and at the start of the next run). Without it, casks with a `.pkg` installer fail and are listed as "needs sudo". |
| `AUTOREMOVE` | `CFG_AUTOREMOVE="0"` | Set `1` to run `brew autoremove` (uninstall dependencies nothing needs any more). While `0`, `brew cleanup` is also run with `HOMEBREW_NO_AUTOREMOVE=1`, because cleanup autoremoves by default. |
| `SKIP_FORMULAE` | `CFG_SKIP_FORMULAE=""` | Space-separated formulae to leave alone. Reported as still outdated. |
| `SKIP_CASKS` | `CFG_SKIP_CASKS=""` | Space-separated casks to leave alone. Reported as still outdated. |
| `BREW_TIMEOUT` | `CFG_BREW_TIMEOUT="3600"` | Limit in seconds for `update`, the formula upgrade and `cleanup`. Once one hits it, the remaining steps are skipped. `0` = no limit. |
| `CASK_TIMEOUT` | `CFG_CASK_TIMEOUT="900"` | Limit in seconds per cask. A slow cask fails alone and the rest still run. |
| `RUN_BUDGET` | `CFG_RUN_BUDGET="6600"` | Wall-clock budget in seconds for the whole run. Each step's limit is capped to what is left; once it is used up the remaining steps are skipped and the summary is still written. Keep it below Mosyle's limit for the command. `0` = no budget. |
| `ACCEPT_XCODE_LICENSE` | `CFG_ACCEPT_XCODE_LICENSE="1"` | When full Xcode is the selected developer dir and its license is not accepted (every brew command fails), run `xcodebuild -license accept` as root. `0` = report only. |
| `UPDATE_CLT` | `CFG_UPDATE_CLT="1"` | When the Command Line Tools are installed and `softwareupdate --list` offers a newer "Command Line Tools for Xcode" label, install it before brew runs. `0` = report only. |
| `REPAIR_CASKS` | `CFG_REPAIR_CASKS="1"` | A cask that fails with "App source ... is not there" is force-uninstalled and installed again. `0` = report only. |
| `RUBY_GEMS` | `CFG_RUBY_GEMS="net-imap:branch rexml:latest"` | Gems bundled with Homebrew Ruby to keep current (step 5b). For each Homebrew Ruby (`opt/ruby`, `opt/ruby@*`): `gem install` the newest release, then delete older copies wherever that Ruby loads from (its Cellar keg and `lib/ruby/gems/<abi>`), and delete copies in `lib/ruby/gems/<abi>` dirs whose Ruby is gone. `:branch` keeps the newest of each installed major.minor (net-imap backports fixes); `:latest` keeps only the newest. Default gems (`specifications/default`) and macOS system Ruby are never deleted. Needs no fixed-version list. Gem dirs inside the prefix are chowned back to the brew user first (root-owned files cause `Gem::FilePermissionError`). A Ruby whose `gem` reports no gem dir for its own ABI is skipped and listed as a problem. Empty = skip. |

## update-nodejs.sh
Updates Node.js across Homebrew / official pkg (per-user managers report-only). **No runtime arguments and no pinned target version.** Installed Homebrew `node` / `node@N` formulae are `brew upgrade`d to the current formula. An official `/usr/local` pkg is raised to the latest stable release of its installed major from `https://nodejs.org/dist/index.json` (a test can point `NODE_DIST_JSON` at a cached index). Brew's download bar and the new/deleted formula and cask catalogs are omitted from the log.

## update-powershell.sh
Updates PowerShell to the fixed version. **No arguments** (self-escalates via `sudo`; target is the in-script constant `FIXED_VERSION`).

## repair-zscaler-agent.sh
Diagnoses and applies bounded remediation (`launchctl kickstart -k` on an already-loaded, non-running/stale daemon only) for a Zscaler Client Connector that has stopped checking in. Emits one machine-parseable line in the same schema as `Repair-ZscalerAgent.ps1`, plus a full evidence log per run under `/var/log/composecure`. Reads **environment variables**, with an in-script `CONFIG` block for Mosyle.

| Environment variable | CONFIG default | Description |
|----------------------|----------------|-------------|
| `CHECKIN_STALE_MINUTES` | `CFG_CHECKIN_STALE_MINUTES="60"` | Minutes of log inactivity after which check-in is treated as STALE. |
| `DRY_RUN` | `CFG_DRY_RUN="0"` | Set `1` to report only; kickstart nothing. |

## update-office-macos.sh
Updates App Store-installed Microsoft Office (Word/Excel/PowerPoint/Outlook/OneNote) via `mas`, quitting and updating only apps the App Store itself currently reports as outdated — no hardcoded target version. Takes **command-line flags** (Mosyle-compatible; no environment variables or `CONFIG` block).

| Flag | Description |
|------|-------------|
| `--dry-run` | Report which apps `mas outdated` currently flags; change nothing beyond ensuring `mas` itself is installed (a detection dependency, not an Office change). |
| `--accurate` | Pass `--accurate` through to `mas outdated`/`mas upgrade` for a slower, more precise check (may prompt for App Store sign-in). |

## update-zoom.sh
Updates Zoom Workplace to the release Zoom currently ships (Tenable ZSB advisories such as plugins 334489 / 334491). **No pinned version:** the target is read from where `https://zoom.us/client/latest/ZoomInstallerIT.pkg` redirects (`cdn.zoom.us/prod/<N.N.N.build>/...`). Inventories `/Applications/zoom.us.app` and per-user `~/Applications/zoom.us.app` copies, and exits 0 without downloading when everything is current. Defers while a meeting is in progress (`CptHost` / `aomhost` running). If Zoom is open with no meeting, it is quit (AppleScript as the console user, then TERM) just before the install and reopened afterwards: Zoom's own preinstall will not update a running Zoom 6.6+ from the command line. It copies the package to `/Applications/.zoomusUpdateUseOnly` and exits 1 ("An error occurred while running scripts from the package", CSPRMB-15-A). When verification fails, `/Library/Logs/zoomusinstall.log` is copied into the run log and the cause is named. Checks the package is signed with a Developer ID Installer certificate for Zoom's Apple team ID `BJ4HAAB9B3` (the team ID, not the company name, which changed to "Zoom Communications, Inc."; the signer is logged either way), installs with a time limit, and re-reads the app version before claiming success. Older per-user copies are removed only after the machine-wide copy is verified. Reads **environment variables**, with an in-script `CONFIG` block for Mosyle. Exit `0` = current or not installed, `2` = deferred / not verified / per-user copy left, `1` = latest version, download or signature check failed.

| Environment variable | CONFIG default | Description |
|----------------------|----------------|-------------|
| `DRY_RUN` | `CFG_DRY_RUN="0"` | Set `1` to report what would be installed or removed and change nothing. |
| `FORCE_CLOSE` | `CFG_FORCE_CLOSE="0"` | Set `1` to install even during a meeting (Zoom is quit first, which drops the call). |
| `CLOSE_IDLE_ZOOM` | `CFG_CLOSE_IDLE_ZOOM="1"` | Quit an open Zoom that is not in a meeting, install, then reopen it. `0` = defer (exit 2) while Zoom is open. |
| `QUIT_TIMEOUT` | `CFG_QUIT_TIMEOUT="30"` | Seconds to wait for Zoom to exit after the quit request, and again after TERM. Still running = defer (exit 2). |
| `REMOVE_USER_COPIES` | `CFG_REMOVE_USER_COPIES="1"` | Remove older `~/Applications/zoom.us.app` copies that are not running, once the machine-wide copy is verified current. `0` = report them (exit 2). |
| `PKG_URL` | `CFG_PKG_URL="https://zoom.us/client/latest/ZoomInstallerIT.pkg"` | The "latest" URL the version and package come from. |
| `DOWNLOAD_TIMEOUT` / `INSTALL_TIMEOUT` | `900` / `900` | Wall-clock limits in seconds for the download and the installer. |

## update-wireshark.sh
Updates Wireshark for macOS to the latest release of its branch (Tenable plugin 349570 "Wireshark 4.6.x < 4.6.9", csmb-059, and later advisories of the same shape). **No pinned version:** the target comes from Wireshark's own Sparkle update feed, `https://www.wireshark.org/update/0/Wireshark/<installed>/macOS/<arm64|x86-64>/en-US/stable.xml`, which lists the newest release of each supported branch with its DMG URL, size, SHA-256 and minimum macOS. A copy stays on its branch (4.4 → 4.4.19 on Intel); a branch no longer in the feed moves to the newest release this macOS can run. Updates `/Applications/Wireshark.app` and per-user `~/Applications/Wireshark.app` copies; other copies Spotlight finds are reported (exit 2), not changed. Exits 0 without downloading when everything is current. A copy with Wireshark, dumpcap or tshark running from it is deferred (Wireshark asks before quitting, and an unsaved capture would be lost). The DMG must match the feed's size and SHA-256, mount read-only, hold `Wireshark.app` at the target version, pass `codesign --verify --deep --strict`, and be signed with a Developer ID Application certificate for Wireshark's team ID `7Z6EMTD2C6`. Each copy is replaced by copying the new app beside it and swapping, keeping the old owner; the old app is deleted only once the new one is in place. ChmodBPF and the "Add Wireshark to the system path" packages are left alone. Reads **environment variables**, with an in-script `CONFIG` block for Mosyle. Exit `0` = current or not installed, `2` = deferred / dry run / copy left old, `1` = feed, download, checksum, DMG or signature check failed (nothing changed).

| Environment variable | CONFIG default | Description |
|----------------------|----------------|-------------|
| `DRY_RUN` | `CFG_DRY_RUN="0"` | Set `1` to report the target and the copies that would be replaced; change nothing (exit 2). |
| `FORCE_CLOSE` | `CFG_FORCE_CLOSE="0"` | Set `1` to stop Wireshark / dumpcap / tshark running from an old copy (TERM, then KILL) and update it. Unsaved captures are lost. |
| `QUIT_TIMEOUT` | `CFG_QUIT_TIMEOUT="20"` | Seconds to wait after TERM before KILL when `FORCE_CLOSE=1`. |
| `UPDATE_USER_COPIES` | `CFG_UPDATE_USER_COPIES="1"` | Update older `~/Applications/Wireshark.app` copies in place. `0` = report them (exit 2). |
| `FEED_BASE` | `CFG_FEED_BASE="https://www.wireshark.org/update/0/Wireshark"` | Base of the update feed URL. |
| `DOWNLOAD_TIMEOUT` / `COPY_TIMEOUT` | `900` / `600` | Wall-clock limits in seconds for the download and for copying the app into place. |

## remove-apple-pages.sh
Removes Apple Pages (`com.apple.iWork.Pages`) app bundles, e.g. Tenable plugin 298993 "Apple Pages < 15.1" (CVE-2025-46316). Finds copies the way Tenable does: Spotlight by bundle id (so renamed copies count) plus a walk of `/Applications` and `/Users` (Downloads, Desktop, Trash, nested folders; `~/Library` is skipped). Only bundles whose `CFBundleIdentifier` is exactly `com.apple.iWork.Pages` are touched; documents and the per-user container are never removed. Copies under `/Volumes` are reported, not deleted. Defers while Pages is running. Re-searches after removal before claiming success, and names the missing macOS permission when it gets "Operation not permitted" (App Management for the delete, Full Disk Access for the search). Reads **environment variables**, with an in-script `CONFIG` block for Mosyle. Exit `0` = nothing left to remove, `2` = running / not removed / not searchable / other volume / dry run with work, `1` = PlistBuddy missing.

| Environment variable | CONFIG default | Description |
|----------------------|----------------|-------------|
| `DRY_RUN` | `CFG_DRY_RUN="0"` | Set `1` to list what would be removed and change nothing (exit 2 when something would be removed). |
| `FORCE_CLOSE` | `CFG_FORCE_CLOSE="0"` | Set `1` to quit a running Pages first (graceful quit as the console user, then TERM, then KILL; unsaved work can be lost). |
| `KEEP_FROM_VERSION` | `CFG_KEEP_FROM_VERSION=""` | Empty = remove every Apple Pages copy. Set e.g. `15.1` to keep copies at or above that version and remove only older ones. |

## macos/superseded/*
Retained for reference/rollback; prefer the replacements noted in each header (the Ruby-gem scripts are superseded by `remediate-ruby-gem.sh`; `update-photoshop.sh` by `update-adobe-rum.sh`).

- `superseded/ruby-netimap-cellar-cleanup.sh` — **No arguments** (thresholds are in-script constants).
- `superseded/ruby-netimap-update.sh` — **No arguments** (thresholds are in-script constants).
- `superseded/remediate-rexml.sh` — **No arguments** (self-escalates via `sudo`; fixed version is a constant).
- `superseded/cleanup-rexml-gemspec.sh` — **No arguments** (self-escalates via `sudo`; fixed version is a constant).
- `superseded/update-photoshop.sh` — reads **environment variables** `FORCE_CLOSE` (default `0`, quit a running Photoshop) and `NO_FALLBACK` (default `0`, keep the run Photoshop-only instead of retrying `RUM` unfiltered).
