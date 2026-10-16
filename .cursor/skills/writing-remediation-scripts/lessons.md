# Lessons catalog

Each entry gives the rule, then the evidence: the host or PR where it bit us. Search this file for the error text you are seeing.

## Verifying outcomes

- **The exit code says nothing about whether the work happened.**
  - A WiX bundle with registered dependents skips its uninstall and returns 0 (Update-DotNetRuntimes).
  - Adobe RUM can exit 0 with the app unchanged.
  - Re-read the version, ARP entry or folder.
- **A non-zero code is not always failure.** RUM exits with RC 2 and prints "No new updates are available" on Acrobat-only Macs. Accept it only when the output and the inventory both confirm nothing was offered (#58).
- **Diagnose by the actual code.** Keep a lookup table, e.g. 1605/1612/1618/1619/1620 for msiexec. Printing one canned explanation for every failure misled the operator on CSPC-004 (#21).
- **`Start-Process -PassThru` + `WaitForExit(ms)` leaves `ExitCode` blank in Windows PowerShell.**
  - Read `$null = $p.Handle` right after start, then call `WaitForExit()` again after the timed wait.
  - `[int]$null` is 0, so a blank code must become UNKNOWN (CSLT-057, #61).
- **Check what a staged payload actually contains.**
  - The WinGet bundle held 1.29.290, the version already installed, so 315 "successful" provisions would have changed nothing (#15).
  - Check the inner manifest version, an `MZ` header on downloads, and `setup.exe`'s major (SQL 2019 and 2022 Express share a file name).
- **Version eyeball trap:** 1.29.290 < 1.30.80. Compare with `[version]` or `sort -V`, never as strings or by eye.

## Stale state inside one run

- **Snapshot staleness.** Phase 2 judged "orphaned" against the Phase-0 snapshot and deleted the .NET 10 that Phase 1a had just installed. Its final report still said "advanced" (CSLT-020, #28). Re-read state after every mutation.
- **Used before assigned.** Phase 1d verified a removal against `$arpPaths`, which was only set later, so it always "passed" (#21).
- **Race between a lookup and its use.** A hive that was not loaded when checked was loaded by the time `reg load` ran. On failure, re-check `hivelist` before falling back (CSPRLT-68, #57).

## PowerShell / Endpoint Central (SYSTEM, 32-bit agent)

- **`$matches` is replaced by every successful `-match`,** including ones with no capture groups. Copy groups into locals immediately. `(x86)` checks turned the SDK major into 0 and built `aka.ms/dotnet/0.0/...` (CSPC-004, #38 and #52).
- **Native stderr becomes a terminating error under `$ErrorActionPreference='Stop'` + `2>&1` in PowerShell 5.1.**
  - Run `reg.exe` and similar under `Continue`, and return exit code and output as data.
  - Drop the bare `RemoteException` records (#56, #57).
- **The 32-bit agent sees `HKLM\SOFTWARE` as `WOW6432Node`.**
  - Relaunch through `Sysnative` into 64-bit PowerShell when 64-bit keys matter (#56).
  - Otherwise read both views: 32-bit SQL instances register only under WOW6432Node (#63).
  - The 32-bit Uninstall path is `HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`. A draft with an extra `Software` segment found nothing.
- **Per-user installs are invisible from HKLM.**
  - Walk every profile through HKU, loading unloaded `NTUSER.DAT` with `reg load`.
  - For locked hives, register an Active Setup component that applies the fix at the user's next sign-in (#56, #65).
- **SYSTEM's `%TEMP%` is `C:\Windows\Temp`.** Installers that fail early write their logs there, not under Program Files (CSPRLT-94, #66).
- **A mutex existing is not a mutex being owned.** `Global\_MSIExecute` exists whenever `msiexec /V` is alive. Probe with `WaitOne(0)` (CSLT-192, #40).
- **Dependency Files are extracted to `$PSScriptRoot`.** `$MyInvocation.MyCommand.Path` is wrong inside functions (#31).
- **Never pass paths or quoted values as EC arguments.** Use bare switches only.
- **Newer scripts contain no literal double-quote character.** Build it with `[char]34` and use single-quoted strings, because EC mangles quotes. Check with `rg -c '"' windows/<Script>.ps1`.
- **Invoke native exes by full path with `-NoNewWindow`.** Bare `msiexec.exe` fails under SYSTEM through ShellExecute.
- **Prefer raw .NET over modules that may be missing under SYSTEM.** `Test-NetConnection` can't report a TLS issuer anyway (#30).
- **When a script chains another, the EC package's main script must be the caller and the callee goes in Dependency Files.** The CSPRLT-94 package ran `Update-CitrixWorkspace.ps1` with `Remove-CitrixWorkspaceLegacy.ps1`'s switch. Say which file is the entry point in the header and in `docs/SCRIPT-ARGUMENTS.md`.

## bash / Mosyle (root, bash 3.2)

- **Never capture long tool output with `$(...)`.** A kill discards all of it (jriegel-mac, #34). Stream to `/var/log/composecure/<script>_<step>.log` and copy a filtered tail plus any `Error:` lines into the main log.
- **Measure time limits with `date +%s`, not by counting sleeps.**
  - Background timers stretch, and a 900s limit let a cask run 2304s.
  - Kill the whole tree: collect descendants with `pgrep -P` *before* killing, or killing only `sudo` leaves brew's children running.
  - Keep a whole-run budget below Mosyle's limit so the SUMMARY is always written (#67).
- **brew refuses root.** Run it as the owner of `<prefix>/bin/brew` (`stat -f %Su`), not the console user. Run Intel `/usr/local` under `arch -x86_64`.
- **`brew cleanup` autoremoves by default.** Set `HOMEBREW_NO_AUTOREMOVE=1` unless autoremove was asked for; cleanup removed openssl@3 on CSMB-026.
- **Root-run tools leave root-owned files in user-owned trees,** e.g. `Gem::FilePermissionError` on rexml (ARMB-02, ARMB-09). Never run gem or brew as root, and chown the prefix's gem dirs back before installing.
- **Preflight on Macs:**
  - An unaccepted Xcode license makes every brew call fail (`xcodebuild -license check`).
  - Outdated Command Line Tools make brew rebuild for hours (`softwareupdate --list`).
- **Mosyle logs:** drop progress bars and brew's new/renamed/deleted catalogs. Keep the log ASCII only (`LC_ALL=C tr -cd '\11\12\40-\176'`, `HOMEBREW_NO_EMOJI=1`); Mosyle renders multi-byte characters as `????`.
- **Mosyle passes no environment variables.** Settings go in the `CFG_*` CONFIG block, with environment overrides for terminal use and tests.
- **Subshell scoping:**
  - `cmd | while read` runs in a subshell, so variables set inside are lost.
  - A recursive function clobbers its caller's loop variable; write it as `name() ( ... )`.
- **Empty arrays under `set -u` abort in bash 3.2:** `"${arr[@]}"` on an empty array raises "unbound variable". For an optional command prefix, use an unquoted scalar the way the brew scripts do (`ARCH_CMD=""` or `ARCH_CMD="arch -x86_64"`, then `$ARCH_CMD "$bin"`).
- **A background `sleep N; kill` watchdog stretches the same way a sleep-counting loop does.** Poll and compare `date +%s` instead.
- **bash 3.2:** no `mapfile`/`readarray`, associative arrays (`declare -A`) or case conversion (`${v,,}`). `local` works and a few scripts use it. Most scripts give function variables a unique prefix instead (`rs_`, `ga_`).
- **Kill only what is provably stale.** Age-gate it with `ps -o etime` (RUM, #35). Match the app's main binary, not helpers under its bundle.

## Domain rules (Tenable and vendors)

- **Tenable reads files on disk, not package-manager state.**
  - Old Cellar kegs and gemspecs, side-by-side .NET folders, SWID tags, and per-user copies all keep a finding open.
  - It sometimes reads ARP entries too, so orphaned registrations matter (#24).
- **Fixed versions are per release branch.** net-imap is fixed on 0.4, 0.5 and 0.6 separately. `gem install` alone only adds the newest branch (ARMB-02, #48).
- **Default gems (`specifications/default`) and macOS system Ruby are never deleted.** Only a newer Ruby fixes them.
- **A dependency blocker must match on architecture.** An x64 app cannot use x86 .NET 8, so it does not block removing x86 .NET 8 (CSLT-057, #61).
- **End-of-support comes from a date table.** A major past its date is EOL automatically, and a major inside the warning window gets its successor staged (#53).
- **Split failure classes that look alike to the operator:** Nessus 409 duplicate identity vs connection failed vs empty response from TLS inspection. "Never connected" is not a regression (#30, #42).
- **Bundle placeholders** (`PackageFullName` containing `_~_`) have no manifest on disk until a user signs in (#14).
- **Hostname lookup tables go stale.** Use prefix patterns plus a short exception list (#9).

## Testing on the Linux VM

- **Shim the macOS and Windows tools in a temp dir on `PATH`:** `sudo`, `stat`, `dscl`, `sw_vers`, `visudo`, `xcode-select`, `pkgutil`, `softwareupdate` and `brew`. Point the script at the fixture with `BREW_PREFIXES`, `LOG_DIR` and similar overrides.
- **`chmod +x` every shim, including ones a single test adds later.** A non-executable shim silently falls through to the real command.
- **On Linux, `pgrep` matches only the first 15 characters of `comm`.** Full RemoteUpdateManager matching needs a Mac.
- **Hard-coded `C:\Logs` paths fail on Linux.** Dot-source the helpers, or rewrite the log path in a temp copy for smoke runs.
- **Assert on the fixture's call log** (`$S/calls`) for ordering, e.g. upgrade before cleanup, or the CLT install before brew update.
