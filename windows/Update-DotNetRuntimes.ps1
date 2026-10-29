<#
.SYNOPSIS
    Remediation: Microsoft .NET Core security updates (v3.13)
    Nessus Plugin IDs : 302122, 307353 (+ 314679, 320854, 326863 -- same fix)

.DESCRIPTION
    For each .NET major channel ALREADY PRESENT on the machine (per arch):
      1. Installs the latest patch of each installed flavor via aka.ms
         channel permalinks
      2. Uninstalls OLDER versions of the same major (required to clear
         Tenable -- it flags every vulnerable version folder on disk)
      3. VERIFIES the new version is still on disk afterward; if the
         cleanup removed it (or anything else went sideways), reinstalls
         and re-verifies. Exits 1 if the machine does not end in a
         strictly better state than it started.

    v3.13 (SHRBME-08, 2026-10-29): every download failed with Could not
    establish trust relationship for the SSL/TLS secure channel, and the
    run spent five minutes retrying seven installers 3 times each. All
    downloads now go through Save-Installer. A TLS trust or handshake
    failure is not retried; it logs the likely cause (Zscaler root CA
    missing from LocalMachine\Root, system clock, out-of-date root store),
    and every later download in the run is skipped. Phase 1a no longer says
    the successor is present when all of its installs failed.

    v3.12 (CSLT-023, 2026-10-29): -RepairBrokenHost. CSLT-023 had no
    host\fxr folder, with .NET 6.0.21-6.0.32 and Windows Desktop 5.0.17
    under shared\, so the run stopped and asked for a manual repair. With
    the switch, each broken root gets the latest runtime patch of the newest
    major on disk (current major if shared\ is empty), then /repair of the
    same bundle if dotnet --list-runtimes still fails. The run continues
    once it works and stops as before if not. A host\fxr rename already
    queued in PendingFileRenameOperations skips the repair for that root,
    since only a reboot completes it.

    v3.11 (CSLT-174, 2026-10-29):
      * Phase 1c called Invoke-Msi, which only existed in
        Remove-DotNetEolChannel.ps1, so removing a superseded MSI-registered
        SDK threw and failed the run. The helper is now defined here, and the
        Phase 2 MSI uninstall uses it as well (full msiexec path, busy retry).
      * Phase 2 kept older registrations whose uninstall exited 0 but left
        the entry (9.0.16 and 8.0.27 on CSLT-174). Their files were already
        gone; only the registration was left. With
        -RemoveOrphanedRegistrations, an older entry whose exact version has
        no files on disk and no live dependency holder is now stripped from
        the registry, as Phase 1d already does for whole majors.
      * The closing error now says a step failed instead of blaming the
        runtime flavors, which on CSLT-174 had all passed verification.

    v3.10 (CSLT-015, 2026-10-28): host\fxr was missing entirely and
    dotnet.exe printed "The folder [...\host\fxr] does not exist" to stderr.
    Windows PowerShell 5.1 turned that into a terminating error under
    ErrorActionPreference Stop, so the run died at its first
    'dotnet --list-runtimes'. The call now runs with the preference relaxed,
    the missing folder is recognised as a broken host next to CSPRLT-94's
    missing hostfxr.dll, the on-disk runtimes are logged, and the stop
    message says to repair the newest one.

    v3.9 (2026-10-27): -RemoveRetiredMajor. Phase 4, after Phase 3 has
    verified the run, removes an EOL or near-EOL major (8 and 9 map to 10)
    once its successor is on disk for every flavor/arch that had it. The
    uninstall is Remove-DotNetEolChannel.ps1 -DotNet<N> -RemoveStaleFolders,
    staged beside this script. It refuses (exit 2) when:
      * an app's runtimeconfig.json targets that major without rollForward
        Major/LatestMajor (Program Files, ProgramData, inetpub, user
        AppData and .dotnet\tools are scanned);
      * an SDK or hosting bundle of that major is installed;
      * the run failed, or an install needs a reboot first.
    Implies -InstallSuccessorMajor.

    v3.8 (from the CSPC-072 run, 2026-10-12): -InstallSuccessorMajor did
    nothing on a .NET 8-only host 29 days before .NET 8's end of support.
    Phase 1a only considered majors in $EolMajors (9), and $EolSuccessorMajor
    only mapped 9 -> 10.
      * Phase 1a now also stages a successor for majors inside the
        end-of-support warning window ($EolWarnDays), so .NET 10 can be in
        place before the SEoL findings start. $EolSuccessorMajor adds 8 -> 10.
      * A major past its $EolDates entry is now EOL automatically. Before,
        .NET 8 would have dropped out of the warning on 2026-11-10 and not
        been reported as EOL until someone edited $EolMajors.
      * A successor shared by two retiring majors (8 and 9 -> 10) is
        installed once per flavor/arch.

    v3.7 (from the CSPC-004 run, 2026-10-06, plugin 326863): every x86 and
    arm64 SDK parsed as major 0. Get-DotNetSdkEntries read the major from
    $matches AFTER the '(x86)' arch -match had replaced it, so Phase 1c
    fetched https://aka.ms/dotnet/0.0/dotnet-sdk-win-x86.exe (a 0.2 MB
    non-installer), never gave the lone SDK 8.0.420 (x86) a newer sibling,
    and so never superseded it. That SDK is what holds the 8.0.26 x86
    runtimes, so their uninstalls kept no-op'ing. Parsing now lives in
    ConvertTo-SdkEntryInfo, which captures the major first.

    v3.6 (from the CSLT-020 run, 2026-09-02): v3.5's -InstallSuccessorMajor
    was SELF-DEFEATING and destructive. Phase 1a installed .NET 10, and
    Phase 2 then removed it again in the same run -- including hard-stripping
    the registry keys via the v3.4 fallback when the MSI uninstall no-op'd.
    Net effect: ~6 minutes of downloads, then the host ended exactly where it
    started, and Phase 3 still reported "All present flavors advanced".
      * ROOT CAUSE. Phase 2's ORPHANED GROUP check asks "does this
        (flavor, arch, major) have any payload on disk" -- but it read
        $before, the Phase-0 snapshot, while reading ARP entries FRESH.
        A brand-new major is by definition absent from $before, so .NET 10's
        just-written registrations looked like ARP entries backed by nothing.
        That comparison was only ever safe because every phase before v3.5
        installed newer PATCHES of majors already present at Phase 0;
        -InstallSuccessorMajor broke that invariant deliberately. Phase 2 now
        re-inventories the disk ($diskNow) at its own start and compares
        against that, so fresh ARP is matched against fresh disk.
      * WHY NOTHING CAUGHT IT. Phase 3 builds its checklist from $before too,
        so the successor major was never verified at all -- the run destroyed
        .NET 10 and still exited 0. Phase 3 now separately verifies every
        (flavor/arch, major) that Phase 1a reports having installed, and
        fails the run if one is missing from disk at the end.
      * Phase 1d is NOT affected: its orphan list is computed at Phase 0 from
        ARP entries that existed then, so it cannot flag a major whose
        registrations were written later in the run.

    v3.5: -InstallSuccessorMajor. For each EOL major found installed, ALSO
    installs the mapped successor major ($EolSuccessorMajor; currently only
    9 -> 10) for every flavor/arch that has the EOL major -- PURELY
    ADDITIVE, opt-in, never touches or removes the EOL major itself. This
    does NOT clear the SEoL finding and does NOT retarget any app: .NET's
    default roll-forward policy does not cross major versions, so an app
    targeting net9.0 will fail outright ("Framework ... version 9.0.0 ...
    not found") the moment .NET 9 is actually removed, unless that specific
    app is recompiled against net10.0 or its runtimeconfig.json explicitly
    sets "rollForward": "LatestMajor" -- neither of which this script can
    see or decide on the app's behalf. What it buys is pre-staging the
    runtime an app owner needs the moment they DO retarget, so migration
    does not require a second EC deployment round. Removing the EOL channel
    is still Remove-DotNetEolChannel.ps1, once nothing depends on it.

    v3.4 (from the CSLT-020 run, 2026-09-02): two fixes, one correcting a
    long-standing assumption this script had documented since v3.0.

    CORRECTION: every previous version claimed "Tenable keys on FOLDER
    presence, so an orphaned ARP-only registration is inventory hygiene, not
    a finding-clearing action." CSLT-020's Tenable export proves this false
    for at least one plugin family: NINE separate "Security Update for
    Microsoft .NET Core" findings (187859, 190535, 181277, 208286, 178193,
    179502, 209021, 183025, 193142 -- July 2023 through October 2024
    advisories) were ALL open on a host whose real runtimes were already
    fully current (8.0.30 x86, 9.0.19 x64). Every one of them reported
    Installed version 6.0.18.32522 at Path C:\Program Files\dotnet\ -- the
    exact DisplayVersion of an orphaned 'Microsoft Windows Desktop Runtime -
    6.0.18 (x64)' ARP entry with NO on-disk payload anywhere. Each finding's
    own description says outright: "Nessus has ... relied only on the
    application's self-reported version number" -- i.e. the ARP
    DisplayVersion, read directly, independent of any folder on disk.
    Removing a dead orphaned entry is therefore NOT purely cosmetic; for
    this plugin family it is required to clear the finding at all, no
    matter how current the real runtime is.

    BUG FIX (the reason the CSLT-020 orphan removal actually failed):
      * Removing that exact entry failed with 'The system cannot find the
        file specified' -- its QuietUninstallString pointed at a cached
        Package Cache bootstrapper .exe that no longer existed (consistent
        with zero on-disk payload: its own installer copy was gone too).
        Start-Process THROWING is a different code path than a bad exit
        code, so it landed in the generic catch block, which never reached
        the -AllowHardRemoval fallback added in v3.2 -- that fallback only
        ran after a successful (non-throwing) uninstall attempt. The catch
        block now runs the same holder-check + hard-removal logic, factored
        into a shared Invoke-ArpHardRemoval so both paths use it.

    v3.3 (from the CSPC-004 run, 2026-09-01, still plugin 326863): the v3.2
    holder diagnostics did their job and named the actual blocker --
    'Microsoft .NET SDK 8.0.420 (x86)' -- holding a WiX reference on BOTH the
    8.0.26 x86 Windows Desktop Runtime and the orphaned 8.0.26 x86 .NET
    Runtime entry. But 8.0.420 (x86) was the ONLY x86 SDK on the host, so
    Phase 1c's existing "keep the newest, remove the rest" grouping never
    even considered it: a group of one is trivially "the newest in its
    group," however stale. -RemoveSupersededSdks removes DUPLICATE SDKs; it
    never installed a newer one to replace a lone stale one.
      * New Install-Sdk (same aka.ms permalink family as Install-Runtime:
        https://aka.ms/dotnet/<major>.0/dotnet-sdk-win-<arch>.exe) installs
        the current SDK patch for every (major, arch) with an SDK present.
        This just adds a newer sibling to the group; the EXISTING
        supersede-and-remove logic (global.json pin guard included) then
        sees two entries and finishes the job unchanged.
      * Gated on -RemoveSupersededSdks, not a new switch: that flag already
        means "manage SDKs on this build machine, confirmed with the
        owner." Not run by default -- an SDK bundle is ~150-250 MB per arch,
        versus ~10-55 MB for a runtime patch, and should not download
        unprompted on every pass the way Phase 1's runtime installs do.

    v3.2 (from the SAME-DAY CSPC-004 re-run, 2026-08-31, still plugin 326863):
    the v3.1 orphaned-group removal reported "the ARP entry survived an
    exit-0 uninstall" -- unconditionally -- for an uninstall that actually
    exited 1612 (ERROR_INSTALL_SOURCE_ABSENT: the bundle's own cached
    uninstall payload is gone, not a bundle skipping uninstall for a live
    dependent). There was no SDK or hosting bundle in that arch/major to
    blame either, and the message pointed at a "dependency diagnostics"
    section that this removal path never populates in the first place.
      * Invoke-ArpEntryRemoval now diagnoses by the ACTUAL exit code (a table
        of known msiexec/bundle codes: 1605/1612/1618/1619/1620) instead of
        assuming exit-0-plus-dependents every time, and runs the WiX
        dependency-holder lookup INLINE for the failing version so the log
        either names a real holder or honestly says none exists.
      * -RemoveOrphanedRegistrations callers (both the whole-major Phase 1d
        path and the exact-group Phase 2 path) now pass -AllowHardRemoval:
        if no dependency holder is found for a confirmed-zero-payload entry,
        the ARP registry key is stripped directly rather than leaving dead
        metadata behind that a broken uninstaller can never clear.
      * Phase 1d's own inline removal (a duplicate of the Phase 2 helper) is
        gone; it now calls the shared function. That inline block was also
        checking $arpPaths before the variable was ever assigned (it was
        previously defined right before Phase 2, after Phase 1d already ran),
        so its verification silently reported success no matter what
        happened. $arpPaths is now assigned once, up front, before Phase 0.

    v3.1 (from the CSPC-004 run, 2026-08-31, plugin 326863): Phase 2 grouped
    ARP entries by (flavor prefix, major, arch) and kept whichever had the
    HIGHEST version registered IN THAT GROUP, with no check for whether the
    group had any on-disk payload backing it at all. x86 Windows Desktop
    Runtime never had an 8.x folder on this host (only 10.0.11 was ever
    installed for that flavor/arch) -- but ARP still carried 8.0.26/8.0.27
    registrations, and 8.0.27 was mechanically "the newest registered", so
    it was kept. Tenable's plugin 326863 reads DisplayVersion straight from
    that ARP entry, so "keep the max" cleared nothing; the same pattern held
    for x86 .NET Runtime 8.0.26-29. Phase 1d's existing ARP-only-major check
    could not catch this: it only fires when a MAJOR has zero payload
    ACROSS EVERY flavor/arch, and major 8 was genuinely installed elsewhere
    on this host (x64). Phase 2 now checks each group's EXACT
    (flavor, arch, major) against the disk inventory; a group with none
    logs as an ORPHANED GROUP and every entry in it becomes a removal
    candidate (gated by -RemoveOrphanedRegistrations, the same flag as the
    whole-major case, since both are "ARP claims a version nothing backs").

    v2 fixes (from the 2026-07-14 cspc-100 run):
      * Cleanup now keys on the version IN THE DISPLAYNAME, not
        DisplayVersion. ARP mixes numbering schemes (component entries
        like 80.36.x vs bundle entries like 10.0.9.x); sorting on
        DisplayVersion made v1 uninstall its own freshly-installed
        bundle. All entries sharing the newest name-version are kept.
      * Download sanity check is now an MZ-header check + 5 MB floor.
        v1's flat 20 MB floor false-flagged legitimate ~10 MB
        aspnetcore-runtime installers as block pages.

    v2.2 (from the 2026-07-17 cspc-100 rerun):
      * Verification is now idempotent: success = newest version on disk
        >= starting max AND no superseded (older) versions remain. v2.1
        required strictly-greater-than-start, which false-failed every
        flavor on machines that already began at the current patch.
      * When superseded version folders SURVIVE exit-0 uninstalls (MSI
        dependency references -- the cspc-099/cspc-100 pattern), the
        script now dumps HKLM:\SOFTWARE\Classes\Installer\Dependencies
        holders and their resolved product names into the log, then
        fails honestly. Clearing the refs is a human decision.

    v2.1: EOL-channel awareness. Majors past end-of-support (9 and
    anything below 8, as of July 2026) are still patched to their FINAL
    build (clears vulnerable-version findings), but the log carries a
    prominent EOL warning: SEoL/unsupported-software findings only clear
    by REMOVING the channel, and removal is deliberately left as a human
    decision -- apps pin to their major and do not roll forward, so
    check dependents before removing. The warning makes every deployment
    log double as an EOL census.

    v3.0 closes a long-standing blind spot: majors that exist ONLY as ARP
    registrations, with no runtime payload on disk. Every phase was driven off
    'dotnet --list-runtimes', so such a major never entered the check list at
    all -- it was not patched, not verified, and not EOL-reported. Seen on
    CSPRLT-116 (.NET 5.0.17 / 6.0.15) and again on CSPC-099, where .NET 6.0.36
    sat in ARP while the starting state showed only 8.0.30, and the EOL banner
    fired for .NET 8 but stayed silent about a channel dead since Nov 2024.
      * A new ARP census runs alongside the runtime inventory and reports each
        major as ON-DISK, ARP-ONLY (orphaned registration), or both.
      * ARP-only majors are included in the EOL warnings, so a dead channel is
        named even with no payload.
      * -RemoveOrphanedRegistrations (opt-in) uninstalls ARP entries for majors
        with no payload on disk. Removal is verified, since a bundle with
        dependents reports success without doing anything. Originally assumed
        Tenable keys on FOLDER presence, making this inventory hygiene rather
        than a finding-clearing action -- CORRECTED in v3.4 below: at least
        the "Security Update for Microsoft .NET Core" plugin family reads the
        ARP DisplayVersion directly, so this DOES clear real findings.

    v2.9: -RemoveSupersededSdks clears the ACTUAL blocker to pruning runtimes.
    On CSPC-004 the runtime cleanup was not failing -- it was correctly refusing,
    because SDK 8.0.420 and 8.0.421 hold WiX dependency references on the
    8.0.26 and 8.0.27 frameworks. A bundle with registered dependents skips its
    uninstall and returns 0, and -RemoveStaleFolders refuses to delete a
    framework a live product owns. Adding more removal logic could not help; the
    SDKs had to go first.
      * New Phase 1c (opt-in) removes SUPERSEDED SDKs within a major, keeping the
        newest. SDKs roll forward, so a build targeting net8.0 uses the newest
        8.0.4xx present -- older ones exist only to pin frameworks.
      * GLOBAL.JSON GUARD. A global.json can pin an exact SDK version, and
        removing that version breaks the developer's build. Phase 1c scans user
        profiles and common source roots for global.json files, reads any
        sdk.version pin, and REFUSES to remove a version that is pinned --
        reporting the file so the owner can be consulted.
      * Runs BEFORE Phase 2, so once the refs are released the existing runtime
        cleanup succeeds on the same pass rather than needing a second run.
      * Removal is verified (a bundle with remaining dependents still reports 0).

    v2.8: makes the two strategic problems visible, because the monthly churn is
    a symptom rather than the disease.
      * REDUNDANCY SUMMARY. Counts how many patch versions of each major are
        installed and how many are redundant. .NET rolls forward, so an app
        targeting net8.0 binds to the highest 8.0.x present -- every older patch
        is dead weight that generates a finding per monthly advisory. CSPC-004
        carries three 8.x patches (8.0.26 / 8.0.27 / 8.0.30) where one would do.
        The cause is that EC's MS26-DOTNET patches INSTALL without removing, so
        each month adds a version and nothing prunes.
      * APPROACHING-EOL WARNING. The existing EOL check only fires once a major
        is already dead. .NET 8 ends support 2026-11-10, and a host still pinned
        to 8.x by an SDK in November inherits the whole problem again as SEoL
        findings. Majors within EOL_WARN_DAYS (default 180) are now flagged with
        the date and days remaining, so the retargeting conversation happens
        before the deadline rather than after.

    v2.7 (from three CSPC-004 runs on 2026-08-06 that made zero progress):
      * Phase 2 now VERIFIES each uninstall instead of trusting exit 0. A WiX
        bundle that still has registered dependents SKIPS its uninstall and
        returns SUCCESS -- so the same six ARP entries were reported 'Removed'
        on every run and were still there next time. The script now re-queries
        ARP after each uninstall and, if the entry survives, says so and names
        the likely reason rather than reporting a removal that did not happen.
      * -AbortOnPendingReboot exits 3010 immediately when a reboot is pending,
        instead of burning 30-90 minutes on installs that will roll back.
        CSPC-004 accumulated PendingFileRenameOperations across runs (46 -> 54)
        because each failed attempt queued more, and only the 8.0 x86 bundles
        failed -- consistent with queued renames targeting those exact files.

    v2.6 (from the 2026-08-06 CSPC-004 run):
      * Installer bundles now get /log, so a 1603 is diagnosable instead of
        opaque. CSPC-004 produced two 1603s (x86 WindowsDesktop and x86
        NETCore) after 8-12 minutes each -- long enough to be a rollback --
        with nothing to inspect afterwards.
      * Pending-reboot PRE-CHECK before Phase 1. A pending reboot is a common
        cause of 1603 and of partial bundle installs.
      * Downloads retry (3 attempts) with an explicit timeout. The 10.0 x86
        download on CSPC-004 timed out after 5 minutes with no retry.
      * Diagnostics now classify the dependency holder: HOSTING BUNDLE vs
        .NET SDK vs orphan, because the remedy differs. An SDK pins the
        framework, targeting pack and workload packs it shipped with, and
        CANNOT be 'updated in place' to release them -- the superseded SDK
        must be removed (CSPC-004: SDK 8.0.420 pinned 8.0.26, SDK 8.0.421
        pinned 8.0.27, blocking six flavours).
      * Starting state now lists installed SDKs, since their presence
        predicts exactly this class of stall.

    v2.5 (from the 2026-08-05 CSLT-044 run): handles the ASP.NET Core HOSTING
    BUNDLE. The hosting bundle (ARP name 'Microsoft .NET <ver> - Windows Server
    Hosting') installs the .NET + ASP.NET Core shared frameworks plus the IIS
    module, and registers WiX dependency providers on the frameworks it owns.
    While the bundle stays on an old patch it PINS those framework folders, so
    the uninstall exits 0 and the payload survives -- exactly what happened on
    CSLT-044, where 8.0.27 was held by 'Microsoft .NET 8.0.27 - Windows Server
    Hosting' across four flavour/arch combinations.
      * New Phase 1b updates each installed hosting bundle to the current patch
        of its own major, which moves its dependency refs forward and releases
        the old framework.
      * -RemoveStaleFolders now REFUSES to delete a framework version that a
        live dependency provider still holds. Deleting a folder the hosting
        bundle owns can break IIS-hosted ASP.NET Core apps and leaves the
        bundle's registration inconsistent.
      * NOTE: the aka.ms hosting-bundle permalink has historically lagged the
        newest patch, so the result is verified rather than assumed.
      * NOTE: a manual IIS restart may be needed after a hosting bundle change
        (stop WAS, then start W3SVC and dependents). The script does not do this
        for you -- it logs the reminder.

    v2.4 (from the 2026-07-28 CSPRLT-116 run): the superseded-version check
    is now PER MAJOR. v2.3 compared every version of a flavor/arch against the
    single highest, so on a machine with .NET 8 and .NET 9 side by side it
    reported the fully-patched 8.0.29 as "stale beside 9.0.18" -- a false
    failure, and with -RemoveStaleFolders it would have DELETED a current,
    in-use runtime. Different majors are independent channels; only versions
    within the same major can supersede one another.

.PARAMETER RemoveStaleFolders
    v2.3: when superseded version folders survive with NO Installer
    dependency references (orphaned payload -- deregistered but never
    deleted, as confirmed on cspc-100), delete them directly. This is
    what Microsoft's .NET Uninstall Tool does. Guards: a newer version
    of the same flavor/arch must exist on disk, and the folder must
    pass an in-use test (atomic rename) -- a folder whose files are
    loaded by a running app is skipped with a warning to retry after
    the app is closed.

.NOTES
    Deploy via Endpoint Central (SYSTEM). EC-safe concatenated strings.

    ENDPOINT CENTRAL CONFIGURATION:
      Execute Script from : Repository
      Script Arguments    : switches only, e.g. -RemoveOrphanedRegistrations
                            (bare switches contain no $ and no quotes, so they
                            are not subject to EC's argument mangling; the log
                            now echoes every switch so a dropped one is visible)
      Specify exit code(s): 0,3010
                            3010 means "done, reboot required" and is a SUCCESS.
                            Listing only 0 makes every reboot-required run show
                            as failed. Exit 2 is deliberately NOT in the success
                            list -- it means a human must act (SDK or hosting
                            bundle pinning a framework, orphans found but not
                            removed, a host needing a reboot first), and showing
                            those as failed in EC is the correct signal.
      Run As              : System (MSI install/uninstall requires it)
    -DryRun to preview. Exit: 0 ok / 3010 reboot recommended / 1 failure /
    2 updates done but -RemoveRetiredMajor refused (a human decides).
    -RemoveRetiredMajor: also stage Remove-DotNetEolChannel.ps1 as a
    Dependency File.

    CSPRLT-94 (2026-09-16): 'dotnet --list-runtimes' failed outright with
    "the required library hostfxr.dll could not be found in
    [C:\Program Files\dotnet\host\fxr\8.0.21]". dotnet.exe resolves the
    HIGHEST host\fxr\<version> directory and loads hostfxr.dll from it, so a
    resolver folder that exists WITHOUT its DLL breaks the muxer for every
    installed major. Because --list-runtimes then emitted only that error and
    matched no runtime lines, Get-InstalledMap reported that root as EMPTY,
    which every later phase reads as "no .NET installed here". It now detects
    the failure, falls back to shared\ payload folders for inventory, and
    stops with exit 1 rather than acting on untrustworthy data. The stale-
    folder rollback also now checks whether it restored a resolver folder
    whose DLL had already been deleted, which is one way to reach that state.
#>

[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$RemoveStaleFolders,
    # Exit 3010 straight away if a reboot is pending. Recommended: repeated runs
    # on a host with queued file renames waste 30-90 minutes and change nothing.
    [switch]$AbortOnPendingReboot,
    # Remove superseded .NET SDKs within a major, keeping the newest. This is what
    # releases the dependency refs that block runtime pruning. Guarded by a
    # global.json scan; NOT enabled by default because it is a build-environment
    # change on someone's development machine. v3.3: also installs the current
    # SDK patch for every (major, arch) present BEFORE the dedup check, so a
    # LONE stale SDK (no duplicate to compare against) is no longer invisible
    # to this cleanup -- a single old SDK still pins whatever frameworks it
    # shipped with (CSPC-004, 2026-09-01).
    [switch]$RemoveSupersededSdks,
    # Uninstall ARP registrations that have NO runtime payload backing them --
    # covers two distinct cases: a whole MAJOR with zero payload across every
    # flavor/arch (Phase 1d), and a specific (flavor, arch, major) with zero
    # payload even though the major exists elsewhere on the host (Phase 2,
    # v3.1). BOTH cases can clear a real version finding, not just tidy
    # inventory: plugin 326863 (v3.1, Phase 2 case) and the "Security Update
    # for Microsoft .NET Core" plugin family (v3.4, CSLT-020, Phase 1d case
    # -- 9 findings on one dead ARP-only .NET 6 entry) both read DisplayVersion
    # straight from ARP, so an orphaned entry left in place (even the
    # "newest" one in its group) keeps the finding open regardless of what
    # the real, current runtime looks like.
    [switch]$RemoveOrphanedRegistrations,
    # For every EOL major found installed, ALSO install the successor major
    # (currently only 9 -> 10) for each flavor/arch that has the EOL major --
    # PURELY ADDITIVE, never touches or removes the EOL major's files or ARP
    # registrations. This does NOT retarget any app and does NOT clear the
    # SEoL finding by itself: .NET's default roll-forward policy does not
    # cross major versions, so an app targeting net9.0 still requires .NET 9
    # to be present and keeps running on it until it is explicitly
    # recompiled against net10.0 or its runtimeconfig.json sets
    # "rollForward": "LatestMajor". What this buys is pre-staging the
    # runtime the app owner needs the moment they retarget, so migration
    # does not need a second EC deployment round. Removing the EOL channel
    # once nothing depends on it is still Remove-DotNetEolChannel.ps1, a
    # separate human decision.
    [switch]$InstallSuccessorMajor,
    # v3.9: after the successor is verified on disk, remove the retiring major
    # (EOL or near-EOL, e.g. 8 -> 10) by running Remove-DotNetEolChannel.ps1
    # -DotNet<N> -RemoveStaleFolders, which must be staged beside this script.
    # Implies -InstallSuccessorMajor. Refuses (exit 2) when an app's
    # runtimeconfig.json targets that major without rolling forward, when an
    # SDK or hosting bundle of that major is installed, or when the run is
    # not otherwise clean. That script's own foreign-WiX-holder check also
    # still applies.
    [switch]$RemoveRetiredMajor,
    # v3.12: when dotnet.exe cannot load its host (host\fxr folder or
    # hostfxr.dll missing), install the latest patch of the newest major on
    # disk, then /repair it if the host is still broken, and continue only
    # once dotnet --list-runtimes works. Skipped when a host\fxr rename is
    # already queued for the next boot -- that host needs a reboot instead.
    [switch]$RepairBrokenHost
)
if ($RemoveRetiredMajor) { $InstallSuccessorMajor = [switch]$true }

$ErrorActionPreference = 'Stop'
$LogDir  = 'C:\Logs\CompoSecure'
# Concatenated, not Join-Path: Join-Path validates the drive qualifier, which
# makes this file impossible to dot-source for unit tests off Windows.
$LogFile = $LogDir + '\DotNetUpdate_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.log'
$TempDir = ($env:TEMP) + '\dotnet_update'
if (-not (Test-Path $LogDir))  { New-Item -ItemType Directory -Path $LogDir  -Force -ErrorAction SilentlyContinue | Out-Null }
if (-not (Test-Path $TempDir)) { New-Item -ItemType Directory -Path $TempDir -Force -ErrorAction SilentlyContinue | Out-Null }
# Set by Save-Installer on the first TLS failure; every later download skips.
$script:TlsFailure = ''

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] [' + $Level + '] ' + $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

function Get-MajorSupportStatus {
    # 'EOL', 'SOON' (within WarnDays of its end date) or 'OK'. A major past its
    # $EolDates entry is EOL even if nobody has added it to $EolMajors yet.
    param([int]$Major, [int[]]$EolMajors, [int]$MinSupported, [hashtable]$EolDates, [int]$WarnDays, [datetime]$Now)
    if (($EolMajors -contains $Major) -or ($Major -lt $MinSupported)) { return 'EOL' }
    if ($EolDates.ContainsKey($Major)) {
        $days = ([datetime]$EolDates[$Major] - $Now).TotalDays
        if ($days -le 0) { return 'EOL' }
        if ($days -le $WarnDays) { return 'SOON' }
    }
    return 'OK'
}

function Get-SuccessorTargets {
    # -InstallSuccessorMajor work list: one { From; To } per EOL or near-EOL
    # major that has a configured successor, ascending by From.
    param([int[]]$EolSeen, [int[]]$EolSoonSeen, [hashtable]$Map)
    $out = @()
    foreach ($m in (@($EolSeen) + @($EolSoonSeen) | Sort-Object -Unique)) {
        if ($Map.ContainsKey([int]$m)) { $out += [pscustomobject]@{ From = [int]$m; To = $Map[[int]$m] } }
    }
    return $out
}

function Test-RuntimeConfigNeedsMajor {
    # Does the app behind this <app>.runtimeconfig.json stop starting when
    # .NET $Major is removed? Framework-dependent apps bind to their major and
    # only cross to a later one with rollForward Major / LatestMajor (or the
    # legacy rollForwardOnNoCandidateFx = 2). Self-contained apps list
    # includedFrameworks and carry their own runtime. Unparseable text that
    # names the major counts as a dependency: a guess must not delete it.
    param([string]$Json, [int]$Major)
    if ([string]::IsNullOrWhiteSpace($Json)) { return $false }
    try { $cfg = $Json | ConvertFrom-Json -ErrorAction Stop } catch {
        return ($Json -match ('"version"\s*:\s*"' + $Major + '\.'))
    }
    $ro = $cfg.runtimeOptions
    if ($null -eq $ro) { return $false }
    if ($ro.includedFrameworks) { return $false }
    $rf = '' + $ro.rollForward
    if ($rf -match '^(?i)(Major|LatestMajor)$') { return $false }
    if (('' + $ro.rollForwardOnNoCandidateFx) -eq '2') { return $false }
    $fws = @()
    if ($ro.framework) { $fws += $ro.framework }
    if ($ro.frameworks) { $fws += @($ro.frameworks) }
    foreach ($fw in $fws) {
        if (('' + $fw.version) -match ('^' + $Major + '\.')) { return $true }
    }
    return $false
}

function Get-RetireDecision {
    # -RemoveRetiredMajor go/no-go for one retiring major. Removal only when
    # the run is otherwise clean and every flavor/arch that had the major now
    # has its successor on disk. Returns Remove (bool) and Reasons (why not).
    param(
        [int]$Major, [int]$Successor,
        [string[]]$KeysWithMajor, [hashtable]$After,
        [int]$AppPinCount, [string[]]$Sdks, [string[]]$HostingBundles,
        [bool]$RunFailed, [bool]$RebootPending, [bool]$RemoverFound
    )
    $reasons = @()
    if ($Major -lt 5 -or $Major -gt 9) { $reasons += ('Remove-DotNetEolChannel.ps1 has no -DotNet' + $Major + ' switch') }
    if ($RunFailed) { $reasons += 'an earlier step of this run failed' }
    if ($RebootPending) { $reasons += 'an install this run needs a reboot first' }
    if (-not $RemoverFound) { $reasons += 'Remove-DotNetEolChannel.ps1 is not staged beside this script or in C:\' }
    foreach ($k in $KeysWithMajor) {
        $has = @($After[$k] | Where-Object { $_.Major -eq $Successor })
        if ($has.Count -eq 0) { $reasons += ($k + ' has no .NET ' + $Successor + ' on disk') }
    }
    if ($AppPinCount -gt 0) { $reasons += ('' + $AppPinCount + ' app(s) on disk target .NET ' + $Major + ' without rolling forward') }
    foreach ($s in $Sdks) { $reasons += ('SDK installed: ' + $s + ' (developer machine; remove by hand with the owner)') }
    foreach ($h in $HostingBundles) { $reasons += ('Hosting bundle installed: ' + $h + ' (IIS apps)') }
    return [pscustomobject]@{ Remove = ($reasons.Count -eq 0); Reasons = $reasons }
}

function Get-HostFxrFailure {
    # '' when the muxer works, else which part of host\fxr is broken:
    #   MissingDll    -- CSPRLT-94 (2026-09-16): host\fxr\8.0.21 existed with
    #                    no hostfxr.dll in it. dotnet.exe resolves the HIGHEST
    #                    host\fxr\<ver> folder and loads hostfxr.dll from it,
    #                    so the muxer breaks for EVERY installed major:
    #                    "the required library hostfxr.dll could not be found"
    #   MissingFolder -- CSLT-015 (2026-10-28): host\fxr itself was gone:
    #                    "The folder [C:\Program Files\dotnet\host\fxr] does
    #                    not exist"
    # --list-runtimes then emits ONLY that error and matches no runtime lines,
    # which used to be indistinguishable from "no runtimes installed".
    param($Lines)
    if (-not $Lines) { return '' }
    foreach ($line in $Lines) {
        $s = [string]$line
        if ($s -match '(?i)required library hostfxr\.dll could not be found') { return 'MissingDll' }
        if ($s -match '(?i)folder \[[^\]]*\\host\\fxr\] does not exist') { return 'MissingFolder' }
    }
    return ''
}

function Test-HostFxrLoadFailure {
    param($Lines)
    return ((Get-HostFxrFailure -Lines $Lines) -ne '')
}

function Get-RuntimeVersionsFromDisk {
    # Fallback inventory that does not need a working muxer: the payload
    # folders themselves. Returns objects with Flavor + [version] Version.
    param([string]$Root)
    $out = @()
    if ([string]::IsNullOrWhiteSpace($Root)) { return $out }
    $sharedRoot = $Root + '\shared'
    if (-not (Test-Path -LiteralPath $sharedRoot)) { return $out }
    Get-ChildItem -LiteralPath $sharedRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $flavor = $_.Name
        if ($flavor -notmatch '^Microsoft\.(?:NETCore|WindowsDesktop|AspNetCore)\.App$') { return }
        Get-ChildItem -LiteralPath $_.FullName -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.Name -match '^(\d+\.\d+\.\d+)') {
                $out += [pscustomobject]@{ Flavor = $flavor; Version = [version]$matches[1] }
            }
        }
    }
    return $out
}

function Get-HostRepairPlan {
    # -RepairBrokenHost: what to do for one broken root. A host\fxr rename
    # already queued for boot means the fix is a reboot; installing now would
    # only queue another. Otherwise install the newest major on disk (its
    # runtime installer carries host\fxr), or the current major if none.
    param($OnDisk, [string[]]$PendingRenames, [string]$Arch, [int]$FallbackMajor)
    $hostDir = if ($Arch -eq 'x86') { '\\Program Files \(x86\)\\dotnet\\host\\fxr' } else { '\\Program Files\\dotnet\\host\\fxr' }
    $queued = @($PendingRenames | Where-Object { $_ -and ($_ -match ('(?i)' + $hostDir)) })
    if ($queued.Count -gt 0) {
        return [pscustomobject]@{ Action = 'Reboot'; Major = 0; Reason = ($queued[0] -replace '^\\\?\?\\', '') }
    }
    $majors = @($OnDisk | ForEach-Object { $_.Version.Major } | Sort-Object -Unique -Descending)
    if ($majors.Count -eq 0) {
        return [pscustomobject]@{ Action = 'Install'; Major = $FallbackMajor; Reason = 'no runtimes under shared\' }
    }
    return [pscustomobject]@{ Action = 'Install'; Major = [int]$majors[0]; Reason = ('newest major on disk is ' + $majors[0]) }
}

function Test-DotNetHostWorks {
    param([string]$Exe)
    return (@(Invoke-DotNetListRuntimes -Exe $Exe | Where-Object { $_ -match '^Microsoft\.(?:NETCore|WindowsDesktop|AspNetCore)\.App\s+\d' }).Count -gt 0)
}

function Repair-BrokenHostRoots {
    param($Roots, [string[]]$PendingRenames, [int]$FallbackMajor)
    foreach ($root in $Roots) {
        $onDisk = @(Get-RuntimeVersionsFromDisk -Root (Split-Path -Parent $root.Exe))
        $plan = Get-HostRepairPlan -OnDisk $onDisk -PendingRenames $PendingRenames -Arch $root.Arch -FallbackMajor $FallbackMajor
        if ($plan.Action -eq 'Reboot') {
            Write-Log ('  ' + $root.Arch + ': a host\fxr replacement is already queued for the next boot:') -Level WARN
            Write-Log ('    ' + $plan.Reason) -Level WARN
            Write-Log '    Not reinstalling -- reboot to let it complete, then re-run.' -Level WARN
            continue
        }
        Write-Log ('  ' + $root.Arch + ': installing .NET ' + $plan.Major + ' runtime (' + $plan.Reason + ').')
        $ok = Install-Runtime -Flavor 'Microsoft.NETCore.App' -Major $plan.Major -Arch $root.Arch
        if ($DryRun) { continue }
        if ($ok -and (Test-DotNetHostWorks -Exe $root.Exe)) { continue }
        Write-Log ('  ' + $root.Arch + ': host still broken after install -- running the installer with /repair.') -Level WARN
        Install-Runtime -Flavor 'Microsoft.NETCore.App' -Major $plan.Major -Arch $root.Arch -Mode repair | Out-Null
    }
}

function Get-PendingFileRenames {
    $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
    return @($v | Where-Object { $_ })
}

function Invoke-DotNetListRuntimes {
    # dotnet.exe writes host errors to stderr. Under ErrorActionPreference
    # Stop, Windows PowerShell 5.1 turns a stderr line of a 2>&1 redirect into
    # a terminating NativeCommandError, which ended the CSLT-015 run before
    # the broken-host check could read it. Relaxed for this call only.
    param([string]$Exe)
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = @(& $Exe --list-runtimes 2>&1 | ForEach-Object { '' + $_ })
    } finally {
        $ErrorActionPreference = $saved
    }
    return $out
}

function Get-InstalledMap {
    # Returns hashtable: '<arch>|<flavor>' -> list of [version] present on disk
    param($Roots)
    $map = @{}
    foreach ($root in $Roots) {
        if (-not (Test-Path $root.Exe)) { continue }
        $lines = Invoke-DotNetListRuntimes -Exe $root.Exe
        $matched = 0
        foreach ($line in $lines) {
            if ($line -match '^(Microsoft\.(?:NETCore|WindowsDesktop|AspNetCore)\.App)\s+(\d+\.\d+\.\d+)') {
                $key = $root.Arch + '|' + $matches[1]
                if (-not $map.ContainsKey($key)) { $map[$key] = @() }
                $map[$key] += [version]$matches[2]
                $matched++
            }
        }
        $failure = ''
        if ($matched -eq 0) { $failure = Get-HostFxrFailure -Lines $lines }
        if ($failure) {
            # Do NOT let a broken muxer masquerade as an empty root: every
            # later phase would read that as "nothing installed here" and
            # start installing/removing against bogus inventory.
            $script:MuxerBroken = $true
            if ($script:MuxerBrokenRoots -notcontains $root.Arch) {
                $script:MuxerBrokenRoots += $root.Arch
            }
            if ($script:MuxerFailures -notcontains $failure) { $script:MuxerFailures += $failure }
            switch ($failure) {
                'MissingDll'    { Write-Log ('  ' + $root.Arch + ': dotnet.exe cannot load hostfxr.dll -- the host\fxr set is broken.') -Level ERROR }
                'MissingFolder' { Write-Log ('  ' + $root.Arch + ': dotnet.exe finds no host\fxr folder -- the .NET host resolver is missing.') -Level ERROR }
                default         { throw ('Unknown host failure ' + $failure) }
            }
            foreach ($line in $lines) {
                if ([string]$line -match '(?i)hostfxr|host\\fxr') { Write-Log ('    ' + ([string]$line).Trim()) -Level ERROR }
            }
            Write-Log '    Falling back to shared\ payload folders for inventory.' -Level WARN
            $onDisk = @(Get-RuntimeVersionsFromDisk -Root (Split-Path -Parent $root.Exe))
            if ($onDisk.Count -eq 0) { Write-Log '    No runtime folders under shared\ either.' -Level WARN }
            foreach ($d in $onDisk) {
                Write-Log ('    on disk: ' + $d.Flavor + ' ' + $d.Version) -Level WARN
                $key = $root.Arch + '|' + $d.Flavor
                if (-not $map.ContainsKey($key)) { $map[$key] = @() }
                $map[$key] += $d.Version
            }
        }
    }
    return $map
}

function Get-DownloadFailureKind {
    # TLS failures come from this machine's certificate store or TLS setup,
    # so retrying the same request cannot succeed. '' = retryable.
    param([string]$Message)
    if ($Message -match '(?i)trust relationship|remote certificate is invalid|UntrustedRoot|PartialChain|certificate chain') { return 'TlsTrust' }
    if ($Message -match '(?i)Could not create SSL/TLS secure channel|SSL connection could not be established') { return 'TlsChannel' }
    return ''
}

function Write-TlsFailureHelp {
    param([string]$Kind, [string]$Url)
    Write-Log '    *** TLS FAILURE -- no download can succeed on this machine as it is. ***' -Level ERROR
    if ($Kind -eq 'TlsTrust') {
        Write-Log '    The server certificate chain is not trusted by this machine. With' -Level ERROR
        Write-Log '    Zscaler SSL inspection the chain ends at the Zscaler root CA, which' -Level ERROR
        Write-Log '    must be in LocalMachine\Root (the SYSTEM account does not use the' -Level ERROR
        Write-Log '    user store). Other causes: a wrong system clock, or an out-of-date' -Level ERROR
        Write-Log '    root store (pending Windows Update reboot).' -Level ERROR
        $z = @(Get-ChildItem 'Cert:\LocalMachine\Root' -ErrorAction SilentlyContinue | Where-Object { $_.Subject -match '(?i)zscaler' })
        if ($z.Count -gt 0) {
            foreach ($c in $z) { Write-Log ('    Zscaler root present: ' + $c.Subject + ' (expires ' + $c.NotAfter.ToString('yyyy-MM-dd') + ')') -Level ERROR }
        } else {
            Write-Log '    No Zscaler root CA in LocalMachine\Root.' -Level ERROR
        }
    } else {
        Write-Log '    The TLS handshake itself failed: TLS 1.2 disabled in SCHANNEL, or a' -Level ERROR
        Write-Log '    proxy/firewall resetting the connection.' -Level ERROR
    }
    Write-Log ('    System clock (UTC): ' + (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) -Level ERROR
    Write-Log ('    Test as SYSTEM: Invoke-WebRequest ' + $Url + ' -UseBasicParsing -Method Head') -Level ERROR
    Write-Log '    Skipping every remaining download this run.' -Level ERROR
}

function Save-Installer {
    # Downloads with retries. Returns $true when $Dest was written.
    param([string]$Url, [string]$Dest, [int]$TimeoutSec = 300, [int]$Attempts = 3)
    if ($script:TlsFailure) {
        Write-Log ('    Skipped -- an earlier download failed TLS (' + $script:TlsFailure + ').') -Level ERROR
        return $false
    }
    foreach ($attempt in 1..$Attempts) {
        try {
            Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing -TimeoutSec $TimeoutSec
            return $true
        } catch {
            $msgs = @()
            $ex = $_.Exception
            while ($ex) { $msgs += $ex.Message; $ex = $ex.InnerException }
            $msg = $msgs -join ' | '
            Remove-Item $Dest -Force -ErrorAction SilentlyContinue
            $kind = Get-DownloadFailureKind -Message $msg
            if ($kind) {
                Write-Log ('    Download failed: ' + $msg) -Level ERROR
                $script:TlsFailure = $kind
                Write-TlsFailureHelp -Kind $kind -Url $Url
                return $false
            }
            Write-Log ('    Download attempt ' + $attempt + ' of ' + $Attempts + ' failed: ' + $msg) -Level WARN
            if ($attempt -lt $Attempts) { Start-Sleep -Seconds 10 }
        }
    }
    Write-Log ('    Download failed after ' + $Attempts + ' attempts. If Zscaler is throttling large') -Level ERROR
    Write-Log '    transfers, stage the installer locally and run it manually.' -Level ERROR
    return $false
}

function Install-Runtime {
    # Downloads + installs one flavor/major/arch. Returns $true on success.
    # -Mode repair reruns the same bundle with /repair (-RepairBrokenHost).
    param([string]$Flavor, [string]$Major, [string]$Arch, [ValidateSet('install', 'repair')][string]$Mode = 'install')
    $stems = @{
        'Microsoft.NETCore.App'        = 'dotnet-runtime-win-'
        'Microsoft.WindowsDesktop.App' = 'windowsdesktop-runtime-win-'
        'Microsoft.AspNetCore.App'     = 'aspnetcore-runtime-win-'
    }
    $stem = $stems[$Flavor]
    $url  = 'https://aka.ms/dotnet/' + $Major + '.0/' + $stem + $Arch + '.exe'
    $dest = Join-Path $TempDir ($stem + $Arch + '-' + $Major + '.exe')
    Write-Log ('  [' + $Flavor + ' ' + $Major + '.0 ' + $Arch + '] ' + $url)
    if ($DryRun) { Write-Log '    [DRYRUN] Would download + install.'; return $true }
    # v2.6: retry with an explicit timeout -- a single 5-minute stall used to
    # abandon the whole flavour (CSPC-004, 10.0 x86).
    if (-not (Save-Installer -Url $url -Dest $dest)) { return $false }
    $item = Get-Item $dest
    $szMB = [math]::Round($item.Length / 1MB, 1)
    # Sanity: must be a Windows executable (MZ header) and non-trivial size.
    # v2: size floor is 5 MB -- aspnetcore installers are legitimately ~10 MB.
    $fs = [System.IO.File]::OpenRead($dest)
    $b1 = $fs.ReadByte(); $b2 = $fs.ReadByte()
    $fs.Close(); $fs.Dispose()
    $isMZ = ($b1 -eq 0x4D -and $b2 -eq 0x5A)
    Write-Log ('    Downloaded ' + $szMB + ' MB, MZ header: ' + $isMZ)
    if (-not $isMZ -or $item.Length -lt 5MB) {
        Write-Log '    Not a valid installer (block page?). Skipping.' -Level ERROR
        Remove-Item $dest -Force -ErrorAction SilentlyContinue
        return $false
    }
    # v2.6: /log so a 1603 leaves something to read.
    $bundleLog = Join-Path $LogDir ('dotnet_bundle_' + $Flavor + '_' + $Major + '_' + $Arch + $(if ($Mode -eq 'repair') { '_repair' } else { '' }) + '.log')
    $p = Start-Process $dest -ArgumentList ('/' + $Mode + ' /quiet /norestart /log "' + $bundleLog + '"') -Wait -PassThru
    Write-Log ('    Installer exit: ' + $p.ExitCode)
    Remove-Item $dest -Force -ErrorAction SilentlyContinue
    if ($p.ExitCode -eq 3010) { $script:Reboot = $true; return $true }
    if ($p.ExitCode -ne 0) {
        Write-Log '    Install failed.' -Level ERROR
        Write-Log ('    Bundle log: ' + $bundleLog) -Level ERROR
        if ($p.ExitCode -eq 1603) {
            Write-Log '    1603 is a fatal/rollback error. Most common causes here: a pending' -Level ERROR
            Write-Log '    reboot, a locked file from a running .NET process, or a damaged' -Level ERROR
            Write-Log '    Package Cache entry for the version being replaced. Search the' -Level ERROR
            Write-Log '    bundle log for "Error 0x" and "Rolling back".' -Level ERROR
        }
        return $false
    }
    return $true
}



function Install-Sdk {
    # Downloads + installs the current SDK patch for one major/arch. Same
    # aka.ms permalink family as Install-Runtime (confirmed pattern:
    # https://aka.ms/dotnet/<major>.0/dotnet-sdk-win-<arch>.exe).
    #
    # v3.3: added because a LONE stale SDK per (major, arch) was invisible to
    # Phase 1c's existing dedup logic, which only flags a version as
    # superseded when TWO OR MORE share a group. CSPC-004 (2026-09-01) had
    # exactly one x86 SDK (8.0.420) holding a WiX reference on the 8.0.26 x86
    # frameworks -- confirmed by name in the v3.2 holder diagnostics -- and
    # nothing in Phase 1c ever attempted to install the current x86 patch
    # (8.0.424) that would let the existing supersede-and-remove logic below
    # actually fire. Installing here just adds a second, newer entry to the
    # group; the removal path is unchanged and still respects the global.json
    # pin guard and -RemoveSupersededSdks gating.
    param([string]$Major, [string]$Arch)
    $url  = 'https://aka.ms/dotnet/' + $Major + '.0/dotnet-sdk-win-' + $Arch + '.exe'
    $dest = Join-Path $TempDir ('dotnet-sdk-win-' + $Arch + '-' + $Major + '.exe')
    Write-Log ('  [SDK ' + $Major + '.0 ' + $Arch + '] ' + $url)
    if ($DryRun) { Write-Log '    [DRYRUN] Would download + install.'; return $true }
    if (-not (Save-Installer -Url $url -Dest $dest)) { return $false }
    $item = Get-Item $dest
    $szMB = [math]::Round($item.Length / 1MB, 1)
    $fs = [System.IO.File]::OpenRead($dest)
    $b1 = $fs.ReadByte(); $b2 = $fs.ReadByte()
    $fs.Close(); $fs.Dispose()
    $isMZ = ($b1 -eq 0x4D -and $b2 -eq 0x5A)
    Write-Log ('    Downloaded ' + $szMB + ' MB, MZ header: ' + $isMZ)
    # SDK bundles run ~150-250 MB; a much smaller file here is a block page,
    # same MZ-header + size-floor sanity check as Install-Runtime (v2).
    if (-not $isMZ -or $item.Length -lt 50MB) {
        Write-Log '    Not a valid installer (block page?). Skipping.' -Level ERROR
        Remove-Item $dest -Force -ErrorAction SilentlyContinue
        return $false
    }
    $bundleLog = Join-Path $LogDir ('dotnet_sdk_bundle_' + $Major + '_' + $Arch + '.log')
    $p = Start-Process $dest -ArgumentList ('/install /quiet /norestart /log "' + $bundleLog + '"') -Wait -PassThru
    Write-Log ('    Installer exit: ' + $p.ExitCode)
    Remove-Item $dest -Force -ErrorAction SilentlyContinue
    if ($p.ExitCode -eq 3010) { $script:Reboot = $true; return $true }
    if ($p.ExitCode -ne 0) {
        Write-Log '    SDK install failed.' -Level ERROR
        Write-Log ('    Bundle log: ' + $bundleLog) -Level ERROR
        return $false
    }
    return $true
}

function Get-DotNetSdks {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $out = @()
    Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue |
      Where-Object { $_.DisplayName -match '^Microsoft \.NET SDK' } | ForEach-Object {
        $out += $_.DisplayName
    }
    return ($out | Sort-Object -Unique)
}

function Test-PendingReboot {
    $reasons = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
        $reasons += 'Component Based Servicing: RebootPending'
    }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
        $reasons += 'Windows Update: RebootRequired'
    }
    $pfro = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
    if ($pfro) { $reasons += ('PendingFileRenameOperations: ' + $pfro.Count + ' entries') }
    return $reasons
}

function Get-ArpRuntimeMajors {
    # Majors registered in ARP, regardless of whether any payload exists on disk.
    # Returns major -> list of ARP entries.
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $map = @{}
    Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue | Where-Object {
        $_.DisplayName -match '^Microsoft (\.NET|ASP\.NET Core|Windows Desktop) Runtime'
    } | ForEach-Object {
        if ($_.DisplayName -match '(\d+)\.(\d+)\.(\d+)') {
            $maj = [int]$matches[1]
            if (-not $map.ContainsKey($maj)) { $map[$maj] = @() }
            $map[$maj] += $_
        }
    }
    return $map
}

function ConvertTo-SdkEntryInfo {
    # Parses 'Microsoft .NET SDK 8.0.420 (x86)'. Major must be captured before
    # the arch -match, which replaces $matches.
    param([string]$DisplayName)
    if ($DisplayName -notmatch '^Microsoft \.NET SDK\s+(\d+)\.(\d+)\.(\d+)') { return $null }
    $major = [int]$matches[1]
    $ver = [version]($matches[1] + '.' + $matches[2] + '.' + $matches[3])
    $arch = 'x64'
    if ($DisplayName -match '\(x86\)') { $arch = 'x86' }
    elseif ($DisplayName -match '\(arm64\)') { $arch = 'arm64' }
    return [pscustomobject]@{ Version = $ver; Major = $major; Arch = $arch }
}

function Get-DotNetSdkEntries {
    # Full ARP entries for .NET SDKs, with parsed version and architecture.
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $out = @()
    Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue | ForEach-Object {
        $info = ConvertTo-SdkEntryInfo -DisplayName $_.DisplayName
        if ($info) {
            $out += [pscustomobject]@{
                Name = $_.DisplayName; Version = $info.Version; Major = $info.Major
                Arch = $info.Arch; Entry = $_
            }
        }
    }
    return $out
}

function Get-GlobalJsonSdkPins {
    # A global.json can pin an exact SDK version; removing it breaks the build.
    # Searched shallowly in user profiles and the usual source roots -- a full
    # C: scan would be far too slow to run on every deployment.
    $roots = @('C:\dev','C:\src','C:\Projects','C:\repos')
    Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        foreach ($sub in @('source','source\repos','repos','Documents','Desktop','Projects','git')) {
            $p = Join-Path $_.FullName $sub
            if (Test-Path $p) { $roots += $p }
        }
    }
    $pins = @()
    foreach ($r in ($roots | Sort-Object -Unique)) {
        Get-ChildItem -Path $r -Filter 'global.json' -Recurse -Depth 4 -File -ErrorAction SilentlyContinue |
          ForEach-Object {
            try {
                $j = Get-Content $_.FullName -Raw -ErrorAction Stop | ConvertFrom-Json
                if ($j.sdk -and $j.sdk.version) {
                    $pins += [pscustomobject]@{
                        File = $_.FullName
                        Version = ('' + $j.sdk.version)
                        RollForward = ('' + $j.sdk.rollForward)
                    }
                }
            } catch { }
        }
    }
    return $pins
}

function Get-HostingBundles {
    # ARP entries for the ASP.NET Core Hosting Bundle, e.g.
    #   'Microsoft .NET 8.0.27 - Windows Server Hosting'
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $out = @()
    Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue |
      Where-Object { $_.DisplayName -match 'Windows Server Hosting' } | ForEach-Object {
        if ($_.DisplayName -match '(\d+)\.(\d+)\.(\d+)') {
            $out += [pscustomobject]@{
                Name    = $_.DisplayName
                Version = [version]($matches[1] + '.' + $matches[2] + '.' + $matches[3])
                Major   = [int]$matches[1]
                Entry   = $_
            }
        }
    }
    return $out
}

function Test-VersionHeldByDependency {
    # Does any WiX dependency provider for this version still have a live
    # dependent product? If so the framework folder must NOT be deleted.
    param([string]$Version)
    $depRoot = 'HKLM:\SOFTWARE\Classes\Installer\Dependencies'
    $verEsc  = [regex]::Escape($Version)
    $holders = @()
    Get-ChildItem $depRoot -ErrorAction SilentlyContinue |
      Where-Object { $_.PSChildName -match $verEsc } | ForEach-Object {
        $depPath = Join-Path $_.PSPath 'Dependents'
        if (-not (Test-Path $depPath)) { return }
        Get-ChildItem $depPath -ErrorAction SilentlyContinue | ForEach-Object {
            $g = $_.PSChildName
            foreach ($hive in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\',
                                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\')) {
                $prop = Get-ItemProperty ($hive + $g) -ErrorAction SilentlyContinue
                if ($prop -and $prop.DisplayName) { $holders += $prop.DisplayName; break }
            }
        }
    }
    return ($holders | Sort-Object -Unique)
}

function Install-HostingBundle {
    # Architecture-neutral single installer; URL shape differs from the runtimes.
    param([int]$Major)
    $url  = 'https://aka.ms/dotnet/' + $Major + '.0/dotnet-hosting-win.exe'
    $dest = Join-Path $TempDir ('dotnet-hosting-' + $Major + '-win.exe')
    Write-Log ('  [Hosting Bundle ' + $Major + '.0] ' + $url)
    if ($DryRun) { Write-Log '    [DRYRUN] Would download + install.'; return $true }
    if (-not (Save-Installer -Url $url -Dest $dest)) { return $false }
    $item = Get-Item $dest
    $fs = [System.IO.File]::OpenRead($dest)
    $b1 = $fs.ReadByte(); $b2 = $fs.ReadByte()
    $fs.Close(); $fs.Dispose()
    $isMZ = ($b1 -eq 0x4D -and $b2 -eq 0x5A)
    Write-Log ('    Downloaded ' + [math]::Round($item.Length/1MB,1) + ' MB, MZ header: ' + $isMZ)
    if (-not $isMZ -or $item.Length -lt 5MB) {
        Write-Log '    Not a valid installer (block page?). Skipping.' -Level ERROR
        Remove-Item $dest -Force -ErrorAction SilentlyContinue
        return $false
    }
    $p = Start-Process $dest -ArgumentList '/install /quiet /norestart' -Wait -PassThru
    Write-Log ('    Installer exit: ' + $p.ExitCode)
    Remove-Item $dest -Force -ErrorAction SilentlyContinue
    if ($p.ExitCode -eq 3010) { $script:Reboot = $true; return $true }
    if ($p.ExitCode -ne 0) { Write-Log '    Hosting bundle install failed.' -Level ERROR; return $false }
    return $true
}

# Map an ARP DisplayName prefix (e.g. "Microsoft .NET Runtime", "Microsoft
# Windows Desktop Runtime") to the internal flavor key used in $before/$after
# (e.g. "Microsoft.NETCore.App"), so Phase 2 can check whether a group's
# (flavor, arch, major) has ANY on-disk payload at all -- finer-grained than
# Phase 1d's whole-major ARP-only check, which misses a flavor+arch that has
# zero payload for a major while a DIFFERENT flavor/arch of that same major
# is genuinely installed (see v3.1 notes above).
function Get-FlavorKeyForArpPrefix {
    param([string]$Prefix)
    if ($Prefix -match 'ASP\.NET Core')   { return 'Microsoft.AspNetCore.App' }
    if ($Prefix -match 'Windows Desktop') { return 'Microsoft.WindowsDesktop.App' }
    if ($Prefix -match '\.NET Runtime')   { return 'Microsoft.NETCore.App' }
    return $null
}

# Is this exact ARP version present on disk for its flavor/arch? An
# unrecognised flavor counts as present so it is never hard-removed.
function Test-ArpVersionOnDisk {
    param($DiskMap, [string]$Prefix, [string]$Arch, [version]$Version)
    $flavorKey = Get-FlavorKeyForArpPrefix -Prefix $Prefix
    if (-not $flavorKey) { return $true }
    $diskKey = $Arch + '|' + $flavorKey
    if (-not $DiskMap.ContainsKey($diskKey)) { return $false }
    return [bool]($DiskMap[$diskKey] | Where-Object { $_ -eq $Version })
}

function Invoke-Msi {
    # Full path + -NoNewWindow: a bare 'msiexec.exe' goes through ShellExecute
    # under EC SYSTEM and fails. 1618/1601 = installer busy, retry.
    param([string]$Arguments, [int]$Retries = 4)
    $msiexec = 'msiexec.exe'
    if ($env:SystemRoot) {
        $full = Join-Path $env:SystemRoot 'System32\msiexec.exe'
        if (Test-Path $full) { $msiexec = $full }
    }
    $attempt = 0
    while ($true) {
        $attempt++
        $p = Start-Process -FilePath $msiexec -ArgumentList $Arguments -Wait -PassThru -NoNewWindow
        $code = $p.ExitCode
        if ($code -ne 1618 -and $code -ne 1601) { return $code }
        if ($attempt -ge $Retries) {
            Write-Log ('    Still ' + $code + ' after ' + $attempt + ' attempts.') -Level ERROR
            return $code
        }
        $wait = 30 * $attempt
        Write-Log ('    ' + $code + ' = installer busy. Waiting ' + $wait + 's, retry ' + $attempt + '/' + $Retries + '...') -Level WARN
        Start-Sleep -Seconds $wait
    }
}

# Known non-zero uninstaller/msiexec exit codes worth naming explicitly,
# because "the ARP entry survived" has more than one root cause and the
# wrong one sends the operator looking for a holder that does not exist.
$script:KnownUninstallErrors = @{
    1605 = 'ERROR_UNKNOWN_PRODUCT -- Windows Installer has no record of this product code'
    1612 = 'ERROR_INSTALL_SOURCE_ABSENT -- the bundle cannot find its own cached uninstall payload (Package Cache entry for this exact version is gone; the ARP registration outlived it)'
    1618 = 'ERROR_INSTALL_ALREADY_RUNNING -- another install/uninstall was in progress'
    1619 = 'ERROR_INSTALL_PACKAGE_OPEN_FAILED -- the install package could not be opened'
    1620 = 'ERROR_INSTALL_PACKAGE_INVALID -- the install package is invalid'
}

# Uninstall one ARP runtime entry and verify it. v3.2: diagnoses failures by
# ACTUAL exit code instead of always blaming "exit-0 dependents" -- CSPC-004
# (2026-08-31) got exit 1612 (ERROR_INSTALL_SOURCE_ABSENT, a genuine failure,
# not a silent no-op) and the log still printed the exit-0/dependents theory
# verbatim, then pointed at a "dependency diagnostics" section that Phase 2's
# orphaned-group path never populates. Now the holder lookup runs inline,
# right here, for whatever version actually failed, so the log either shows
# the real holder or honestly says none exists.
# Shared by both failure paths in Invoke-ArpEntryRemoval below: a normal
# uninstall that ran but left the entry in place, AND (v3.4) an uninstall
# command that could not even be LAUNCHED. CSLT-020 (2026-09-02): the
# orphaned entry's QuietUninstallString pointed at a cached bootstrapper
# .exe that no longer existed on disk -- Start-Process itself threw "The
# system cannot find the file specified" before any exit code existed to
# diagnose. Unsurprising for an entry with zero on-disk PAYLOAD anywhere:
# its own cached installer copy (Package Cache) was gone too. That failure
# used to hit the generic catch block and stop there, never reaching the
# hard-removal fallback at all, regardless of -AllowHardRemoval.
function Invoke-ArpHardRemoval {
    param($Entry)
    Write-Log '    -RemoveOrphanedRegistrations, no dependency holder, and no on-disk' -Level WARN
    Write-Log '    payload for this version: stripping the ARP entry' -Level WARN
    Write-Log '    directly (registry-only; there is nothing left for it to reference).' -Level WARN
    try {
        Remove-Item -Path $Entry.PSPath -Recurse -Force -ErrorAction Stop
        Start-Sleep -Seconds 1
        $stillThere = Get-ItemProperty -Path $arpPaths -ErrorAction SilentlyContinue |
                      Where-Object { $_.PSChildName -eq $Entry.PSChildName }
        if (-not $stillThere) {
            Write-Log '    Hard removal succeeded -- orphaned entry cleared.'
            return $true
        }
        Write-Log '    Hard removal did not stick either. Leaving it; escalate manually.' -Level ERROR
        return $false
    } catch {
        Write-Log ('    Hard removal failed: ' + $_) -Level ERROR
        return $false
    }
}

function Invoke-ArpEntryRemoval {
    param($Entry, [string]$Version, [switch]$AllowHardRemoval)
    if ($DryRun) { Write-Log '    [DRYRUN] Would uninstall.'; return $false }
    try {
        if ($Entry.QuietUninstallString) {
            $cmd   = $Entry.QuietUninstallString
            $exeQ  = ($cmd -split '"')[1]
            $argsQ = ($cmd.Substring($cmd.IndexOf($exeQ) + $exeQ.Length + 1)).Trim()
            $u = Start-Process $exeQ -ArgumentList $argsQ -Wait -PassThru
        } elseif ($Entry.PSChildName -match '^\{[0-9A-Fa-f-]+\}$') {
            $u = @{ ExitCode = (Invoke-Msi ('/x ' + $Entry.PSChildName + ' /qn /norestart')) }
        } else {
            Write-Log '    No usable uninstall string.' -Level WARN
            return $false
        }
        $exitCode = $u.ExitCode
        Write-Log ('    Uninstall exit: ' + $exitCode)
        if ($exitCode -eq 3010) { $script:Reboot = $true }
        # v2.7: exit 0 is NOT proof of removal. A WiX bundle with registered
        # dependents skips its uninstall and reports success.
        Start-Sleep -Seconds 1
        $stillThere = Get-ItemProperty -Path $arpPaths -ErrorAction SilentlyContinue |
                      Where-Object { $_.PSChildName -eq $Entry.PSChildName }
        if (-not $stillThere) { return $true }

        $holders = @()
        if ($Version) { $holders = Test-VersionHeldByDependency -Version $Version }

        if ($exitCode -eq 0) {
            Write-Log '    NOT ACTUALLY REMOVED -- the ARP entry survived an exit-0 uninstall.' -Level WARN
            if ($holders.Count -gt 0) {
                Write-Log '    A bundle with registered dependents skips uninstall and returns' -Level WARN
                Write-Log '    success. Holder(s):' -Level WARN
                foreach ($h in $holders) { Write-Log ('      ' + $h) -Level WARN }
            } else {
                Write-Log '    No WiX dependency holder found for this version either -- the' -Level WARN
                Write-Log '    exit-0 no-op has an unidentified cause. Inspect the ARP entry by hand.' -Level WARN
            }
        } else {
            Write-Log ('    UNINSTALL FAILED -- exit ' + $exitCode + ' is a genuine error, not a silent no-op.') -Level WARN
            if ($script:KnownUninstallErrors.ContainsKey($exitCode)) {
                Write-Log ('    ' + $script:KnownUninstallErrors[$exitCode] + '.') -Level WARN
            }
            if ($holders.Count -gt 0) {
                Write-Log '    WiX dependency holder(s) also found (deal with these too):' -Level WARN
                foreach ($h in $holders) { Write-Log ('      ' + $h) -Level WARN }
            } else {
                Write-Log '    No WiX dependency holder found -- the "registered dependents" theory' -Level WARN
                Write-Log '    does not apply here.' -Level WARN
            }
        }

        if ($AllowHardRemoval -and $holders.Count -eq 0) {
            if (Invoke-ArpHardRemoval -Entry $Entry) { return $true }
        }

        Write-Log '    Re-running this script will not help until the above is resolved.' -Level WARN
        $script:UninstallNoOp = $true
        return $false
    } catch {
        # v3.4: this used to be a dead end regardless of -AllowHardRemoval --
        # the exception means the uninstall command never even ran, so there
        # is no exit code and $stillThere was never checked. The entry is
        # necessarily still present (nothing removed it), so the same
        # holder-check + hard-removal path applies.
        Write-Log ('    Uninstall error: ' + $_) -Level WARN
        if ($_.ToString() -match 'cannot find the file specified|CannotFindPath') {
            Write-Log '    The uninstall command itself does not exist on disk (its cached' -Level WARN
            Write-Log '    Package Cache copy is gone) -- this cannot be run through Windows' -Level WARN
            Write-Log '    Installer at all; the "registered dependents" theory does not apply.' -Level WARN
        } else {
            Write-Log '    If folders persist after exit 0: MSI reference counting --' -Level WARN
            Write-Log '    see HKLM:\SOFTWARE\Classes\Installer\Dependencies.' -Level WARN
        }

        $holders = @()
        if ($Version) { $holders = Test-VersionHeldByDependency -Version $Version }
        if ($holders.Count -gt 0) {
            Write-Log '    WiX dependency holder(s) found (deal with these too):' -Level WARN
            foreach ($h in $holders) { Write-Log ('      ' + $h) -Level WARN }
        }

        if ($AllowHardRemoval -and $holders.Count -eq 0) {
            if (Invoke-ArpHardRemoval -Entry $Entry) { return $true }
        }

        $script:UninstallNoOp = $true
        return $false
    }
}

function Find-RuntimeConfigPins {
    # <app>.runtimeconfig.json files whose app needs .NET $Major (see
    # Test-RuntimeConfigNeedsMajor). The dotnet roots are skipped: the SDK's
    # own tools there go with the SDK.
    param([int]$Major)
    $roots = @('C:\Program Files', 'C:\Program Files (x86)', 'C:\ProgramData', 'C:\inetpub')
    foreach ($u in @(Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
        foreach ($sub in @('AppData\Local', 'AppData\Roaming', '.dotnet\tools')) {
            $p = $u.FullName + '\' + $sub
            if (Test-Path -LiteralPath $p) { $roots += $p }
        }
    }
    $skip = '(?i)^C:\\Program Files( \(x86\))?\\dotnet\\|^C:\\ProgramData\\Package Cache\\'
    $hits = @()
    foreach ($r in $roots) {
        if (-not (Test-Path -LiteralPath $r)) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $r -Filter '*.runtimeconfig.json' -Recurse -Depth 8 -File -ErrorAction SilentlyContinue)) {
            if ($f.FullName -match $skip) { continue }
            $text = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction SilentlyContinue
            if (Test-RuntimeConfigNeedsMajor -Json $text -Major $Major) { $hits += $f.FullName }
        }
    }
    return $hits
}

function Find-RemoverScript {
    foreach ($d in @($PSScriptRoot, 'C:\')) {
        if (-not $d) { continue }
        $p = $d.TrimEnd('\') + '\Remove-DotNetEolChannel.ps1'
        if (Test-Path -LiteralPath $p) { return $p }
    }
    return $null
}

$Reboot = $false
$Failed = $false
$NeedsHuman = $false
$RetiredRemoved = @()
$UninstallNoOp = $false
# (arch|flavor, major) pairs successfully installed by Phase 1a, so Phase 3
# can verify they are still on disk at the end of the run (v3.6).
$SuccessorInstalled = @()

# EOL status by major, as of July 2026. Update when channels change:
#   8  = LTS, supported until Nov 2026
#   9  = STS, END OF SUPPORT May 2026
#   10 = LTS, current
$EolMajors       = @(9)          # explicitly EOL
$MinSupported    = 8             # anything below this is long-dead
$EolSeen         = @()
# End-of-support dates for majors still supported. Update as Microsoft publishes.
#   8  = LTS, ends 2026-11-10
#   10 = LTS, ends 2028-11-14
$EolDates        = @{ 8 = '2026-11-10'; 10 = '2028-11-14' }
$EolWarnDays     = 180
$EolSoonSeen     = @()

# -InstallSuccessorMajor mapping: EOL or near-EOL major -> the next major to
# stage alongside it. Microsoft alternates yearly LTS (even)/STS (odd)
# releases, so the natural migration target is the next LTS. Add an entry
# here (not a "+1" formula) so a mapping is a deliberate, reviewed decision
# rather than an assumption baked into the math.
$EolSuccessorMajor = @{ 8 = 10; 9 = 10 }

# Unit tests dot-source this file for the helpers above; stop before the run.
if ($env:UPDATE_DOTNET_DOTSOURCE -eq '1') { return }

# Set when dotnet.exe cannot load hostfxr.dll, so inventory came from disk
# instead of the muxer and cannot be trusted for install decisions.
$script:MuxerBroken      = $false
$script:MuxerBrokenRoots = @()
$script:MuxerFailures    = @()

Write-Log '=============================================='
Write-Log ' .NET Runtime Update (v3.13) -- 302122/307353/314679/320854/326863/+.NETCore-family'
Write-Log (' Host   : ' + $env:COMPUTERNAME)
# Echo EVERY switch, so a log proves which arguments actually arrived. Endpoint
# Central has a history in this environment of altering argument strings, and a
# silently-dropped switch is indistinguishable from a switch that did nothing.
Write-Log ' Switches received:'
Write-Log ('   -DryRun                      : ' + $DryRun)
Write-Log ('   -RemoveStaleFolders          : ' + $RemoveStaleFolders)
Write-Log ('   -AbortOnPendingReboot        : ' + $AbortOnPendingReboot)
Write-Log ('   -RemoveSupersededSdks        : ' + $RemoveSupersededSdks)
Write-Log ('   -RemoveOrphanedRegistrations : ' + $RemoveOrphanedRegistrations)
Write-Log ('   -InstallSuccessorMajor       : ' + $InstallSuccessorMajor + $(if ($RemoveRetiredMajor) { '  (implied by -RemoveRetiredMajor)' } else { '' }))
Write-Log ('   -RemoveRetiredMajor          : ' + $RemoveRetiredMajor)
Write-Log ('   -RepairBrokenHost            : ' + $RepairBrokenHost)
if ($MyInvocation.Line) {
    Write-Log (' Invoked as: ' + $MyInvocation.Line.Trim())
}
Write-Log '=============================================='

$roots = @(
    @{ Arch = 'x64'; Exe = 'C:\Program Files\dotnet\dotnet.exe' },
    @{ Arch = 'x86'; Exe = 'C:\Program Files (x86)\dotnet\dotnet.exe' }
)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# v3.2: hoisted above Phase 1d. It previously was not assigned until right
# before Phase 2, so Phase 1d's own removal-verification (`Get-ItemProperty
# -Path $arpPaths`) ran against $null and silently reported every hard
# removal as successful regardless of what actually happened. Never observed
# in a log because Phase 1d has had zero whole-major orphans to remove so
# far, but it was live and would have masked a real failure the first time
# one occurred.
$arpPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

# ------------------------------------------------------------------
# Phase 0: record the starting state
# ------------------------------------------------------------------
# v2.6: a pending reboot is a leading cause of 1603 on bundle installs.
$rebootReasons = Test-PendingReboot
if ($rebootReasons.Count -gt 0) {
    Write-Log ''
    Write-Log '*** PENDING REBOOT DETECTED -- installs may fail with 1603 ***' -Level WARN
    foreach ($rr in $rebootReasons) { Write-Log ('***   ' + $rr) -Level WARN }
    if ($AbortOnPendingReboot) {
        Write-Log '*** -AbortOnPendingReboot set: stopping now. Reboot and re-run.' -Level WARN
        Write-Log '=============================================='
        exit 3010
    }
    Write-Log '*** Reboot first for the most reliable result. Continuing anyway.' -Level WARN
    Write-Log '*** (Pass -AbortOnPendingReboot to stop here instead. Repeated runs on a' -Level WARN
    Write-Log '*** host with queued renames add more of them and achieve nothing.)' -Level WARN
}

$before = Get-InstalledMap $roots

$hostRepairTried = $false
if ($script:MuxerBroken -and $RepairBrokenHost) {
    Write-Log ''
    Write-Log '=== Repairing the broken .NET host (-RepairBrokenHost) ==='
    $hostRepairTried = $true
    $currentMajor = [int](($EolDates.Keys | Measure-Object -Maximum).Maximum)
    Repair-BrokenHostRoots -Roots ($roots | Where-Object { $script:MuxerBrokenRoots -contains $_.Arch }) `
        -PendingRenames (Get-PendingFileRenames) -FallbackMajor $currentMajor
    $script:MuxerBroken      = $false
    $script:MuxerBrokenRoots = @()
    $script:MuxerFailures    = @()
    $before = Get-InstalledMap $roots
    if (-not $script:MuxerBroken) {
        Write-Log '  Host repaired: dotnet --list-runtimes works again. Continuing the normal run.'
    }
}

if ($script:MuxerBroken) {
    Write-Log ''
    if ($hostRepairTried) {
        Write-Log '*** -RepairBrokenHost did not restore the host (see the repair section above).' -Level ERROR
    }
    Write-Log '*** BROKEN .NET HOST -- STOPPING ***' -Level ERROR
    Write-Log ('*** Affected root(s): ' + ($script:MuxerBrokenRoots -join ', ')) -Level ERROR
    Write-Log '*** dotnet.exe resolves the HIGHEST host\fxr\<version> folder and loads' -Level ERROR
    if ($script:MuxerFailures -contains 'MissingFolder') {
        Write-Log '*** hostfxr.dll from it. Here the host\fxr folder itself is gone, so' -Level ERROR
    } else {
        Write-Log '*** hostfxr.dll from it. That folder exists here but the DLL does not, so' -Level ERROR
    }
    Write-Log '*** the muxer is broken for EVERY installed major -- not just that one.' -Level ERROR
    Write-Log '*** The on-disk list above came from shared\ payload folders, not from the' -Level ERROR
    Write-Log '*** muxer, so it is not safe to base install/removal decisions on it.' -Level ERROR
    Write-Log '***' -Level ERROR
    Write-Log '*** Fix, in order:' -Level ERROR
    Write-Log '***   1. Reboot. A queued PendingFileRenameOperations entry replacing a' -Level ERROR
    Write-Log '***      locked hostfxr.dll only completes at boot; this often resolves it.' -Level ERROR
    if ($script:MuxerFailures -contains 'MissingFolder') {
        Write-Log '***   2. If it persists, repair the NEWEST runtime in the on-disk list' -Level ERROR
        Write-Log '***      (Apps > Installed apps > Microsoft .NET Runtime > Modify > Repair, or' -Level ERROR
        Write-Log '***      its installer with /repair /quiet). That writes host\fxr\<version>.' -Level ERROR
        Write-Log '***      If shared\ holds no runtimes at all, dotnet.exe is a leftover:' -Level ERROR
        Write-Log '***      install any current .NET runtime, which brings its own host.' -Level ERROR
    } else {
        Write-Log '***   2. If it persists, reinstall the runtime for the version named above' -Level ERROR
        Write-Log '***      (its installer restores host\fxr\<version>\hostfxr.dll).' -Level ERROR
    }
    Write-Log '***   3. Re-run this script only after dotnet --list-runtimes works.' -Level ERROR
    if (-not $hostRepairTried) {
        Write-Log '*** Or re-run with -RepairBrokenHost to let this script do step 2.' -Level ERROR
    }
    if ($script:MuxerFailures -contains 'MissingDll') {
        Write-Log '*** Do NOT delete the empty host\fxr folder as a workaround unless a HIGHER' -Level ERROR
        Write-Log '*** version folder with a valid hostfxr.dll remains.' -Level ERROR
    }
    Write-Log '=============================================='
    exit 1
}

Write-Log ''
Write-Log '=== Starting state ==='
foreach ($key in ($before.Keys | Sort-Object)) {
    Write-Log ('  ' + $key + ' : ' + (($before[$key] | Sort-Object) -join ', '))
    $majorsHere = $before[$key] | ForEach-Object { $_.Major } | Sort-Object -Unique
    foreach ($m in $majorsHere) {
        $status = Get-MajorSupportStatus -Major $m -EolMajors $EolMajors -MinSupported $MinSupported -EolDates $EolDates -WarnDays $EolWarnDays -Now (Get-Date)
        if ($status -eq 'EOL' -and $script:EolSeen -notcontains $m) { $script:EolSeen += $m }
        if ($status -eq 'SOON' -and $script:EolSoonSeen -notcontains $m) { $script:EolSoonSeen += $m }
    }
}
$sdks = Get-DotNetSdks
if ($sdks.Count -gt 0) {
    Write-Log ''
    Write-Log '  Installed .NET SDKs (each PINS the framework it shipped with):'
    foreach ($s in $sdks) { Write-Log ('    ' + $s) }
    if ($sdks.Count -gt 1) {
        Write-Log '  More than one SDK present -- superseded SDKs will block removal of' -Level WARN
        Write-Log '  their frameworks. Consolidating to one current SDK is what clears it.' -Level WARN
    }
}

# --- ARP census: catch majors registered but with no payload on disk ---------
$arpMajors  = Get-ArpRuntimeMajors
$diskMajors = @()
foreach ($key in $before.Keys) {
    foreach ($m in ($before[$key] | ForEach-Object { $_.Major })) {
        if ($diskMajors -notcontains $m) { $diskMajors += $m }
    }
}
$OrphanMajors = @()
if ($arpMajors.Keys.Count -gt 0) {
    Write-Log ''
    Write-Log '  Major-version census (runtime folders vs ARP registrations):'
    foreach ($m in (($arpMajors.Keys + $diskMajors) | Sort-Object -Unique)) {
        $onDisk = ($diskMajors -contains $m)
        $inArp  = $arpMajors.ContainsKey([int]$m)
        if ($onDisk -and $inArp)      { Write-Log ('    .NET ' + $m + ' : on disk + registered') }
        elseif ($onDisk)              { Write-Log ('    .NET ' + $m + ' : on disk, NOT registered in ARP') -Level WARN }
        else {
            Write-Log ('    .NET ' + $m + ' : ARP-ONLY -- registered with NO runtime payload on disk') -Level WARN
            foreach ($e in $arpMajors[[int]$m]) { Write-Log ('        ' + $e.DisplayName) -Level WARN }
            $OrphanMajors += $m
        }
    }
    if ($OrphanMajors.Count -gt 0) {
        Write-Log '    ARP-only majors are invisible to dotnet --list-runtimes, so they were' -Level WARN
        Write-Log '    previously skipped entirely by this script. At least the "Security' -Level WARN
        Write-Log '    Update for Microsoft .NET Core" Tenable plugin family reads the ARP' -Level WARN
        Write-Log '    DisplayVersion directly (CSLT-020, 2026-09-02: 9 open findings all' -Level WARN
        Write-Log '    pointed at one dead 6.0.18 orphan) -- leaving this in place can keep' -Level WARN
        Write-Log '    real findings open no matter how current the actual runtime is.' -Level WARN
        if (-not $RemoveOrphanedRegistrations) {
            Write-Log '    Re-run with -RemoveOrphanedRegistrations to uninstall them.' -Level WARN
        }
    }
}

# --- redundancy: how many patch versions per major, and how many are dead weight
$redundantTotal = 0
$majorCounts = @{}
foreach ($key in $before.Keys) {
    foreach ($v in $before[$key]) {
        $mk = ($key + '|' + $v.Major)
        if (-not $majorCounts.ContainsKey($mk)) { $majorCounts[$mk] = @() }
        $majorCounts[$mk] += $v
    }
}
$redundantLines = @()
foreach ($mk in ($majorCounts.Keys | Sort-Object)) {
    $vs = @($majorCounts[$mk] | Sort-Object -Unique)
    if ($vs.Count -le 1) { continue }
    $newest = ($vs | Sort-Object -Descending)[0]
    $dead = @($vs | Where-Object { $_ -ne $newest })
    $redundantTotal += $dead.Count
    $parts = $mk -split '\|'
    $redundantLines += ('    ' + $parts[0] + ' [' + $parts[1] + '.x] : ' + $vs.Count +
                        ' versions installed, ' + $dead.Count + ' redundant (' +
                        (($dead | Sort-Object) -join ', ') + ' superseded by ' + $newest + ')')
}
if ($redundantTotal -gt 0) {
    Write-Log ''
    Write-Log ('  REDUNDANT PATCH VERSIONS: ' + $redundantTotal + ' installed version(s) serve no purpose.') -Level WARN
    foreach ($l in $redundantLines) { Write-Log $l -Level WARN }
    Write-Log '  .NET rolls forward: an app targeting net<major>.0 binds to the HIGHEST' -Level WARN
    Write-Log '  patch present, so older patches are dead weight that generate a finding' -Level WARN
    Write-Log '  per monthly advisory. Note EC MS26-DOTNET patches install WITHOUT' -Level WARN
    Write-Log '  removing, which is why these accumulate; this script is what prunes them.' -Level WARN
}

# --- majors approaching end of support
if ($EolSoonSeen.Count -gt 0) {
    Write-Log ''
    foreach ($m in ($EolSoonSeen | Sort-Object)) {
        $eol = [datetime]$EolDates[[int]$m]
        $days = [math]::Round(($eol - (Get-Date)).TotalDays)
        Write-Log ('*** .NET ' + $m + ' REACHES END OF SUPPORT ' + $eol.ToString('yyyy-MM-dd') +
                   ' -- ' + $days + ' days away ***') -Level WARN
    }
    Write-Log '*** After that date this major generates SEoL findings that patching cannot' -Level WARN
    Write-Log '*** clear -- only removing the channel will. If an SDK or app pins it, start' -Level WARN
    Write-Log '*** the retargeting conversation with the owner NOW rather than in arrears.' -Level WARN
}

if ($EolSeen.Count -gt 0) {
    Write-Log ''
    Write-Log ('*** EOL CHANNEL(S) DETECTED: .NET ' + (($EolSeen | Sort-Object) -join ', .NET ') + ' ***') -Level WARN
    Write-Log '*** These majors are past end-of-support. This script will patch them' -Level WARN
    Write-Log '*** to their FINAL build (clears vulnerable-version findings), but' -Level WARN
    Write-Log '*** SEoL findings only clear by REMOVING the channel. Do NOT remove' -Level WARN
    Write-Log '*** without first checking which apps depend on it -- apps pin to' -Level WARN
    Write-Log '*** their major and will break. Flag this host for migration review.' -Level WARN
    Write-Log '*** Removal is Remove-DotNetEolChannel.ps1 (plugin 172179), not this' -Level WARN
    Write-Log '*** script -- EC software-inventory uninstall of a .NET bundle fails' -Level WARN
    Write-Log '*** under SYSTEM (bare msiexec.exe) and the bundle no-ops while it' -Level WARN
    Write-Log '*** still has child-MSI dependents. That script handles both.' -Level WARN
}

# ------------------------------------------------------------------
# Phase 1: install latest patch of every installed flavor/major/arch
# ------------------------------------------------------------------
Write-Log ''
Write-Log '=== Phase 1: installing latest patches ==='
foreach ($key in $before.Keys) {
    $arch   = ($key -split '\|')[0]
    $flavor = ($key -split '\|')[1]
    $majors = $before[$key] | ForEach-Object { $_.Major } | Sort-Object -Unique
    foreach ($major in $majors) {
        if (-not (Install-Runtime -Flavor $flavor -Major $major -Arch $arch)) { $Failed = $true }
    }
}

# ------------------------------------------------------------------
# Phase 1a: EOL successor major (opt-in, PURELY ADDITIVE)
# ------------------------------------------------------------------
# Installs the mapped successor major (see $EolSuccessorMajor) for every
# flavor/arch that has an EOL major installed. Never touches, patches
# differently, or removes the EOL major itself -- this only ever adds a
# runtime that was not there before. It does NOT retarget any app: .NET's
# default roll-forward policy does not cross major versions, so an app
# targeting net9.0 keeps requiring .NET 9 until it is recompiled against
# net10.0 or its runtimeconfig.json sets "rollForward": "LatestMajor". The
# point is to pre-stage the runtime an app owner needs the moment they
# retarget, so migration does not need a second EC deployment round.
Write-Log ''
Write-Log '=== Phase 1a: EOL successor major (opt-in, additive only) ==='
$retiring = @(@($EolSeen) + @($EolSoonSeen) | Sort-Object -Unique)
if ($retiring.Count -eq 0) {
    Write-Log '  No EOL or near-EOL majors present -- nothing to do.'
} elseif (-not $InstallSuccessorMajor) {
    Write-Log ('  EOL or near-EOL major(s) present (.NET ' + ($retiring -join ', .NET ') + ') -- not') -Level WARN
    Write-Log '  installing a successor (pass -InstallSuccessorMajor). This only adds a' -Level WARN
    Write-Log '  runtime side by side; it never removes or retargets anything on its own.' -Level WARN
} else {
    $targets = @(Get-SuccessorTargets -EolSeen $EolSeen -EolSoonSeen $EolSoonSeen -Map $EolSuccessorMajor)
    foreach ($m in $retiring) {
        if (-not $EolSuccessorMajor.ContainsKey([int]$m)) {
            Write-Log ('  .NET ' + $m + ' has no configured successor in $EolSuccessorMajor -- skipping.') -Level WARN
        }
    }
    $staged = @()
    foreach ($target in $targets) {
        $eolMajor  = $target.From
        $successor = $target.To
        Write-Log ('  .NET ' + $eolMajor + ' -> staging .NET ' + $successor + ' alongside it (NOT removing .NET ' + $eolMajor + '):')
        foreach ($key in $before.Keys) {
            $arch        = ($key -split '\|')[0]
            $flavor      = ($key -split '\|')[1]
            $hasEolMajor = [bool]($before[$key] | Where-Object { $_.Major -eq $eolMajor })
            if (-not $hasEolMajor) { continue }
            if ($staged -contains ($key + '|' + $successor)) { continue }
            $staged += ($key + '|' + $successor)
            if (Install-Runtime -Flavor $flavor -Major $successor -Arch $arch) {
                # v3.6: recorded so Phase 3 can prove it SURVIVED the run.
                # Phase 3's own checklist is built from $before, which can
                # never contain a major Phase 1a just added, so without this
                # a successor major that gets removed later in the same run
                # passes verification silently (CSLT-020).
                $SuccessorInstalled += @{ Key = $key; Major = $successor }
            } else {
                $Failed = $true
            }
        }
        if (-not ($SuccessorInstalled | Where-Object { $_.Major -eq $successor })) {
            Write-Log ('  .NET ' + $successor + ' was NOT staged -- every install above failed.') -Level ERROR
            continue
        }
        Write-Log ('  .NET ' + $successor + ' is now present alongside .NET ' + $eolMajor + '. Apps still') -Level WARN
        Write-Log ('  targeting net' + $eolMajor + '.0 are UNAFFECTED and keep running on .NET ' + $eolMajor + ' --') -Level WARN
        Write-Log '  retargeting (recompile against the new TFM, or set "rollForward":' -Level WARN
        Write-Log '  "LatestMajor" in the app runtimeconfig.json) is a decision for the app' -Level WARN
        Write-Log '  owner, not something this script does. Once nothing depends on the old' -Level WARN
        Write-Log ('  major, remove it with Remove-DotNetEolChannel.ps1 to clear the SEoL finding.') -Level WARN
    }
}

# ------------------------------------------------------------------
# Phase 2: uninstall superseded versions -- keyed on DISPLAYNAME version
# ------------------------------------------------------------------
Write-Log ''
Write-Log '=== Phase 1b: ASP.NET Core Hosting Bundle ==='
$hb = Get-HostingBundles
if (-not $hb) {
    Write-Log '  No hosting bundle installed (no IIS ASP.NET Core hosting on this host).'
} else {
    foreach ($b in $hb) {
        Write-Log ('  Installed: ' + $b.Name + '  (version ' + $b.Version + ')')
    }
    # Update each major whose bundle is behind the newest runtime we just installed.
    $afterP1 = Get-InstalledMap $roots
    foreach ($b in ($hb | Sort-Object Major -Unique)) {
        $maj = $b.Major
        $newestForMajor = [version]'0.0.0'
        foreach ($k in $afterP1.Keys) {
            foreach ($v in $afterP1[$k]) {
                if ($v.Major -eq $maj -and $v -gt $newestForMajor) { $newestForMajor = $v }
            }
        }
        if ($b.Version -ge $newestForMajor) {
            Write-Log ('  Bundle ' + $maj + '.x at ' + $b.Version + ' is not behind the runtimes (' + $newestForMajor + '). Leaving it.')
            continue
        }
        Write-Log ('  Bundle ' + $maj + '.x is at ' + $b.Version + ' but runtimes are at ' + $newestForMajor + '.') -Level WARN
        Write-Log '  It PINS the old framework folders, so updating it is what releases them.' -Level WARN
        if (-not (Install-HostingBundle -Major $maj)) { $Failed = $true; continue }
        if (-not $DryRun) {
            Start-Sleep -Seconds 3
            $nowBundles = Get-HostingBundles | Where-Object { $_.Major -eq $maj }
            $nowVer = if ($nowBundles) { ($nowBundles | Sort-Object Version -Descending)[0].Version } else { [version]'0.0.0' }
            if ($nowVer -gt $b.Version) {
                Write-Log ('  Hosting bundle advanced: ' + $b.Version + ' -> ' + $nowVer)
                Write-Log '  REMINDER: a manual IIS restart may be required -- stop the Windows'
                Write-Log '  Process Activation Service (WAS), then start W3SVC and dependents.'
            } else {
                Write-Log ('  Hosting bundle did NOT advance (still ' + $nowVer + ').') -Level WARN
                Write-Log '  The aka.ms hosting permalink has historically lagged the newest patch.' -Level WARN
                Write-Log '  Download the current bundle from dotnet.microsoft.com and install it' -Level WARN
                Write-Log '  manually, then re-run this script.' -Level WARN
            }
        }
    }
}

Write-Log ''
Write-Log '=== Phase 1c: superseded .NET SDKs ==='
$sdkEntries = Get-DotNetSdkEntries
if (-not $sdkEntries) {
    Write-Log '  No .NET SDKs installed.'
} else {
    foreach ($s in ($sdkEntries | Sort-Object Major, Version)) {
        Write-Log ('  Installed: ' + $s.Name)
    }

    # v3.3: a LONE SDK per (major, arch) is invisible to the dedup logic
    # below -- it is trivially "the newest in its group" even if it is
    # months out of patch, and it still pins whatever frameworks it shipped
    # with. Gated on -RemoveSupersededSdks (same switch, since it already
    # means "manage SDKs on this build machine, confirmed with the owner")
    # rather than a new switch: this downloads a ~150-250 MB bundle per
    # arch, which should not happen on every run by default the way the
    # much smaller runtime patches do in Phase 1.
    if ($RemoveSupersededSdks -and -not $DryRun) {
        Write-Log ''
        Write-Log '  Installing the current SDK patch for every (major, arch) present, so a'
        Write-Log '  lone stale SDK gets a newer sibling and the supersede logic below can'
        Write-Log '  actually see and remove it.'
        $doneMA = @()
        foreach ($s in $sdkEntries) {
            $ma = ('' + $s.Major + '|' + $s.Arch)
            if ($doneMA -contains $ma) { continue }
            $doneMA += $ma
            if (-not (Install-Sdk -Major $s.Major -Arch $s.Arch)) { $Failed = $true }
        }
        $sdkEntries = Get-DotNetSdkEntries
    }

    # group by major + arch; anything below the newest in its group is superseded
    $groups = @{}
    foreach ($s in $sdkEntries) {
        $k = ('' + $s.Major + '|' + $s.Arch)
        if (-not $groups.ContainsKey($k)) { $groups[$k] = @() }
        $groups[$k] += $s
    }
    $superseded = @()
    foreach ($k in $groups.Keys) {
        $sorted = @($groups[$k] | Sort-Object Version -Descending)
        if ($sorted.Count -le 1) { continue }
        $keep = $sorted[0]
        foreach ($old in ($sorted | Select-Object -Skip 1)) {
            Write-Log ('  SUPERSEDED: ' + $old.Name + '  (newest in ' + $k + ' is ' + $keep.Version + ')') -Level WARN
            $superseded += $old
        }
    }

    if ($superseded.Count -eq 0) {
        Write-Log '  No superseded SDKs -- one per major/arch, nothing to remove.'
    } elseif (-not $RemoveSupersededSdks) {
        Write-Log ''
        Write-Log ('  ' + $superseded.Count + ' superseded SDK(s) are PINNING old frameworks.') -Level WARN
        Write-Log '  They hold WiX dependency references, so the runtime cleanup below will' -Level WARN
        Write-Log '  correctly refuse and the findings will not clear. Re-run with' -Level WARN
        Write-Log '  -RemoveSupersededSdks to remove them (a global.json scan guards against' -Level WARN
        Write-Log '  breaking a pinned build). This is a build-environment change: confirm' -Level WARN
        Write-Log '  with the machine owner first.' -Level WARN
    } else {
        Write-Log ''
        Write-Log '  Scanning for global.json SDK pins before removing anything...'
        $pins = Get-GlobalJsonSdkPins
        if ($pins.Count -eq 0) {
            Write-Log '  No global.json SDK pins found in user profiles or common source roots.'
        } else {
            foreach ($pin in $pins) {
                Write-Log ('    pin ' + $pin.Version + '  rollForward=' + $(if ($pin.RollForward) { $pin.RollForward } else { '(default)' }) + '  ' + $pin.File)
            }
        }
        foreach ($old in $superseded) {
            $pinnedBy = @($pins | Where-Object { $_.Version -eq $old.Version.ToString() })
            if ($pinnedBy.Count -gt 0) {
                Write-Log ('  REFUSING to remove ' + $old.Name + ' -- pinned by global.json:') -Level ERROR
                foreach ($pb in $pinnedBy) { Write-Log ('      ' + $pb.File) -Level ERROR }
                Write-Log '      Removing it would break that build. Retarget or relax the pin first.' -Level ERROR
                $Failed = $true
                continue
            }
            if ($DryRun) {
                Write-Log ('  [DRYRUN] Would remove ' + $old.Name)
                continue
            }
            Write-Log ('  Removing ' + $old.Name + ' ...')
            $e = $old.Entry
            $rc = $null
            try {
                if ($e.QuietUninstallString) {
                    $cmd = $e.QuietUninstallString
                    $exeQ = ($cmd -split '"')[1]
                    $argsQ = ($cmd.Substring($cmd.IndexOf($exeQ) + $exeQ.Length + 1)).Trim()
                    $u = Start-Process $exeQ -ArgumentList $argsQ -Wait -PassThru -NoNewWindow
                    $rc = $u.ExitCode
                } elseif ($e.PSChildName -match '^\{[0-9A-Fa-f-]+\}$') {
                    $rc = Invoke-Msi ('/x ' + $e.PSChildName + ' /qn /norestart')
                } else {
                    Write-Log '    No usable uninstall string.' -Level WARN
                    continue
                }
            } catch {
                Write-Log ('    Uninstall error: ' + $_) -Level ERROR
                $Failed = $true
                continue
            }
            Write-Log ('    Exit: ' + $rc)
            if ($rc -eq 3010) { $Reboot = $true }
            Start-Sleep -Seconds 2
            $still = Get-DotNetSdkEntries | Where-Object { $_.Name -eq $old.Name }
            if ($still) {
                Write-Log '    NOT ACTUALLY REMOVED -- the SDK entry survived. A bundle with its own' -Level WARN
                Write-Log '    remaining dependents skips uninstall and reports success. Consider' -Level WARN
                Write-Log '    Microsoft dotnet-core-uninstall for this host.' -Level WARN
                $script:UninstallNoOp = $true
            } else {
                Write-Log '    Removed. Its framework references are released.'
            }
        }
    }
}

Write-Log ''
Write-Log '=== Phase 1d: orphaned ARP registrations (no payload on disk) ==='
if ($OrphanMajors.Count -eq 0) {
    Write-Log '  None -- every registered major has a runtime payload.'
} elseif (-not $RemoveOrphanedRegistrations) {
    Write-Log ('  ' + $OrphanMajors.Count + ' major(s) registered with no payload: .NET ' + (($OrphanMajors | Sort-Object) -join ', .NET '))
    Write-Log '  Not removing (pass -RemoveOrphanedRegistrations).'
} else {
    foreach ($m in ($OrphanMajors | Sort-Object)) {
        foreach ($e in $arpMajors[[int]$m]) {
            if ($DryRun) { Write-Log ('  [DRYRUN] Would remove ' + $e.DisplayName); continue }
            Write-Log ('  Removing orphaned registration: ' + $e.DisplayName)
            $verStr = $null
            if ($e.DisplayName -match '(\d+\.\d+\.\d+)') { $verStr = $matches[1] }
            # v3.2: reuse Invoke-ArpEntryRemoval instead of a duplicate inline
            # block -- this was also the block relying on $arpPaths before it
            # was assigned (see hoist above) and hardcoding the "exit-0
            # dependents" theory regardless of the actual exit code.
            Invoke-ArpEntryRemoval -Entry $e -Version $verStr -AllowHardRemoval | Out-Null
        }
    }
}

Write-Log ''
Write-Log '=== Phase 2: removing superseded versions (by DisplayName version) ==='

# v3.6: re-inventory the disk HERE. Phase 2 reads ARP fresh (below), so it has
# to compare against an equally fresh view of what is on disk -- anything
# installed by Phase 1/1a is invisible to the Phase-0 $before map, and an ARP
# entry whose payload "does not exist" only because the snapshot predates its
# install is not an orphan. See the ORPHANED GROUP check below (CSLT-020).
$diskNow = Get-InstalledMap $roots

$dotnetArp = Get-ItemProperty -Path $arpPaths -ErrorAction SilentlyContinue | Where-Object {
    $_.DisplayName -match '^Microsoft (\.NET|ASP\.NET Core|Windows Desktop) Runtime'
}

# Group key: name-prefix|major|arch. Version = the one written in DisplayName.
$groups = @{}
foreach ($e in $dotnetArp) {
    if ($e.DisplayName -match '^(.*?Runtime)\s*-?\s*(\d+)\.(\d+)\.(\d+)\s*\((x64|x86)\)') {
        $prefix  = $matches[1].Trim()
        $nameVer = [version]($matches[2] + '.' + $matches[3] + '.' + $matches[4])
        $arch    = $matches[5]
        $key     = $prefix + '|' + $matches[2] + '|' + $arch
        if (-not $groups.ContainsKey($key)) { $groups[$key] = @() }
        $groups[$key] += @{ Entry = $e; NameVer = $nameVer }
    }
}

foreach ($key in $groups.Keys) {
    $items  = $groups[$key]
    $parts  = $key -split '\|'
    $prefix = $parts[0]; $groupMajor = [int]$parts[1]; $groupArch = $parts[2]

    # v3.1: does THIS EXACT (flavor, arch, major) have any on-disk payload at
    # all? Phase 1d's ARP-only check only catches a MAJOR with zero payload
    # ACROSS EVERY flavor/arch -- it never fires when a different flavor/arch
    # of the same major is genuinely installed elsewhere (e.g. x64 8.0.30
    # exists, so major 8 is never flagged, even though x86 WindowsDesktop/
    # NETCore never had an 8.x folder at all). CSPC-004 (2026-08-31, plugin
    # 326863): x86 Windows Desktop Runtime 8.0.27 and .NET Runtime 8.0.26-29
    # were ALL orphaned this way, and 8.0.27/8.0.29 were being marked "Keep"
    # simply for being the highest DisplayName version REGISTERED, with
    # nothing on disk backing any of them -- Tenable reads DisplayVersion
    # from ARP directly, so "keep the max ARP entry" cleared nothing.
    # v3.6: this check asks "is there payload on disk", so it must read the
    # disk as it is NOW ($diskNow, re-inventoried at the top of Phase 2), not
    # the Phase-0 snapshot ($before). CSLT-020 (2026-09-02) is what this cost:
    # Phase 1a installed .NET 10, and Phase 2 -- comparing freshly-read ARP
    # entries against a disk map captured BEFORE that install -- found no
    # major-10 payload in $before, declared the brand-new registrations an
    # ORPHANED GROUP, and removed them (hard-stripping the registry keys via
    # the v3.4 fallback when the MSI uninstall no-op'd). The run installed
    # .NET 10 and destroyed it ~3 minutes later, ending exactly where it
    # started. The $before comparison was only ever safe because every
    # earlier phase installed newer PATCHES of majors already in $before;
    # -InstallSuccessorMajor (v3.5) broke that invariant by design.
    $flavorKey = Get-FlavorKeyForArpPrefix -Prefix $prefix
    $diskKey   = $groupArch + '|' + $flavorKey
    $hasPayloadForMajor = $false
    if ($flavorKey -and $diskNow.ContainsKey($diskKey)) {
        $hasPayloadForMajor = [bool]($diskNow[$diskKey] | Where-Object { $_.Major -eq $groupMajor })
    }

    if (-not $hasPayloadForMajor) {
        Write-Log ('  ORPHANED GROUP: ' + $prefix + ' [' + $groupMajor + '.x ' + $groupArch + '] -- no on-disk') -Level WARN
        Write-Log ('  payload for this flavor/arch/major at all. None of the entries below are' ) -Level WARN
        Write-Log ('  backing anything; "keep the highest registered version" would keep a' ) -Level WARN
        Write-Log ('  dead ARP entry, which is exactly what left plugin 326863 open on CSPC-004.') -Level WARN
        foreach ($it in $items) {
            $e = $it.Entry
            if (-not $RemoveOrphanedRegistrations) {
                Write-Log ('    ORPHAN (not removed): ' + $e.DisplayName + '  [' + $e.DisplayVersion + ']') -Level WARN
                continue
            }
            Write-Log ('    Removing orphan: ' + $e.DisplayName + '  [' + $e.DisplayVersion + ']') -Level WARN
            Invoke-ArpEntryRemoval -Entry $e -Version $it.NameVer.ToString() -AllowHardRemoval | Out-Null
        }
        if (-not $RemoveOrphanedRegistrations) {
            Write-Log '    Re-run with -RemoveOrphanedRegistrations to remove these.' -Level WARN
        }
        continue
    }

    $maxVer = ($items | ForEach-Object { $_.NameVer } | Sort-Object -Descending)[0]
    foreach ($it in $items) {
        $e = $it.Entry
        if ($it.NameVer -ge $maxVer) {
            Write-Log ('  Keeping : ' + $e.DisplayName + '  [' + $e.DisplayVersion + ']')
            continue
        }
        Write-Log ('  Removing: ' + $e.DisplayName + '  [' + $e.DisplayVersion + ']') -Level WARN
        # Hard removal only when THIS version has no files on disk: an older
        # sibling that still has a payload may be a real SDK/hosting-bundle
        # reference, and stripping its registration would hide that. A live
        # dependency holder still blocks it inside Invoke-ArpEntryRemoval.
        $arpOnly = -not (Test-ArpVersionOnDisk -DiskMap $diskNow -Prefix $prefix -Arch $groupArch -Version $it.NameVer)
        if ($arpOnly) { Write-Log ('    ' + $it.NameVer + ' has no files on disk -- registry entry only.') }
        Invoke-ArpEntryRemoval -Entry $e -Version $it.NameVer.ToString() -AllowHardRemoval:($arpOnly -and $RemoveOrphanedRegistrations) | Out-Null
    }
}

# ------------------------------------------------------------------
# Phase 3: verify -- every flavor must now be at a HIGHER patch than
# it started at. If the newest install got removed (v1 bug class),
# reinstall it once and re-check.
# ------------------------------------------------------------------
Write-Log ''
Write-Log '=== Phase 3: verification ==='

if (-not $DryRun) {
    $after = Get-InstalledMap $roots
    $staleFound = @()
    # v2.4: evaluate each MAJOR channel independently. .NET 8 and .NET 9 on the
    # same machine are both legitimate; only same-major versions supersede.
    $checkList = @()
    foreach ($key in $before.Keys) {
        foreach ($m in ($before[$key] | ForEach-Object { $_.Major } | Sort-Object -Unique)) {
            $checkList += @{ Key = $key; Major = $m }
        }
    }

    # v3.6: verify Phase 1a's successor-major installs SURVIVED this run. The
    # checklist above is built from $before, so a major that Phase 1a added
    # can never appear in it -- which is exactly how CSLT-020 (2026-09-02)
    # reported "All present flavors advanced" in the same run that installed
    # .NET 10 and then deleted it again in Phase 2. Checked separately
    # because the criterion differs: for these there is no "starting max" to
    # regress against, the requirement is simply that the major is present.
    foreach ($si in $SuccessorInstalled) {
        $sLabel = $si.Key + ' [' + $si.Major + '.x successor]'
        $sNow   = @($after[$si.Key] | Where-Object { $_.Major -eq $si.Major })
        if ($sNow.Count -gt 0) {
            Write-Log ('  OK      ' + $sLabel + ' : staged at ' + (($sNow | Sort-Object -Descending)[0]) + '.')
        } else {
            Write-Log ('  FAILED  ' + $sLabel + ' : installed by Phase 1a but NOT on disk now --') -Level ERROR
            Write-Log '          something removed it later in this same run. Check the Phase 2 log' -Level ERROR
            Write-Log '          above for an ORPHANED GROUP entry naming this major.' -Level ERROR
            $Failed = $true
        }
    }
    foreach ($item in $checkList) {
        $key    = $item.Key
        $maj    = $item.Major
        $arch   = ($key -split '\|')[0]
        $flavor = ($key -split '\|')[1]
        $label  = $key + ' [' + $maj + '.x]'

        $startMax = (@($before[$key] | Where-Object { $_.Major -eq $maj }) | Sort-Object -Descending)[0]
        $nowList  = @($after[$key] | Where-Object { $_.Major -eq $maj })
        $nowMax   = if ($nowList.Count -gt 0) { ($nowList | Sort-Object -Descending)[0] } else { [version]'0.0.0' }

        # Check 1 (idempotent): newest of THIS major must be at least the starting max.
        if ($nowMax -lt $startMax) {
            Write-Log ('  MISSING ' + $label + ' : newest now ' + $nowMax + ' < started ' + $startMax + '. Reinstalling...') -Level WARN
            if (Install-Runtime -Flavor $flavor -Major $maj -Arch $arch) {
                $after = Get-InstalledMap $roots
                $nowList = @($after[$key] | Where-Object { $_.Major -eq $maj })
                $nowMax = if ($nowList.Count -gt 0) { ($nowList | Sort-Object -Descending)[0] } else { [version]'0.0.0' }
            }
            if ($nowMax -lt $startMax) {
                Write-Log ('  FAILED  ' + $label + ' : could not restore a current version.') -Level ERROR
                $Failed = $true
                continue
            }
        }

        # Check 2: no superseded versions of THIS major may remain on disk.
        $stale = @($nowList | Where-Object { $_ -lt $nowMax })
        if ($stale.Count -eq 0) {
            Write-Log ('  OK      ' + $label + ' : at ' + $nowMax + ', no superseded versions on disk.')
        } else {
            Write-Log ('  STALE   ' + $label + ' : ' + (($stale | Sort-Object) -join ', ') + ' still on disk beside ' + $nowMax) -Level WARN
            foreach ($s in $stale) { if ($staleFound -notcontains $s.ToString()) { $staleFound += $s.ToString() } }

            if (-not $RemoveStaleFolders) {
                Write-Log '          Payload persists after uninstall. Re-run with -RemoveStaleFolders' -Level ERROR
                Write-Log '          if diagnostics below show no dependency references.' -Level ERROR
                $Failed = $true
            } else {
                # Direct folder removal: safe when a newer version exists and folder is not in use
                $rootPath = if ($arch -eq 'x64') { 'C:\Program Files\dotnet' } else { 'C:\Program Files (x86)\dotnet' }
                foreach ($s in $stale) {
                    # SAFETY: never delete a framework a live product still depends on.
                    $holders = Test-VersionHeldByDependency -Version $s.ToString()
                    if ($holders.Count -gt 0) {
                        Write-Log ('          REFUSING to delete ' + $s + ' -- still held by:') -Level ERROR
                        foreach ($hh in $holders) { Write-Log ('            ' + $hh) -Level ERROR }
                        Write-Log '          Update or remove that product first (for a hosting bundle,' -Level ERROR
                        Write-Log '          install the current bundle for its major -- Phase 1b does this).' -Level ERROR
                        $Failed = $true
                        continue
                    }
                    $foldersToClear = @()
                    $foldersToClear += Join-Path $rootPath ('shared\' + $flavor + '\' + $s)
                    if ($flavor -eq 'Microsoft.NETCore.App') {
                        $foldersToClear += Join-Path $rootPath ('host\fxr\' + $s)
                    }
                    foreach ($f in $foldersToClear) {
                        if (-not (Test-Path $f)) { continue }
                        $inUseTest = $f + '.deleting'
                        try {
                            Rename-Item -Path $f -NewName (Split-Path -Leaf $inUseTest) -ErrorAction Stop
                            Remove-Item -Path $inUseTest -Recurse -Force -ErrorAction Stop
                            Write-Log ('          Deleted orphaned folder: ' + $f)
                        } catch {
                            if (Test-Path $inUseTest) {
                                Rename-Item -Path $inUseTest -NewName (Split-Path -Leaf $f) -ErrorAction SilentlyContinue
                            }
                            Write-Log ('          IN USE, skipped: ' + $f) -Level WARN
                            Write-Log '          Close the app using it (it will roll forward on relaunch) and re-run.' -Level WARN
                            $Failed = $true
                            # Remove-Item deletes children before the directory
                            # itself. If a child went but the directory did not
                            # (a held directory handle -- AV or an open CWD),
                            # the rollback above restores a resolver folder that
                            # no longer has hostfxr.dll in it, which breaks
                            # dotnet.exe for every major (CSPRLT-94).
                            if ($f -match '(?i)\\host\\fxr\\') {
                                $dll = $f + '\hostfxr.dll'
                                if ((Test-Path $f) -and -not (Test-Path $dll)) {
                                    Write-Log ('          BROKEN HOST: ' + $f + ' was restored but') -Level ERROR
                                    Write-Log '          hostfxr.dll is gone from it. dotnet.exe loads hostfxr from the' -Level ERROR
                                    Write-Log '          HIGHEST host\fxr folder, so this breaks EVERY installed major.' -Level ERROR
                                    Write-Log '          Reboot, then reinstall that runtime version to restore the DLL.' -Level ERROR
                                }
                            }
                        }
                    }
                }
                # Re-check this key after deletion attempts
                $recheck2 = Get-InstalledMap $roots
                $left = @($recheck2[$key] | Where-Object { $_.Major -eq $maj -and $_ -lt $nowMax })
                if ($left.Count -eq 0) {
                    Write-Log ('  OK      ' + $label + ' : stale folders cleared; at ' + $nowMax + '.')
                } else {
                    $Failed = $true
                }
            }
        }
    }

    # Dependency-reference diagnostics for any stale versions found
    if ($staleFound.Count -gt 0) {
        Write-Log ''
        Write-Log '=== Dependency-reference diagnostics ===' 
        Write-Log 'Products below hold references that block payload deletion:'
        $depRoot = 'HKLM:\SOFTWARE\Classes\Installer\Dependencies'
        foreach ($ver in $staleFound) {
            $verEsc = [regex]::Escape($ver)
            Get-ChildItem $depRoot -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match $verEsc } | ForEach-Object {
                Write-Log ('  Provider: ' + $_.PSChildName)
                $depPath = Join-Path $_.PSPath 'Dependents'
                if (Test-Path $depPath) {
                    Get-ChildItem $depPath | ForEach-Object {
                        $g = $_.PSChildName
                        $dn = ''
                        foreach ($hive in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\')) {
                            $prop = Get-ItemProperty ($hive + $g) -ErrorAction SilentlyContinue
                            if ($prop -and $prop.DisplayName) { $dn = $prop.DisplayName; break }
                        }
                        Write-Log ('    Dependent: ' + $g + '  ' + $dn)
                    }
                } else {
                    Write-Log '    (no Dependents subkey -- orphaned provider registration)'
                }
            }
        }
        Write-Log 'Resolve by dealing with the DEPENDENT product, not by deleting folders.'
        Write-Log 'The remedy depends on which kind of holder it is:'
        Write-Log '  * "... - Windows Server Hosting" -> ASP.NET Core Hosting Bundle.'
        Write-Log '    Install the current bundle for that major (Phase 1b does this), then'
        Write-Log '    re-run. Do NOT use -RemoveStaleFolders: deleting a framework the'
        Write-Log '    bundle owns can break IIS-hosted apps.'
        Write-Log '  * "Microsoft .NET SDK x.y.zzz" -> an SDK. Each SDK pins the framework,'
        Write-Log '    targeting pack and workload packs it shipped with, and CANNOT be'
        Write-Log '    updated in place to release them. Install the current SDK for that'
        Write-Log '    major, then UNINSTALL the superseded SDKs (Microsoft dotnet-core-'
        Write-Log '    uninstall removes them cleanly). CAUTION: this is a build machine --'
        Write-Log '    check with the owner first, and note that a global.json pinned to an'
        Write-Log '    exact SDK version will fail if that version is removed.'
        Write-Log '  * A dependent that resolves to no ARP name is orphaned debris; the'
        Write-Log '    provider key can be removed after confirming nothing needs it.'
    }
}

# ------------------------------------------------------------------
# Phase 4: remove the retiring major once its successor is verified
# (opt-in, -RemoveRetiredMajor). Runs only after Phase 3 so the successor
# check reads the end-of-run disk, and delegates the uninstall itself to
# Remove-DotNetEolChannel.ps1 (bundle-first teardown, SWID/host files,
# foreign WiX holder refusal) rather than duplicating it here.
# ------------------------------------------------------------------
Write-Log ''
Write-Log '=== Phase 4: remove the retired major after its successor (opt-in) ==='
$retireTargets = @(Get-SuccessorTargets -EolSeen $EolSeen -EolSoonSeen $EolSoonSeen -Map $EolSuccessorMajor)
if (-not $RemoveRetiredMajor) {
    if ($retireTargets.Count -gt 0) { Write-Log '  Not removing anything (pass -RemoveRetiredMajor).' }
    else { Write-Log '  No EOL or near-EOL major with a successor -- nothing to do.' }
} elseif ($retireTargets.Count -eq 0) {
    Write-Log '  No EOL or near-EOL major with a successor -- nothing to remove.'
} else {
    $remover = Find-RemoverScript
    $diskEnd = $(if ($DryRun) { $before } else { Get-InstalledMap $roots })
    $allSdks = @(Get-DotNetSdks)
    $allHosting = @(Get-HostingBundles)
    foreach ($rt in $retireTargets) {
        $m = $rt.From
        Write-Log ('  .NET ' + $m + ' -> .NET ' + $rt.To)
        $keysWithMajor = @($before.Keys | Where-Object { @($before[$_] | Where-Object { $_.Major -eq $m }).Count -gt 0 } | Sort-Object)
        Write-Log ('    Scanning for apps that need .NET ' + $m + ' (*.runtimeconfig.json)...')
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $pins = @(Find-RuntimeConfigPins -Major $m)
        Write-Log ('    ' + $pins.Count + ' found in ' + [int]$sw.Elapsed.TotalSeconds + 's.')
        foreach ($p in ($pins | Select-Object -First 25)) { Write-Log ('      needs .NET ' + $m + ': ' + $p) -Level WARN }
        if ($pins.Count -gt 25) { Write-Log ('      ... and ' + ($pins.Count - 25) + ' more') -Level WARN }
        $sdkM = @($allSdks | Where-Object { $_ -match ('^Microsoft \.NET SDK ' + $m + '\.') })
        $hbM = @($allHosting | Where-Object { $_.Major -eq $m } | ForEach-Object { $_.Name })
        $decision = Get-RetireDecision -Major $m -Successor $rt.To -KeysWithMajor $keysWithMajor -After $diskEnd `
            -AppPinCount $pins.Count -Sdks $sdkM -HostingBundles $hbM `
            -RunFailed ([bool]$Failed) -RebootPending ([bool]$Reboot) -RemoverFound ([bool]$remover)
        if ($DryRun) {
            $notYet = @($decision.Reasons | Where-Object { $_ -notmatch ' on disk$' })
            if ($notYet.Count -eq 0) { Write-Log ('    [DRYRUN] Would remove .NET ' + $m + ' once .NET ' + $rt.To + ' is verified for: ' + ($keysWithMajor -join ', ')) }
            else { foreach ($r in $notYet) { Write-Log ('    [DRYRUN] Would NOT remove: ' + $r) -Level WARN } }
            continue
        }
        if (-not $decision.Remove) {
            Write-Log ('    NOT removing .NET ' + $m + ':') -Level WARN
            foreach ($r in $decision.Reasons) { Write-Log ('      - ' + $r) -Level WARN }
            if ($pins.Count -gt 0) {
                Write-Log ('    Those apps fail to start without .NET ' + $m + '. Retarget them (or set') -Level WARN
                Write-Log '    "rollForward": "LatestMajor") with the owner, then re-run.' -Level WARN
            }
            $NeedsHuman = $true
            continue
        }
        $psExe = (Get-Process -Id $PID).Path
        Write-Log ('    .NET ' + $rt.To + ' verified for every flavor/arch that had .NET ' + $m + '; nothing found that needs ' + $m + '.')
        Write-Log ('    Running: ' + $remover + ' -DotNet' + $m + ' -RemoveStaleFolders')
        & $psExe -NoProfile -ExecutionPolicy Bypass -File $remover ('-DotNet' + $m) -RemoveStaleFolders
        $rc = $LASTEXITCODE
        Write-Log ('    Remove-DotNetEolChannel exit: ' + $rc)
        $endMap = Get-InstalledMap $roots
        $leftOld = @($endMap.Keys | Where-Object { @($endMap[$_] | Where-Object { $_.Major -eq $m }).Count -gt 0 })
        $lostNew = @($keysWithMajor | Where-Object { @($endMap[$_] | Where-Object { $_.Major -eq $rt.To }).Count -eq 0 })
        if ($lostNew.Count -gt 0) {
            Write-Log ('    FAILED: .NET ' + $rt.To + ' is missing afterwards for ' + ($lostNew -join ', ')) -Level ERROR
            $Failed = $true
        }
        switch ($rc) {
            0       { }
            3010    { $Reboot = $true }
            2       { $NeedsHuman = $true }
            default { $Failed = $true }
        }
        if ($leftOld.Count -eq 0 -and ($rc -eq 0 -or $rc -eq 3010)) {
            Write-Log ('    .NET ' + $m + ' removed; .NET ' + $rt.To + ' in place.')
            $RetiredRemoved += $m
        } elseif ($leftOld.Count -gt 0) {
            Write-Log ('    .NET ' + $m + ' still on disk for ' + ($leftOld -join ', ') + ' -- see that script' + [char]39 + 's log (RemoveDotNetEol_' + $m + '_*.log).') -Level WARN
            if ($rc -eq 0) { $Failed = $true }
        }
    }
}

# ------------------------------------------------------------------
Write-Log ''
Write-Log '=== Final runtime inventory ==='
foreach ($root in $roots) {
    if (Test-Path $root.Exe) {
        Write-Log ('  [' + $root.Arch + ']')
        foreach ($line in (Invoke-DotNetListRuntimes -Exe $root.Exe)) { Write-Log ('    ' + $line) }
    }
}
Write-Log ''
if ($UninstallNoOp) {
    Write-Log ''
    Write-Log 'AT LEAST ONE UNINSTALL WAS A NO-OP (exit 0, entry survived).' -Level ERROR
    Write-Log 'This host cannot progress by re-running the script. Resolve the holding' -Level ERROR
    Write-Log 'product named in the dependency diagnostics first.' -Level ERROR
}
if ($script:TlsFailure) {
    Write-Log ('NOTHING WAS DOWNLOADED: TLS failure (' + $script:TlsFailure + '). Fix the certificate/TLS cause in the Phase 1 log, then re-run.') -Level ERROR
}
if ($Failed) {
    Write-Log 'One or more steps FAILED (install, SDK removal or verification). See the ERROR lines above.' -Level ERROR
    Write-Log '=============================================='
    exit 1
}
if ($NeedsHuman) {
    Write-Log 'Updates done, but -RemoveRetiredMajor needs a human decision (see Phase 4).' -Level WARN
    Write-Log '=============================================='
    exit 2
}
Write-Log 'All present flavors advanced. Re-run a Nessus scan to confirm.'
$eolLeft = @($EolSeen | Where-Object { $RetiredRemoved -notcontains $_ })
if ($eolLeft.Count -gt 0) {
    Write-Log ('REMINDER: EOL channel(s) still installed on this host: .NET ' + (($eolLeft | Sort-Object) -join ', .NET ')) -Level WARN
    Write-Log 'Patched to final build, but SEoL findings persist until removal/migration.' -Level WARN
    Write-Log 'To remove: Remove-DotNetEolChannel.ps1 with -DotNet5 / -DotNet6 / -DotNet7 / -DotNet8 / -DotNet9' -Level WARN
    Write-Log '(one or more in the same run). No switch defaults to major 6. Pair with -RemoveStaleFolders.' -Level WARN
}
Write-Log '=============================================='
if ($Reboot) { exit 3010 }
exit 0
