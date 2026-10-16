---
name: writing-remediation-scripts
description: Use when writing, fixing, or reviewing a script in this repo (windows/*.ps1 for Endpoint Central, macos/*.sh for Mosyle), when a user pastes a run log or a Tenable finding and asks whether it worked or how to clear it, or when a deployed script failed, hung, no-opped, or reported success that did not happen.
---

# Writing remediation scripts

## Overview
Every script here runs unattended on a real fleet machine: SYSTEM via a 32-bit Endpoint Central agent, or root via Mosyle with no environment variables and a time limit. Most past bugs came from one of four mistakes:
- trusting a tool's exit code;
- reading state captured before our own changes;
- losing output when the job was killed;
- a summary that hid a failed step.

`lessons.md` in this folder has the full catalog with the host or PR that taught each one. Read the section for your platform before editing.

## Reading a run log the user pasted
1. Read the whole log, then answer the question first, e.g. "mostly yes; the update landed, cleanup did not".
2. Classify each problem. Is it:
   - a script bug (fix it, with a regression test);
   - host state (give the user the per-machine command);
   - deployment configuration? For example, the EC package runs the wrong script, or a switch was passed to a script that doesn't take it ("A parameter cannot be found").
3. Quote the exact log lines that prove the cause. If the cause can't be proven from the log, add diagnostics: the vendor's own log, a connectivity probe, the actual exit-code meaning.

## Checklist for every script change
- **State, not exit codes.** After the work, re-read the installed version, registry entry, file or folder. Treat a blank exit code as UNKNOWN, never 0, and look up non-zero codes rather than assuming what they mean.
- **Re-read state after you change it.** Never decide what to remove from a snapshot taken before you installed something.
- **Pure logic before the test gate.** Put helpers above `if ($env:<NAME>_DOTSOURCE -eq '1') { return }` (PowerShell) or `if [ "${<NAME>_SELFTEST:-0}" = "1" ]` (bash). Add `windows/tests/<Script>.Tests.ps1` or `macos/tests/<script>.test.sh` checks that use the verbatim log line from the failing host.
- **Bounded and observable.** Stream output to a per-step log file under the log dir, never a temp file you delete. Give every external call, including "quick" ones like `brew update`, a wall-clock limit that kills the whole process tree, and set a whole-run budget below the deployment tool's own limit.
- **Match the house style:**
  - Windows: no literal `"` (use `[char]34`) and bare switches only.
  - macOS: `CFG_*` CONFIG block; bash 3.2 with `set -u`-safe expansions (no empty arrays).
- **The summary must be honest.** Gather every failed, timed-out or skipped step into the final RESULT. Exit `0` = verified done, `2` = a human must look (EC success codes are `0,3010`), `1` = could not run.
- **Destructive steps:** offer `-DryRun` / `DRY_RUN=1`, hold (exit 2) when user data is present, add the new version before removing the old one, and remove only after confirming the new one landed.
- **No pinned versions.** Resolve the target at run time (latest patch on the installed branch, a date table for end-of-life) and compare per branch with `[version]` or `sort -V`.
- **Docs:** update the script header's version notes and `docs/SCRIPT-ARGUMENTS.md` for any new switch or CONFIG value.

## Verify before claiming
- `bash -n`, `shellcheck -s bash -S warning` (no new warnings), and the macOS test script. For PowerShell: the parser, then `pwsh -NoProfile -File windows/tests/<Script>.Tests.ps1`.
- If a test fails, read the run's log before changing the script. The fixture can be wrong too, for example a shim created after `chmod +x` ran.
- Commit only after every edit tool call has returned, then check `git status` is clean. An edit sent in the same batch as `git commit` gets left out.
- Put measured numbers in PR text (test counts, timings), not estimates.

## Final answer shape
Lead with the verdict. Then list script fixes (with the PR link) separately from per-machine actions the user must take, and from decisions only the user can make (defaults such as auto-accepting a license or granting sudo).
