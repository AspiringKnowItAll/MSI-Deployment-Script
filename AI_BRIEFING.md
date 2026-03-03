# AI Agent Briefing: Install-RemoteMSI.ps1

## Quick Context

Production PowerShell deployment script for remote MSI/MSIX installs with robust credential validation, batch orchestration, retry handling, reboot evaluation, and aggregated logging.

**Owner**: Andrew Lucas  
**Last Modified**: March 2, 2026  
**PowerShell Version Required**: 5.1+ (7+ recommended for parallel)

---

## What This Script Does

`Install-RemoteMSI.ps1` performs silent remote installs in two modes:

1. **Single-machine mode**
2. **Batch mode** from `.txt` / `.csv`

High-level flow:
1. Runtime host bootstrap check (PS version, optional PS7 relaunch/install path)
2. Credential validation against domain services (AD/DC) before heavy processing
3. Operator account confirmation prompt (shows active account, optional credential override)
4. Target sanitization and five-state batch pre-validation (AD/DNS/reachability/WinRM)
5. Authorization canary check on up to 3 ready machines
6. Installer selection from script directory
7. Transfer with retry policy (`5s`, `10s`, `30s`, `60s`)
8. Silent install (`msiexec /quiet /norestart`)
9. Install result normalization (exit descriptions + final per-machine result)
10. Failed-machine-only retry rounds
11. Summary table + one aggregated run log

---

## Current Reboot Logic (Important)

Reboot handling is now **installation-only** for result reporting:

- Script snapshots reboot indicators pre-install and post-install.
- `RebootRequired` is set to `Yes` only if the install itself triggered reboot requirement (MSI code `1641/3010` or newly introduced reboot indicators after install).
- Pre-existing reboot state on the machine is not counted as install-required reboot in final result.
- Summary table shows reboot as a simple `Yes` / `No` column.

Primary functions:
- `Get-PendingRebootState`
- `Get-RebootRequirementEvaluation`

---

## Key Functions (Current)

| Function | Purpose |
|---|---|
| `Write-Log` | Colored console + timestamped run log output |
| `Test-InstallerFilesExist` | Verifies MSI/MSIX exists in script directory |
| `Get-InstallerFiles` / `Get-MSIFile` | Installer discovery + selection |
| `Get-ValidatedSingleHostname` | Single-target input + sanitization |
| `Find-BatchMachineFile` | Batch file discovery / selection |
| `Get-MachineNamesFromFile` | First-column parsing + sanitization |
| `Get-MachineAvailabilityReport` | Five-state machine validation + ready-target extraction |
| `Request-Credentials` | Terminal `Read-Host` credential prompt |
| `Get-ValidatedCredentialForDomain` | Early AD/DC credential validation |
| `Get-CredentialAfterUserConfirmation` | Always-on account prompt + optional credential override |
| `Invoke-AuthorizationCanaryCheck` | Preflight remote-admin authorization check (up to 3 machines) |
| `Copy-MSIWithRetry` | Retry transfer policy and operator retry/abort prompt |
| `Get-PendingRebootState` | Reads reboot indicators (registry + WMI) |
| `Get-RebootRequirementEvaluation` | Determines install-caused reboot required (Yes/No) |
| `Remove-RemoteMSI` | Removes installer from remote machine when applicable |
| `Invoke-MachineInstall` | Sequential single-machine execution path |
| `Invoke-Deployment` | Batch orchestration incl. parallel path + retry rounds |
| `Write-Summary` | Final run summary and result table |
| `Main` | End-to-end orchestration |

---

## Script Phases

```
PHASE 0: Runtime bootstrap (PS host/version gate)
PHASE 1: Installer file verification/selection
PHASE 2: Mode selection (Single/Batch)
PHASE 3: Target input + sanitization
PHASE 4: Credential validation first (AD/DC)
PHASE 5: Operator account confirmation (optional credential override)
PHASE 6: Batch pre-validation by five machine-availability states
PHASE 7: Authorization canary check on up to 3 ready machines
PHASE 8: Session creation + remote temp prep
PHASE 9: Transfer with retry policy
PHASE 10: Silent install and exit code capture
PHASE 11: Install-caused reboot evaluation (pre/post snapshot compare)
PHASE 12: Cleanup, per-machine retries, summary, and logging
```

---

## Decision Log (Current)

1. Credential validation runs before heavy processing.
2. Credential prompts are terminal-based (`Read-Host`) only.
3. Hostname sanitization applies to single and batch modes.
4. Batch file parsing uses first column; header not required.
5. Batch pre-validation is done before deployment workers start and excludes non-ready states.
6. Transfer retry delays are fixed: `5,10,30,60` seconds.
7. Failed machine retries occur after each batch and only for failed targets.
8. MSI retention policy: preserve on most failures; remove on success and corruption/open failure (`1619`).
9. Successful machines are commented in source batch file for reruns.
10. PS7 startup gate remains in place; fallback behavior preserved.
11. Optional PS7 install via configured Windows Update service remains available in interactive runs.
12. Reboot summary/reporting is installation-only `Yes/No` (pre-existing reboot not counted).
13. Credential pre-check is domain-auth based (not probe-machine endpoint based).
14. Batch mode fails fast if no machine is fully reachable after pre-validation.
15. Operator is always shown active execution account and can choose alternate credentials before canary/deployment.
16. Authorization canary validates remote-admin rights on up to 3 ready machines before deployment starts.
17. Batch pre-validation emits in-place status updates (non-animated) and uses the operator-facing wording: "Executing machine-state validation for batch processing list."
18. If pre-validation yields zero ready machines, script prints a machine-state summary table (all parsed machines + derived state) before terminating.

---

## Known Behaviors / Notes

- Parallel execution requires PowerShell 7+; script falls back to sequential when unavailable.
- Console uses animated spinner progress for installer execution and in-place status updates for batch pre-validation.
- Quiet MSI execution does not provide reliable granular percentage progress.
- Aggregated run log is reused across PS5→PS7 relaunch path via `-RunLogPath`.
- Reachability-only machines with WinRM disabled are excluded before deployment.
- Authorization canary failure stops deployment before install execution begins.
- Zero-ready pre-validation now renders a summary table so operators can review derived state per machine even when no install jobs run.

---

## Credential Security

- Password entry uses `Read-Host -AsSecureString`.
- Credentials are not logged or persisted to disk.
- `PSCredential` is used in-memory for remoting only.

---

## External Dependencies

Built-in cmdlets only (no mandatory external modules):
- Remoting: `New-PSSession`, `Invoke-Command`, `Remove-PSSession`
- Transfer: `Copy-Item`
- Validation: `Resolve-DnsName`, `Test-Connection`
- Reboot probes: registry lookups + `Get-WmiObject`
- Logging: `Add-Content`

Remote machine prerequisites:
- WinRM enabled
- Admin-capable credentials

---

## Testing Checklist (Current)

- [ ] Single mode success path (exit `0`) works end-to-end
- [ ] Batch mode with mixed success/failure behaves correctly
- [ ] Domain credential validation rejects invalid credentials within 2 attempts
- [ ] Account confirmation prompt always displays active execution identity
- [ ] Batch pre-validation correctly classifies all five machine states
- [ ] In-place pre-validation status updates appear after the operator-facing validation message
- [ ] If zero machines are ready after pre-validation, summary table still lists all machines with derived state
- [ ] Authorization canary checks up to 3 machines and blocks deployment on failure
- [ ] Transfer retry and retry-cycle prompt works
- [ ] Failed-machine-only retry prompt logic works
- [ ] Reboot column is `Yes` only for install-caused reboot requirement
- [ ] Summary table includes `Reboot` column only (no reboot-reason column)
- [ ] Successful machine comment-out mutation in batch source file works
- [ ] Console + log timestamps/severity are consistent

---

## Agent Guidance

When modifying this script:
1. Keep changes scoped and aligned with current decisions above.
2. Preserve credential-first and retry behavior unless user explicitly requests change.
3. Update both `README.md` and `AI_BRIEFING.md` when behavior changes.
4. Validate script parse and diagnostics before handoff.

---

**End of Briefing**
