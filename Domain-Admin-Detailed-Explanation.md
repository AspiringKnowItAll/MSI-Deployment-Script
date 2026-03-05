# Install-RemoteMSI.ps1 — Domain Admin Detailed Explanation

## Purpose

`Install-RemoteMSI.ps1` deploys an `.msi` or `.msix` package to one or more remote Windows machines over PowerShell Remoting (WinRM), with strong pre-validation, credential validation, retry logic, and full run logging.

---

## Script Scope and Inputs

### Parameters
- `-NonInteractive` (switch): suppresses interactive prompts where possible.
- `-RunLogPath <string>`: optional custom path for the per-run aggregated log file.

### Global configuration values
- Script and installer source folder: script directory.
- Remote staging path: `C:\Temp`
- Log folder: `.\Logs`
- Max credential attempts: `2`
- Transfer retry delays: `5, 10, 30, 60` seconds.
- Run ID format: `yyyyMMdd_HHmmss`
- `$ErrorActionPreference = 'Stop'`

---

## End-to-End Execution Flow

## 1) Startup and logging
1. `Main` starts and captures run start time.
2. `Initialize-RunLog` creates the log file:
   - Uses `-RunLogPath` if provided, otherwise:
   - `Logs\Deployment_<timestamp>.log`
3. `Write-Log` writes timestamped messages to console and log file.

## 2) PowerShell 7 bootstrap check
1. `Invoke-PowerShell7Bootstrap` checks host PS version.
2. If PS 7+, continue.
3. If below PS 7:
   - `Get-PowerShell7Details` searches for `pwsh.exe` in PATH, common install folders, and registry App Paths.
   - In interactive mode, user can relaunch via `Invoke-PowerShell7Relaunch`.
   - If not installed, user can optionally install via `Install-PowerShell7ViaWindowsUpdate` (requires local admin).
4. If relaunched successfully, parent exits and returns child exit code.

## 3) Installer validation and selection
1. `Test-InstallerFilesExist` verifies at least one `.msi`/`.msix` exists in script directory.
2. `Get-MSIFile`:
   - auto-selects single installer, or
   - prompts selection when multiple installers are present.

## 4) Execution mode selection
- `Get-ExecutionMode` prompts:
  - `Single` machine mode
  - `Batch` mode (`.txt`/`.csv` machine list)

## 5) Credential validation and execution identity
1. `Get-ValidatedCredentialForDomain`:
   - Uses current context if `Test-CurrentUserDomainAuth` succeeds.
   - Else prompts via `Request-Credentials` and validates with `Test-DomainCredential`.
2. `Get-CredentialAfterUserConfirmation` shows current/effective identity and optionally accepts alternate validated credentials.

---

## Single Machine Path

## 6) Target input and pre-validation
1. `Get-ValidatedSingleHostname` reads hostname.
2. `ConvertTo-Hostname` sanitizes hostname characters.
3. `Get-MachineAvailabilityReport` runs checks in order:
   - `Test-ComputerInAD`
   - `Resolve-ComputerIPAddresses`
   - `Test-ComputerOnline`
   - `Test-ComputerWinRM`
4. Machine is classified into one state:
   - `ReadyMachines`
   - `InvalidNameNotInAD`
   - `ValidNoDNSIP`
   - `ReachabilityFailed`
   - `WinRMUnavailable`
5. If not `ReadyMachines`, run stops with explicit reason.

## 7) Authorization canary
- `Invoke-AuthorizationCanaryCheck` (single target) validates:
  - session establishment
  - local admin rights (`Test-RemoteAdmin`)
- Any failure aborts before installation.

## 8) Deployment
- `Invoke-Deployment` is called with throttle `1`.
- Per-machine work is done by `Invoke-MachineInstall`:
  1. Open PSSession.
  2. Ensure `C:\Temp` exists.
  3. Capture pre-install reboot state (`Get-PendingRebootState`).
  4. Copy installer with retry policy (`Copy-MSIWithRetry`).
  5. Execute `msiexec.exe /i <path> /quiet /norestart`.
  6. Map exit code using `Get-MSIExitDescription`.
  7. If success (`0`, `1641`, `3010`), evaluate reboot requirement (`Get-RebootRequirementEvaluation`).
  8. Clean remote installer via `Remove-RemoteMSI` on success (and on `1619`).
  9. Return normalized result object (`New-Result`).
- Failed installs can be retried interactively using `Read-RetryChoice`.

---

## Batch Path

## 6) Batch machine file discovery and parse
1. `Find-BatchMachineFile` discovers `.txt/.csv` in script directory or prompts for full path.
2. `Get-MachineNamesFromFile`:
   - reads machine names (first CSV column),
   - ignores blank/comment lines (`#`),
   - sanitizes names (`ConvertTo-Hostname`),
   - deduplicates list.

## 7) Batch pre-validation
- `Get-MachineAvailabilityReport` applies the same 5-state checks to all input machines.
- Non-ready machines are excluded and logged.
- If zero machines are ready:
  - `Write-MachineStateValidationSummary` prints pre-validation summary table,
  - run exits as failed.

## 8) Batch authorization canary
- `Invoke-AuthorizationCanaryCheck` tests up to 3 ready machines.
- Any canary failure aborts full rollout.

## 9) Parallel/sequential execution setup
1. Operator enters thread count (`1` = sequential).
2. If host is below PS 7 and thread count > 1, script forces sequential and logs warning.
3. `Invoke-Deployment` chunks list via `Get-ChunkedArrays`.

## 10) Batch deployment behavior
- In each chunk:
  - PS7+ with throttle >1 uses `ForEach-Object -Parallel -AsJob`.
  - Otherwise sequential `Invoke-MachineInstall`.
- Batch progress spinner is shown.
- Failed machines enter interactive retry rounds (failed machines only).
- Final result collapse per machine is done by `Get-FinalResultPerMachine`.
- Successful machine lines are commented in source list via `Update-BatchFileForSuccesses`.

---

## 11) Final reporting and exit behavior
- `Write-Summary` prints:
  - overall status (`SUCCESS`, `PARTIAL SUCCESS`, `FAILED`)
  - totals (success/fail/reboot)
  - per-machine result table
  - detailed failed-machine log entries
- Exit code:
  - `0` if all final machine results succeeded
  - `1` if any machine failed or fatal exception occurred
- Script pauses for Enter key, then exits with final code.

---

## MSI Exit Codes Mapped in Script

Handled by `Get-MSIExitDescription`:
- `0` Success
- `1641` Success, restart initiated
- `3010` Success, reboot required
- `1601` Installer service unavailable
- `1602` User cancelled
- `1603` Fatal error
- `1618` Another install in progress
- `1619` Package cannot be opened
- `1625` Blocked by policy
- `1632` Temp folder issue
- `1633` Platform unsupported
- `1638` Product version already installed
- default: unknown code

---

## Custom Function Catalog (Script-Defined)

- `Main`
- `Initialize-RunLog`
- `Write-Log`
- `Get-Confirmation`
- `ConvertTo-Hostname`
- `Test-ComputerInAD`
- `Test-ComputerOnline`
- `Resolve-ComputerIPAddresses`
- `Test-ComputerWinRM`
- `Get-ValidatedSingleHostname`
- `Get-ExecutionMode`
- `Get-PowerShell7Details`
- `Test-IsInteractiveSession`
- `Test-IsLocalAdministrator`
- `Read-YesNoChoice`
- `Install-PowerShell7ViaWindowsUpdate`
- `Invoke-PowerShell7Relaunch`
- `Invoke-PowerShell7Bootstrap`
- `Get-InstallerFiles`
- `Test-InstallerFilesExist`
- `Get-MSIFile`
- `Request-Credentials`
- `Test-RemoteAdmin`
- `Test-CurrentUserDomainAuth`
- `Test-DomainCredential`
- `Get-ValidatedCredentialForDomain`
- `Get-EffectiveCredentialIdentity`
- `Get-CredentialAfterUserConfirmation`
- `Invoke-AuthorizationCanaryCheck`
- `Find-BatchMachineFile`
- `Get-MachineNamesFromFile`
- `Get-MachineAvailabilityReport`
- `Write-MachineStateValidationSummary`
- `Get-MSIExitDescription`
- `Copy-MSIWithRetry`
- `Get-PendingRebootState`
- `Get-RebootRequirementEvaluation`
- `Remove-RemoteMSI`
- `New-Result`
- `Invoke-MachineInstall`
- `Read-RetryChoice`
- `Get-ChunkedArrays`
- `Update-BatchFileForSuccesses`
- `Invoke-Deployment`
- `Get-FinalResultPerMachine`
- `Write-Summary`

### Nested/local helper functions
- `Add-CandidatePath` (inside `Get-PowerShell7Details`)
- `Write-SpinnerStatusLine`, `Update-ValidationSpinner` (inside `Get-MachineAvailabilityReport`)
- `Get-ExitDesc`, `Get-RebootState`, `Get-RebootEval` (inside parallel block of `Invoke-Deployment`)

---

## Built-in PowerShell Cmdlets Used

- `Get-Date`
- `Split-Path`
- `Join-Path`
- `Test-Path`
- `New-Item`
- `Add-Content`
- `Write-Host`
- `Read-Host`
- `Get-Command`
- `Get-ChildItem`
- `Get-Content`
- `Set-Content`
- `Get-Item`
- `Get-ItemProperty`
- `Resolve-DnsName`
- `Test-Connection`
- `Test-WSMan`
- `New-PSSession`
- `Invoke-Command`
- `Remove-PSSession`
- `Copy-Item`
- `Remove-Item`
- `Start-Process`
- `Start-Sleep`
- `Get-WmiObject`
- `Where-Object`
- `Sort-Object`
- `Select-Object`
- `Group-Object`
- `ForEach-Object` (including `-Parallel`)
- `Receive-Job`
- `Remove-Job`
- `Out-Null`

---

## Optional/Conditional Cmdlets and External Binaries

- `Get-ADComputer` (when ActiveDirectory module is available)
- `pwsh.exe` (PowerShell 7 relaunch target)
- `msiexec.exe` (remote installer execution)

---

## Security and Operational Notes for Domain Admins

- Requires WinRM/PowerShell Remoting availability on targets.
- Requires permissions sufficient for remote administration and install.
- Uses domain credential validation before deployment to fail fast.
- Canary authorization check prevents broad rollout with insufficient rights.
- Logs all key events to one per-run log for auditing.
- Supports resilient transfer retries and controlled retry prompts.
- Batch mode comments successful entries in source file to streamline reruns.
