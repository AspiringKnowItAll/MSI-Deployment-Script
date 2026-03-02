# Remote MSI/MSIX Installation Script

## Overview
`Install-RemoteMSI.ps1` performs silent remote MSI/MSIX deployment to Windows machines in single-machine or batch mode.

Core behaviors:
- Validates credentials early using a probe machine
- Uses terminal-only credential prompts (`Read-Host`, no GUI dialogs)
- Sanitizes hostnames before use
- Auto-discovers batch source files (`.txt`, `.csv`) from script directory
- Supports transfer retry cycles and per-machine retry rounds
- Produces one aggregated run log per execution

---

## Features

### Security and Validation
- Credential-first workflow (before heavy batch processing)
- Remote admin verification during credential probe
- Hostname sanitization for both single and batch modes
- AD/DNS and online pre-validation for batch targets
- Runtime startup gate for PowerShell host/version capability

### Batch Execution
- Runtime selection: single machine or batch
- Batch parsing from first column (header not required)
- Configurable throttle (`1` = sequential)
- Parallel execution on PowerShell 7+
- Retry prompts apply only to failed machines after each batch

### File Transfer and Install
- Installer discovery from script directory (`*.msi`, `*.msix`)
- Transfer retry delays: `5s`, `10s`, `30s`, `60s`
- After retry exhaustion, operator can retry transfer cycle or abort
- Silent install via `msiexec /quiet /norestart`
- MSI/MSIX exit code mapping to human-readable descriptions
- MSI cleanup on success and on corruption/open-package failures (`1619`); preserved on other failures for troubleshooting

### Reboot Logic (Current Behavior)
- The `Reboot Required` result now means **install-caused reboot only**.
- Script still takes pre-install and post-install reboot snapshots, but pre-existing reboot state on the target machine is **not** counted as install-required reboot.
- Summary table displays reboot as simple `Yes`/`No`.

### Logging and State
- One log per run: `Logs\Deployment_[yyyyMMdd_HHmmss].log`
- PS5 → PS7 relaunch reuses the same run log path
- Color-coded console output + timestamped file output
- Successful batch machines are commented out in source list file for rerun efficiency

---

## Requirements
- PowerShell 5.1+ (PowerShell 7+ recommended for parallel mode)
- WinRM enabled and reachable on target machines
- Administrative rights on target machines
- MSI/MSIX installer in same directory as `Install-RemoteMSI.ps1`
- Local administrator rights on orchestrator only if attempting optional PS7 install via Windows Update/WSUS

---

## Usage

```powershell
.\Install-RemoteMSI.ps1
```

Unattended/non-interactive mode:
```powershell
.\Install-RemoteMSI.ps1 -NonInteractive
```

Interactive flow:
1. Select mode (`Single` or `Batch`)
2. Provide hostname or batch source file
3. Validate credentials with probe machine
4. Select installer file
5. Execute deployment (parallel prompt in batch mode)
6. Handle retry prompts for failed machines only

---

## Exit Codes
- `0` = run completed with no final machine failures
- `1` = one or more final machine failures, or fatal script error

---

## Notes
- Parallel path uses PowerShell 7 runspaces; PowerShell 5.1 falls back to sequential with warning.
- Startup host check runs before normal prompts.
- If PS7 is present, operator can relaunch into `pwsh` (default yes in interactive runs).
- If PS7 is missing (interactive), script can optionally attempt install through configured Windows Update service.
- If PS7 install is unavailable/fails, script continues with fallback behavior.
- `-NonInteractive` suppresses interactive runtime prompts where applicable.
- Quiet MSI execution does not provide reliable real-time progress percentages; status is tracked operationally by job state and final exit code.
