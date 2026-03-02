# Remote MSI/MSIX Installation Script

## Overview
`Install-RemoteMSI.ps1` installs MSI/MSIX packages to remote Windows machines in either single-machine or batch mode.

Key behaviors:
- Credential validation happens early using a probe machine
- Credential prompts use terminal `Read-Host` (no GUI popup)
- Hostnames are sanitized before use
- Batch files (`.txt`/`.csv`) are auto-discovered from script directory or manually supplied
- One aggregated log is generated per script run

---

## Features

### Security and Validation
- Credential-first validation (before heavy batch pre-processing)
- Terminal-only secure credential entry (`Read-Host -AsSecureString`)
- Hostname sanitization for single and batch modes
- AD/DNS and online pre-validation for batch execution lists
- Startup runtime check before prompts (PS host/version capability)

### Batch Execution
- Runtime mode selection: single machine or batch
- Batch input from first column only (no header required)
- Parallel throttle prompt (`1` = sequential)
- Retry rounds apply only to failed machines after each batch
- Retry prompts show attempt count, error code, and error description

### File Transfer and Install
- Installer discovery in script directory (`*.msi`, `*.msix`)
- Transfer retry delays: `5s`, `10s`, `30s`, `60s`
- After transfer retries fail, operator can retry cycle or abort
- MSI exit code mapping to human-readable meanings
- MSI is preserved on non-corruption failures for future retry

### Logging and State
- One log per script run: `Logs\Deployment_[yyyyMMdd_HHmmss].log`
- PS5→PS7 relaunch reuses the same log file path (no parent/child split logs)
- Console and file logging with timestamps and severity
- Successful batch machines are commented out in source list file

---

## Requirements
- PowerShell 5.1+ (PowerShell 7+ recommended for parallel runspace mode)
- WinRM enabled on target machines
- Administrative rights on target machines for installation
- MSI/MSIX file in same directory as `Install-RemoteMSI.ps1`
- Local administrator rights on the orchestrator machine are required only for optional PS7 install via Windows Update/WSUS

---

## Usage

```powershell
.\Install-RemoteMSI.ps1
```

Optional switch for unattended execution:
```powershell
.\Install-RemoteMSI.ps1 -NonInteractive
```

Interactive flow:
1. Select mode (`Single` or `Batch`)
2. Provide target hostname or machine list file
3. Validate credentials against probe machine
4. Select installer file
5. Run execution (`parallel threads` prompt shown for batch)
6. Handle retry prompts for failed machines only

---

## Exit Codes
- `0` = run completed with no final machine failures
- `1` = one or more final machine failures, or fatal script error

---

## Notes
- Parallel execution path uses PowerShell 7 runspaces. On PowerShell 5.1, requested parallel throttle falls back to sequential with a warning.
- Runtime check occurs at script startup. If PS7+ is already installed, install is skipped and operator can relaunch into `pwsh` (default yes).
- If PS7+ is missing in interactive runs, script can attempt installation using the configured Windows Update service (WSUS/Microsoft Update policy path).
- If no approved/applicable PS7 update is available, install fails, or run is unattended, script continues with sequential fallback behavior.
- `-NonInteractive` suppresses runtime prompts where applicable and uses fallback behavior.
- Quiet MSI execution does not provide reliable real-time percentage progress back to caller; status is tracked operationally as running/completed with exit code.
