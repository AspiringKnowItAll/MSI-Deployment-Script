# AI Agent Briefing: Install-RemoteMSI.ps1 Script

## Quick Context

This is a production PowerShell script (`Install-RemoteMSI.ps1`) that remotely installs MSI/MSIX packages on Windows machines with comprehensive error handling, credential management, reboot detection, batch handling, and logging.

**Owner**: Andrew Lucas  
**Last Modified**: March 2, 2026  
**PowerShell Version Required**: 5.1+

---

## What This Script Does

The script performs **silent remote MSI/MSIX installation** with two operator modes:

1. **Single-machine mode** (interactive hostname input)
2. **Batch mode** (CSV/TXT machine list discovery and parsing)

Core workflow:

1. **Validates credentials first** using a probe machine
2. **Sanitizes hostnames** before validation/use
3. **Validates machine candidates** against AD/DNS and online status (batch pre-validation)
4. **Prompts for installer selection** from script directory
5. **Copies installer with retry policy** (5s/10s/30s/60s)
6. **Executes silent installation** (`msiexec /quiet /norestart`)
7. **Maps MSI exit codes** to human-readable meaning
8. **Handles retries per failed machine only** after each batch finishes
9. **Preserves MSI on non-corruption failures** for later retries
10. **Aggregates all activity into one run log file**
11. **Comments successful machines in source file** for rerun skip behavior

---

## Key Technical Details

### Configuration Variables
```powershell
$ScriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path  # Directory containing the PS1 file
$LocalMSIPath = $ScriptDirectory  # MSI/MSIX folder (same as script directory)
$RemoteTempPath = 'C:\Temp'              # Where MSI is copied on remote machine
$LogDirectory = Join-Path -Path $ScriptDirectory -ChildPath 'Logs'  # Logs folder next to script
$MaxCredentialAttempts = 2               # Failed login attempts before abort
$RunLogPath = <optional>                 # Reused during PS5→PS7 relaunch to keep one aggregated log
```

### Main Functions (Know These)

| Function | Purpose |
|----------|---------|
| `Write-Log` | Output to console (color-coded) + log file (timestamped) |
| `Test-InstallerFilesExist` | Verifies MSI/MSIX files exist in script directory before proceeding |
| `Test-ComputerInAD` | Validates hostname exists via DNS/AD |
| `Test-ComputerOnline` | Tests connectivity via TCP 5985 or ICMP (privilege-aware) |
| `Get-ValidatedSingleHostname` | Prompts user for hostname and sanitizes input |
| `Request-Credentials` | Prompts user for credentials using terminal `Read-Host` (no GUI dialog) |
| `Get-ValidatedCredentialForProbe` | Validates credentials first, before heavy processing |
| `Find-BatchMachineFile` | Discovers CSV/TXT machine file in script directory or accepts alternate path |
| `Get-MachineNamesFromFile` | Parses first column/no-header file and sanitizes hostnames |
| `Get-ValidatedBatchMachines` | AD + online pre-validation for batch execution list |
| `Copy-MSIWithRetry` | Applies transfer retry delays (5/10/30/60) then prompts retry/abort |
| `Invoke-Deployment` | Executes batches with retry rounds on failed machines only |
| `Update-BatchFileForSuccesses` | Comments successful machine rows in source list |
| `Get-InstallerFiles` | Enumerates MSI/MSIX files in script directory with extension filtering |
| `Get-MSIFile` | Finds MSI and MSIX files in script directory, prompts if multiple |
| `Get-PowerShell7Details` | Detects local PS7 from command, common install paths, and App Paths registry |
| `Install-PowerShell7ViaWindowsUpdate` | Optional WSUS/Microsoft Update-based PS7 install path |
| `Invoke-PowerShell7Relaunch` | Relaunches script in `pwsh` and reuses same run log path |
| `Invoke-PowerShell7Bootstrap` | Startup runtime gate before normal prompts |
| `Read-RetryChoice` | Prompt for retry/skip/abort for failed machines |
| `Test-PendingReboot` | Checks registry + WMI for reboot requirements |
| `Remove-RemoteMSI` | Deletes MSI from remote machine |
| `Main` | Orchestrates single or batch workflow |

### Script Phases

```
PHASE 0: INSTALLER FILE VERIFICATION
  └─ Verifies MSI/MSIX files exist in script directory, exits with helpful message if not

PHASE 1: MODE + TARGET SOURCE SELECTION
  └─ Select Single or Batch mode, collect hostname or machine list file

PHASE 2: CREDENTIAL VALIDATION (FIRST)
  └─ Validate once against probe machine before full list validation/execution

PHASE 3: MACHINE SANITIZATION + VALIDATION
  └─ Single: sanitize hostname
  └─ Batch: sanitize all names, then pre-validate AD/DNS + online

PHASE 4: MSI/MSIX SELECTION
  └─ User chooses from MSI/MSIX files in script directory

PHASE 5: REMOTE SESSION CREATION
  └─ Creates PSSession to target machine

PHASE 6: REMOTE ENVIRONMENT PREP
  └─ Ensures C:\Temp exists on remote machine

PHASE 7: MSI COPY WITH RETRIES
  └─ Copy-Item to remote machine via PSSession, delay sequence 5/10/30/60

PHASE 8: INSTALLATION EXECUTION
  └─ msiexec /quiet /norestart, captures exit code

PHASE 9: REBOOT DETECTION
  └─ Registry + WMI checks for pending reboot

PHASE 10: CLEANUP, RETRIES, AND LOGGING
  └─ Remove MSI on success (or corruption error), keep on other failures
  └─ Retry failed machines only after batch completion
  └─ Append aggregated run summary to one log file
```

### Exit Codes
- `0` = Success (no reboot needed)
- `1` = Failure (check log file)
- MSI exit code `3010` = Success + reboot required

### Logging
- **Console**: Color-coded (GREEN=success, RED=error, YELLOW=warning, CYAN=info)
- **File**: `Logs\Deployment_[yyyyMMdd_HHmmss].log` (one log file per script run)
- **Timestamps**: Every message logged with `yyyy-MM-dd HH:mm:ss`

---

## Decision Log (March 2, 2026)

These are hard requirements and operator preferences that must be preserved in future edits:

1. **Credential validation must happen first**
  - Validate credentials before full machine-list validation/building work.
  - Rationale: avoid spending time preparing batch lists when credentials are invalid.

2. **Credential input method is terminal-based `Read-Host` only**
  - No GUI credential dialogs.
  - Rationale: GUI popups were unreliable in prior runs; terminal prompts are deterministic.

3. **Single-machine mode also requires hostname sanitization**
  - Rationale: keep parity with batch sanitization and avoid malformed input.

4. **Batch file rules**
  - Scan script directory first for CSV/TXT candidates.
  - Prompt to use detected file or provide alternate path.
  - Parse first column only; do not assume header row.

5. **Batch validation boundaries**
  - Pre-validate AD/DNS and online status before execution.
  - Execution workers should not redo those list-building validations.

6. **Transfer retry policy**
  - Fixed delay sequence: 5s, 10s, 30s, 60s.
  - Then prompt operator to retry transfer cycle or abort.

7. **Failure handling scope**
  - A failure on one machine must not pause other machines in the same batch.
  - After batch completes, retry prompts apply only to failed machine(s).
  - Include attempt count, error code, and human-readable reason in prompt.

8. **MSI retention policy**
  - Keep MSI on remote machine for failures that are not corruption/package-open errors.
  - Remove MSI on success.

9. **Rerun behavior through source file mutation**
  - Comment out successful machines in source CSV/TXT so next script run skips them.
  - Rationale: avoid reprocessing machines already upgraded.

10. **Documentation discipline for agents**
   - Update this briefing with decisions/preferences and rationale when planning/behavior changes.
   - If a new requirement conflicts with previous decisions, explicitly surface the conflict to the user.

11. **PowerShell 7 startup runtime gate**
  - Script must check host/runtime at startup before normal operator prompts.
  - If running in non-PS7 host and `pwsh` 7+ is present, prompt to relaunch in `pwsh` (default = relaunch).
  - If operator declines relaunch, continue run with sequential fallback where parallel is requested.

12. **PowerShell 7 install option when missing**
  - If `pwsh` 7+ is not present and run is interactive, offer optional install attempt via configured Windows Update service (WSUS/Microsoft Update policy path).
  - If `pwsh` 7+ is already installed, skip installation path entirely.
  - If install attempt cannot find approved/applicable update or fails, do not fail deployment; continue with sequential fallback.
  - In non-interactive/unattended runs, skip install attempt and continue sequential fallback.

---

## Important Design Decisions

### 1. Privilege-Aware Connectivity Test
**Why**: Non-admin users can't run ICMP ping on Windows without elevation

**How it works**:
- Checks if user is admin: `[Security.Principal.WindowsIdentity]::GetCurrent().Groups -contains 'S-1-5-32-544'`
- Admin users: Full connectivity test (TCP 5985 + fallback to ICMP)
- Non-admin users: Skip connectivity test, let credential validation handle verification

**Important**: Moved connectivity check to **AFTER** hostname validation but **BEFORE** MSI selection. This allows non-admins to proceed but still validates that the machine exists in AD first.

### 2. Credentials Validated via PSSession Test
**Why**: Only real way to know if credentials work on the remote machine

**How it works**:
- `Get-ValidatedCredentialForProbe` creates a test `New-PSSession` and additionally checks the remote session for local administrator membership
- If successful and admin, credentials are valid
- Retry loop (max 2 attempts) for incorrect password entry
- If current account can connect but isn’t admin, user is prompted right away
- Credential prompts use terminal `Read-Host` (approved verb `Request-Credentials`). This approach:
  - Always works when run from double-click or command line
  - Uses `Read-Host -AsSecureString` for password input (same security as `Get-Credential` GUI)
  - Never attempts GUI dialog
  - Guarantees a prompt appears in the console window
- No credentials = use current user
- `PSCredential` object never written to disk (SecureString in memory only)

### 3. Hybrid Reboot Detection (Registry + WMI)
**Why**: Single method (registry only or WMI only) can miss pending reboots

**How it works**:
- Registry Path 1: `HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations`
- Registry Path 2: `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`
- WMI: `Win32_OperatingSystem.RebootRequired` property
- Returns `$true` if ANY of these indicate reboot needed

### 4. MSI Cleanup Strategy
**Why**: Clean up on success to reduce disk space; preserve on failure for troubleshooting

**How it works**:
- Success path: Remove MSI from remote machine
- Failure path: Keep MSI on remote machine (user can SSH in and check error codes, logs, etc.)
- Log file renamed: `_Incomplete.log` → `_Success.log` or `_Failure.log`

---

## Credential Security & Privacy

⚠️ **CRITICAL**: This script **never stores, logs, or persists credentials**

- Credential prompting uses a simple "approved verb" function `Request-Credentials` that uses terminal `Read-Host` prompts and `Read-Host -AsSecureString` for password entry
- Passwords stored as `SecureString` (encrypted in memory)
- Used only for `New-PSSession` and `Invoke-Command`
- Auto-purged when script ends (garbage collection)
- Never appears in logs, console output, or files

---

## Common Issues & Solutions

### Issue: Non-admin user sees ""Computer not responding to connectivity test""
**Root Cause**: ICMP (ping) requires admin privileges on Windows  
**Fix**: Already implemented - moved connectivity check to after hostname validation, skipped for non-admin users  
**Code Location**: Lines ~513-525 in Main function

### Issue: Credentials validate initially but fail later during install
**Root Cause**: Probe checks can differ from later remote operations if privileges are insufficient  
**Fix**: `Get-ValidatedCredentialForProbe` validates session and remote admin role before deployment steps

### Issue: Running script by double-click never shows credential prompt (no GUI)
**Root Cause**: When PowerShell is started fresh from Explorer, a GUI credential dialog may not render or may not be interactive. We simplified by using terminal prompts exclusively.
**Fix**: Replaced all credential prompts with terminal-based `Request-Credentials` function using `Read-Host` and `Read-Host -AsSecureString`. This guarantees the prompt appears in the console window and works in any context.
**Security**: `Read-Host -AsSecureString` encrypts the password in memory, same as `Get-Credential` GUI.

### Issue: Reboot status not detected
**Root Cause**: Single detection method incomplete  
**Fix**: Hybrid method (registry + WMI) catches edge cases

### Issue: MSI stays on remote machine even after success
**Root Cause**: `Remove-RemoteMSI` has error, but installation succeeded  
**Solution**: Non-blocking error - installation succeeded, just verify cleanup manually

---

## How to Modify This Script

### Add a New Phase/Feature
1. Add logic in appropriate phase section (clearly marked with comments)
2. Follow existing error handling pattern (try-catch around remote operations)
3. Use `Write-Log` for all output (don't use `Write-Host` directly)
4. Test with both admin and non-admin user contexts
5. Update README.md documentation

### Change MSI Source Directory
- Edit `$LocalMSIPath` variable at top of script
- Update README.md Configuration section

### Add Support for Batch/Multiple Machines
- Wrap main workflow in `foreach($Computer in $ComputerList)` loop
- Create aggregated report at end
- Handle session cleanup per machine
- Update credential handling to be per-machine

### Add Pre/Post-Installation Scripts
- Add new parameter section after PHASE 8: REBOOT DETECTION
- Execute scripts via `Invoke-Command` on remote machine
- Log execution status

---

## Testing Checklist

Before deployment or modification, verify:

- [ ] Admin context: Script runs end-to-end successfully
- [ ] Non-admin context: Script runs end-to-end successfully (connectivity check skipped)
- [ ] Invalid hostname: Properly rejected with message
- [ ] Invalid credentials: Retry loop works, max 2 attempts
- [ ] Multiple MSIs: User can select correct one
- [ ] Installation success (exit code 0): MSI removed, log says _Success
- [ ] Installation success with reboot (exit code 3010): MSI removed, reboot status detected
- [ ] Installation failure: MSI preserved, log says _Failure
- [ ] Logging: Console and file output match, timestamps present
- [ ] Color-coded output: SUCCESS=Green, ERROR=Red, WARNING=Yellow, INFO=Cyan

---

## Quick Reference: What Changed & Why

### Recent Changes (Feb 2026)

**Issue 1**: Non-admin users couldn't run script (connectivity test failed)  
**Solution**: Made connectivity test privilege-aware + moved after hostname validation  
**Code**: `Test-ComputerOnline` with admin privilege check in Main function  

**Issue 2**: `$InstallTimeout` variable defined but never used  
**Solution**: Removed unused variable  
**Code**: Deleted `$InstallTimeout = 300` from configuration  

**Issue 4**: Script would silently connect with non‑admin credentials when launched from Explorer, then fail later during installation without ever prompting the user.  
**Solution**: `Get-ValidatedCredentialForProbe` now verifies remote admin membership and forces a credential prompt if the current account cannot perform the required operations.  
**Code**: Updated function implementation earlier in this briefing

**Issue 3**: Better reboot detection needed  
**Solution**: Implemented hybrid registry + WMI approach  
**Code**: `Test-PendingReboot` function  

---

## External Dependencies

✅ **Built-in PowerShell Cmdlets** (No external modules required):
- `New-PSSession` / `Remove-PSSession` / `Invoke-Command` (remoting)
- `Read-Host` / `Read-Host -AsSecureString` (credential input handling)
- `Copy-Item` (file transfer)
- `Test-Connection` (connectivity)
- `Resolve-DnsName` (DNS validation)
- `Get-WmiObject` (reboot detection)
- `Add-Content` (logging)

⚠️ **Requirements on Remote Machine**:
- PowerShell 5.1+ (usually present)
- WinRM enabled and accessible
- Admin access via provided credentials

---

## File Locations

```
c:\Programs\Script\Install-RemoteMSI.ps1    ← Main script
c:\Programs\Script\README.md                ← User documentation
c:\Programs\Script\AI_BRIEFING.md           ← This file
c:\Programs\Script\*.msi or *.msix          ← MSI/MSIX files to install (same directory as script)
c:\Programs\Script\Logs\                    ← Log files directory (created automatically)
c:\Programs\Script\Logs\[ComputerName]_[timestamp]_*.log ← Generated log files
```

---

## Getting Help on Specific Areas

- **Understanding remoting**: Read `Invoke-Command` and `New-PSSession` in `Get-Help`
- **Credential handling**: See `Request-Credentials` and `Get-ValidatedCredentialForProbe` functions
- **Logging strategy**: Review `Write-Log` function
- **Reboot detection**: Study `Test-PendingReboot` function
- **Error flow**: Trace through `Main` function phase-by-phase

---

## Next Steps for Agents

When working on this script:

1. **Read this file first** to understand context and design
2. **Check README.md** for user-facing documentation
3. **Review the Main function** to understand workflow
4. **Test in both admin and non-admin contexts** before finalizing
5. **Update both README.md and this file** if making significant changes
6. **Run the testing checklist** before marking complete

---

**End of Briefing**

For questions about functionality, implementation details, or modifications, refer to inline script comments and the README.md documentation.
