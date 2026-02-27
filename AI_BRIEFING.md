# AI Agent Briefing: Install-RemoteMSI.ps1 Script

## Quick Context

This is a production PowerShell script (`Install-RemoteMSI.ps1`) located at `c:\Programs\Script\` that remotely installs MSI packages on Windows machines with comprehensive error handling, credential management, reboot detection, and logging.

**Owner**: Andrew Lucas  
**Last Modified**: February 26, 2026  
**PowerShell Version Required**: 5.1+

---

## What This Script Does

The script performs **silent remote MSI installation** on a single networked machine with full workflow:

1. **Validates hostname** against Active Directory/DNS
2. **Checks connectivity** (privilege-aware - ICMP for admins, TCP 5985 for non-admins)
3. **Prompts for MSI selection** (discovers in `C:\Downloads\`)
4. **Handles credentials** (tests current user first, prompts if needed)
5. **Copies MSI** to remote machine via PSSession
6. **Executes silent installation** (msiexec /quiet /norestart)
7. **Detects if reboot is required** (registry + WMI hybrid approach)
8. **Cleans up** (removes MSI on success, preserves on failure)
9. **Logs everything** (console + timestamped file with outcome indicator)

---

## Key Technical Details

### Configuration Variables
```powershell
$LocalMSIPath = 'C:\Downloads'           # Source MSI folder (user selects from here)
$RemoteTempPath = 'C:\Temp'              # Where MSI is copied on remote machine
$MaxCredentialAttempts = 2               # Failed login attempts before abort
$LogPath = $null                         # Set dynamically after hostname known
```

### Main Functions (Know These)

| Function | Purpose |
|----------|---------|
| `Write-Log` | Output to console (color-coded) + log file (timestamped) |
| `Test-ComputerInAD` | Validates hostname exists via DNS/AD |
| `Test-ComputerOnline` | Tests connectivity via TCP 5985 or ICMP (privilege-aware) |
| `Get-ValidatedHostname` | Prompts user for hostname with validation loop |
| `Get-SessionCredentials` | Tests current user, prompts for credentials if needed |
| `Get-MSIFile` | Finds MSI files in C:\Downloads, prompts if multiple |
| `Install-RemoteMSI` | Executes msiexec on remote machine, returns exit code |
| `Test-PendingReboot` | Checks registry + WMI for reboot requirements |
| `Remove-RemoteFile` | Deletes MSI from remote machine |
| `Main` | Orchestrates entire 9-phase workflow |

### Script Phases

```
PHASE 1: INPUT VALIDATION
  └─ Gets hostname via Get-ValidatedHostname (AD/DNS check)

PHASE 1.5: CONNECTIVITY CHECK (non-blocking for non-admins)
  └─ Tests if machine reachable (skipped if non-admin)

PHASE 2: MSI SELECTION
  └─ User chooses from MSIs in C:\Downloads

PHASE 3: CREDENTIAL HANDLING
  └─ Tests current user, prompts if insufficient permissions

PHASE 4: REMOTE SESSION CREATION
  └─ Creates PSSession to target machine

PHASE 5: REMOTE ENVIRONMENT PREP
  └─ Ensures C:\Temp exists on remote machine

PHASE 6: MSI COPY
  └─ Copy-Item to remote machine via PSSession

PHASE 7: INSTALLATION EXECUTION
  └─ msiexec /quiet /norestart, captures exit code

PHASE 8: REBOOT DETECTION
  └─ Registry + WMI checks for pending reboot

PHASE 9: CLEANUP & LOGGING
  └─ Remove MSI (success) or keep (failure), rename log file
```

### Exit Codes
- `0` = Success (no reboot needed)
- `1` = Failure (check log file)
- MSI exit code `3010` = Success + reboot required

### Logging
- **Console**: Color-coded (GREEN=success, RED=error, YELLOW=warning, CYAN=info)
- **File**: `C:\Downloads\[ComputerName]_[yyyyMMdd_HHmmss]_[Success|Failure|Incomplete].log`
- **Timestamps**: Every message logged with `yyyy-MM-dd HH:mm:ss`

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
- `Get-SessionCredentials` creates a test `New-PSSession`
- If successful, credentials are valid
- Retry loop (max 2 attempts) for incorrect password entry
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

- `Get-Credential` returns `PSCredential` object
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

### Issue: Credentials prompting failing with "Current user has access" when they don't
**Root Cause**: Test PSSession creation succeeds with default context but fails during actual install  
**Fix**: Gets credentials via `Get-SessionCredentials → Get-ValidatedCredentials` with PSSession test

### Issue: Reboot status not detected
**Root Cause**: Single detection method incomplete  
**Fix**: Hybrid method (registry + WMI) catches edge cases

### Issue: MSI stays on remote machine even after success
**Root Cause**: `Remove-RemoteFile` has error, but installation succeeded  
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

**Issue 3**: Better reboot detection needed  
**Solution**: Implemented hybrid registry + WMI approach  
**Code**: `Test-PendingReboot` function  

---

## External Dependencies

✅ **Built-in PowerShell Cmdlets** (No external modules required):
- `New-PSSession` / `Remove-PSSession` / `Invoke-Command` (remoting)
- `Get-Credential` (credential UIHandling)
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
c:\Downloads\                               ← Default MSI source folder
c:\Downloads\[ComputerName]_[timestamp]_*.log ← Generated log files
```

---

## Getting Help on Specific Areas

- **Understanding remoting**: Read `Invoke-Command` and `New-PSSession` in `Get-Help`
- **Credential handling**: See `Get-SessionCredentials` and `Get-ValidatedCredentials` functions
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
