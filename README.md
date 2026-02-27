# Remote MSI Installation Script

## Overview

`Install-RemoteMSI.ps1` is a production-ready PowerShell script that remotely installs Windows MSI packages on networked machines with comprehensive error handling, credential management, reboot detection, and detailed logging.

**Key Benefit:** Eliminates manual installation visits and provides full visibility into installation status and system reboot requirements.

---

## Features

### Input Validation & Security
- **Early file validation** - verifies MSI/MSIX files exist before proceeding, with helpful error message
- **Interactive hostname input** with validation against DNS and Active Directory
- **Connectivity testing** with privilege-aware fallback (TCP port 5985 for non-admin users, ICMP for admin users)
- **Dynamic credential handling** – script will now not only verify that credentials can establish a session but also confirm that the account is a **local administrator** on the target. If the current user can connect but lacks admin rights, the tool will prompt immediately for alternate credentials using simple terminal prompts.
  **Security Note**: Terminal prompts with `Read-Host -AsSecureString` are just as secure as the GUI `Get-Credential` dialog – passwords are encrypted in memory and never displayed on screen.
- **Credential security** - uses PowerShell `PSCredential` objects with SecureString (never written to disk)
- **Retry logic** - up to 2 failed credential attempts before aborting

### MSI Management
- **Automatic MSI/MSIX discovery** in script directory
- **Interactive selection** if multiple files exist
- **Silent installation** using `msiexec.exe /quiet /norestart`
- **MSI cleanup** on success; preserved on failure for troubleshooting
- **Exit code interpretation** - correctly handles code 3010 (success but reboot required)

### Reboot Detection
Uses **hybrid detection approach** for maximum reliability:
- **Registry checks**: 
  - `HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations`
  - `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`
- **WMI check**: `Win32_OperatingSystem.RebootRequired` property
- Notifies user of any required reboots

### Remote Session Management
- **PSSession-based remoting** - persistent connection for reliability
- **Proper session cleanup** - automatically removes sessions on completion or error
- **Using scope** - leverages `Using:` scope modifier for variable passing to remote commands
- **Error handling** - comprehensive try-catch blocks around each operation

### Logging & Output
- **Dual output**: Console (color-coded) + timestamped log file
- **Color-coded messages**:
  - 🟢 **GREEN** (SUCCESS) - Operation completed successfully
  - 🔴 **RED** (ERROR) - Operation failed
  - 🟡 **YELLOW** (WARNING) - Non-critical issue or requires attention
  - 🔵 **CYAN** (INFO) - Informational messages
- **Smart logging** - log file created at start, renamed based on outcome
- **Log naming**: `[ComputerName]_[yyyyMMdd_HHmmss]_[Success|Failure|Incomplete].log`
- **Log location**: `Logs\` folder (created automatically next to the script)

---

## Requirements

### System Requirements
- **PowerShell**: 5.1 or higher (Windows PowerShell or PowerShell 7+)
- **OS**: Windows Server 2012 R2+ or Windows 7 SP1+
- **Network**: WinRM enabled and accessible on target machines (port 5985 HTTP or 5986 HTTPS)

### Permissions
- **Source machine**: Can run as standard user (non-admin) if target credentials have admin access
- **Target machine**: Admin credentials required for MSI installation
- **Best practice**: Run as admin on source if possible (enables ICMP connectivity test)

### Prerequisites
- MSI or MSIX file placed in the same directory as the `Install-RemoteMSI.ps1` script
- Target machine accessible via network
- Target machine in Active Directory (or resolvable via DNS)
- WinRM service running on target machine
- PowerShell remoting enabled (typically `Enable-PSRemoting -Force` on target)

---

## Usage

### Basic Execution

```powershell
# Run the script (PowerShell 5.1+ required)
.\Install-RemoteMSI.ps1

# Or if you're in a different directory
& 'C:\Programs\Script\Install-RemoteMSI.ps1'
```

### Interactive Prompts

The script will guide you through:

1. **Hostname Entry**
   ```
   Enter the hostname of the target machine: SERVER01
   ```
   - Validates hostname exists in DNS/AD
   - Skips online test for non-admin users
   - Admin users see connectivity status

2. **MSI Selection** (if multiple MSI files exist)

3. **Credential Entry** (terminal prompts)
   ```
   Administrator credentials required for SERVER01
   User: DOMAIN\AdminUser
   Password: ••••••••••••
   ```
   - Credentials are always entered directly in the terminal window using keyboard input
   - No GUI dialog is used (ensures tool works when double-clicked from Explorer)
   - Password is encrypted as `SecureString` in memory (same security as `Get-Credential`)
   - Never displayed on screen, never logged to file

   ```
   Found 3 MSI files. Please select one:
     [1] Application-v1.0.0.msi
     [2] Application-v1.0.1.msi
     [3] Application-v2.0.0.msi
   
   Enter the number of the MSI to install [1-3]: 2
   ```

3. **Credential Entry** (if needed)
   ```
   Enter credentials for DOMAIN
   User: DOMAIN\AdminUser
   Password: ••••••••••••
   ```
   - Automatically validates credentials by testing PSSession creation
   - Retries up to 2 times on failure
   - Uses current user if no credentials needed

### Example Output

*If the first attempt to open a remote session fails with access denied, the script will automatically prompt for alternate credentials and retry.*


```
======================================================================
Remote MSI Installation Tool
======================================================================

2026-02-26 14:32:15 [CYAN] Validating computer 'SERVER01' against Active Directory...
2026-02-26 14:32:16 [GREEN] Computer 'SERVER01' found in DNS.
2026-02-26 14:32:16 [INFO] Note: Running as non-admin. Skipping ICMP connectivity test.
...
2026-02-26 14:35:42 [GREEN] Installation completed successfully (no restart required).
...
======================================================================
Installation Summary
======================================================================
Status: SUCCESS - No Reboot Required
Log File: Logs\SERVER01_20260226_143242_Success.log
======================================================================
```

---

## Execution Behavior When Double‑Clicked

If you run the script by double‐clicking it in Explorer or by using "Run with
PowerShell" the tool will:

- Prompt for hostname and validate it exactly the same as when run in a
  console.
- Automatically ask for administrator credentials in the terminal window if the current user can
  connect but lacks local admin rights on the target.
- Use only straightforward terminal prompts (type username, type password) - no GUI dialogs.
- Pause at the end of execution so the new window does not close immediately.

You will see a final message `Press Enter to close this window...` which can be
ignored when running from an existing terminal.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success - installation completed, MSI removed, no reboot needed |
| `1` | Failure - installation error, MSI preserved on remote machine, check log file |

---

## Log File Reference

### Location
`Logs\[ComputerName]_[yyyyMMdd_HHmmss]_[Success|Failure|Incomplete].log` (folder created automatically next to the script)

### Example Log Contents
```
2026-02-26 14:32:15 [INFO] Installation session started for SERVER01
2026-02-26 14:32:16 [SUCCESS] Hostname validation successful.
2026-02-26 14:32:18 [INFO] Scanning for MSI and MSIX files in 'C:\Programs\Script'...
2026-02-26 14:32:18 [SUCCESS] Found MSI file: MyApp-v2.0.msi
2026-02-26 14:32:22 [INFO] Checking if current user can access remote machine...
2026-02-26 14:32:25 [WARNING] Unable to connect using current user: Access is denied.
2026-02-26 14:32:25 [INFO] Please provide credentials to authenticate.
2026-02-26 14:32:35 [SUCCESS] Credentials validated successfully.
2026-02-26 14:32:38 [SUCCESS] Remote session created successfully.
2026-02-26 14:32:38 [INFO] Preparing remote environment...
2026-02-26 14:32:39 [SUCCESS] Remote temp directory ready.
2026-02-26 14:32:39 [INFO] Copying MSI to remote machine (C:\Temp\MyApp-v2.0.msi)...
2026-02-26 14:32:42 [SUCCESS] MSI copied successfully.
2026-02-26 14:32:42 [INFO] Starting silent MSI installation on remote machine...
2026-02-26 14:35:41 [INFO] MSI installation completed with exit code: 0
2026-02-26 14:35:41 [SUCCESS] Installation completed successfully (no restart required).
2026-02-26 14:35:41 [INFO] Checking for pending reboot indicators...
2026-02-26 14:35:42 [SUCCESS] No pending reboot required.
2026-02-26 14:35:42 [INFO] Removing MSI from remote machine...
2026-02-26 14:35:43 [SUCCESS] MSI removed successfully.
2026-02-26 14:35:43 [SUCCESS] Installation SUCCESSFUL on SERVER01
```

---

## Troubleshooting

### Problem: "Computer not found in DNS"
- **Cause**: Hostname doesn't exist or is not resolvable
- **Solution**: Verify hostname is correct, check DNS settings, ensure machine is on network

### Problem: "Not responding to connectivity test" (Admin users only)
- **Cause**: Machine offline, firewall blocking ICMP, or WinRM disabled
- **Solution**: Verify machine is online, check firewall rules, enable WinRM on target

### Problem: "Failed to validate credentials"
- **Cause**: Incorrect username/password or user doesn't have necessary permissions
- **Solution**: Verify credentials are correct, ensure user is admin on target machine, check domain

### Problem: "Installation failed with exit code X"
- **Cause**: MSI installation error (code varies)
- **Solution**: Check MSI log files on remote machine (usually `%TEMP%\MSI*.log`), verify MSI compatibility with target machine

### Problem: "Error removing MSI" (non-critical warning)
- **Cause**: File already deleted or permission issue
- **Solution**: Verify cleanup manually, check logs for specific error, installation still succeeded

### Problem: Non-admin user can't run script
- **Cause**: User doesn't have admin rights to run script
- **Solution**: Run as admin, OR provide credentials with elevated privileges when prompted during script execution

---

## Configuration

### Modifying Paths

Edit these variables in the script if needed:

```powershell
$RemoteTempPath = 'C:\Temp'              # Temp directory on remote machine
$MaxCredentialAttempts = 2               # Failed credential attempts before abort
```

**Note**: MSI/MSIX files should be placed in the same directory as the `Install-RemoteMSI.ps1` script. The script automatically scans for `*.msi` and `*.msix` files there.

### MSI Silent Installation Flags

The script uses standard msiexec flags:
- `/i` - Install package
- `/quiet` - No UI prompts
- `/norestart` - Don't restart system

To modify these, edit the `Install-RemoteMSI` function's `msiexec.exe` command line.

---

## Best Practices

1. **Test First**: Run script on non-critical test machine before production use
2. **Run as Admin**: If possible, run script with admin privileges for full connectivity testing
3. **Validate Credentials**: Ensure target credentials have admin access on remote machines
4. **MSI Compatibility**: Verify MSI is compatible with target OS and architecture before installation
5. **Network Availability**: Ensure network connectivity to target machines is stable
6. **Log Review**: Always review log files for detailed error information
7. **Maintenance**: Clean up old log files periodically from the `Logs\` folder next to the script

---

## Architecture & Design

### Flow Diagram
```
User Input Validation
    ↓
Hostname & AD Validation
    ↓
Connectivity Check (privilege-aware)
    ↓
MSI Selection
    ↓
Current User Permission Check
    ↓
Credential Prompt (if needed)
    ↓
Credential Validation
    ↓
PSSession Creation
    ↓
Remote Environment Prep
    ↓
MSI Copy to Remote
    ↓
Silent Installation
    ↓
Reboot Detection
    ↓
Cleanup & Result Logging
    ↓
Session Removal
```

### Error Handling Strategy
- **Phase-based validation** - fails fast at each phase before committing changes
- **Try-catch blocks** - comprehensive error trapping with informative messages
- **Graceful degradation** - non-admin users skip privilege-intensive tests but continue
- **Session cleanup** - ensures PSSession is removed even on error
- **MSI preservation** - keeps MSI on remote machine on failure for troubleshooting

### Credential Security
- Uses PowerShell's native `PSCredential` class
- Passwords stored as `SecureString` (encrypted in memory)
- Never logged, never written to disk
- Credentials auto-purged when script ends
- Test connection validates credentials before using

---

## Microsoft Best Practices Implemented

✅ Use persistent PSSession for related commands  
✅ Proper session cleanup with `Remove-PSSession`  
✅ Error handling with try-catch around remote operations  
✅ Credential passed as PSCredential object  
✅ ArgumentList and `Using:` scope for variable passing  
✅ Timeout handling for long-running operations  
✅ User privilege detection for feature availability  
✅ No hardcoded credentials anywhere  
✅ Comprehensive error messages to console and log  

---

## Support & Future Enhancements

### Potential Enhancements
- Batch installation on multiple machines
- Scheduled installation at specific times
- Email notification on completion
- Integration with SCCM or UpdateServices
- Pre/post-installation script execution
- Rollback capability on failure

### Known Limitations
- Single machine per execution (batch mode not implemented)
- No support for non-Windows remote machines
- WinRM required (SSH remoting not implemented)
- MSI only (EXE installers not supported)

---

## Author & Version

- **Author**: Andrew Lucas
- **Assistant**: Claude Haiku 4.5 AI (VSCode Chat)
- **Version**: 1.0
- **Created**: February 26, 2026
- **Last Updated**: February 26, 2026

---

## License

This script is provided as-is for internal organizational use. Modify and distribute as needed for your environment.
