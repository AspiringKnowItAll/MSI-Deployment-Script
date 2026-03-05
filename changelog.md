# Changelog

## 2026-03-05

### Scope
- File changed: `Install-RemoteMSI.ps1`
- Purpose: validate/fix command and flag compatibility across Windows PowerShell 5.1 and PowerShell 7, and remove fragile runtime behavior.

### Changes Implemented

#### 1) Cross-version network reachability in `Test-ComputerOnline`
- Replaced invalid/host-specific `Test-Connection` usage that depended on unsupported parameter sets.
- Added a compatibility-first flow:
  - Try `Test-NetConnection -ComputerName <host> -Port 5985 -InformationLevel Quiet` when available.
  - Fallback to `.NET TcpClient` connect probe on port `5985`.
  - If TCP check fails/unavailable, fallback to `Test-Connection` with dynamic parameter detection:
    - `ComputerName` (PS5.1) vs `TargetName` (PS7)
    - `TimeoutSeconds` vs `TimeoutMilliseconds` when present.
- Result: avoids invalid flag usage while preserving intended behavior on both PowerShell versions.

#### 2) Fixed async socket cleanup bug (`TcpClient`)
- In the `.NET TcpClient` path, moved `EndConnect()` handling into cleanup so resources are finalized consistently.
- Added guarded cleanup around `AsyncWaitHandle.Close()`.
- Result: avoids leaked/unfinished async operation state during timeout/failure paths.

#### 3) Corrected summary banner output (`Write-Host` concatenation)
- Fixed 3 occurrences of:
  - `Write-Host "`n" + ('=' * 70)`
- Updated to:
  - `Write-Host ("`n" + ('=' * 70))`
- Result: ensures the full intended separator string is actually emitted.

#### 4) Added defensive assembly load for domain credential validation
- In `Test-DomainCredential`, added:
  - `Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction SilentlyContinue`
- Result: improves reliability where auto-loading may not occur predictably.

#### 5) Replaced PS7-incompatible WMI probe in reboot checks
- Updated reboot state probe logic in both sequential and parallel execution paths:
  - Old: `Get-WmiObject ...` with WMI-specific `PSBase.Properties` check.
  - New: prefer `Get-CimInstance -ClassName Win32_OperatingSystem`, fallback to `Get-WmiObject -Class ...`.
  - Property evaluation simplified to direct `RebootRequired` check.
- Result: compatibility with PS7 and cleaner object handling across CIM/WMI outputs.

### Validation Performed
- PowerShell parser checks executed successfully after edits:
  - `[ScriptBlock]::Create((Get-Content -Path "Install-RemoteMSI.ps1" -Raw))` returned parse success.
- Additional local command metadata checks were used during implementation to verify parameter-set differences between PS5.1 and PS7.

### Notes
- No functional scope expansion was introduced; all edits were compatibility and correctness fixes for existing behavior.
- No unrelated source files were modified by these implementation changes.
