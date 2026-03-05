# Release Notes

## MSI-Deployment-Script
### Release Date: 2026-03-05

## Overview
This release focuses on PowerShell command/flag correctness, cross-version compatibility (Windows PowerShell 5.1 + PowerShell 7), and reliability hardening in remote pre-validation and reboot-detection logic.

## What Changed

### 1) Cross-version reachability checks (`Test-ComputerOnline`)
- Replaced fragile parameter usage with version-safe logic.
- Added TCP WinRM probe flow:
  - Uses `Test-NetConnection` when available.
  - Falls back to `.NET TcpClient` probe when needed.
- Added dynamic `Test-Connection` parameter selection:
  - `ComputerName` (PS5.1) vs `TargetName` (PS7)
  - timeout parameter support detected at runtime.

### 2) Async socket cleanup reliability
- Hardened `TcpClient` async cleanup to avoid incomplete async state during timeout/failure paths.
- Ensures connection completion/finalization and handle disposal are consistently attempted.

### 3) Summary banner output fix
- Corrected 3 instances where `Write-Host` string concatenation dropped part of the output.
- Result: separator/banner lines now render consistently.

### 4) DirectoryServices assembly load hardening
- Added defensive `Add-Type` load for `System.DirectoryServices.AccountManagement` in credential validation.
- Improves behavior consistency where auto-loading may vary by host/runtime.

### 5) Reboot detection compatibility (PS5.1 + PS7)
- Updated reboot probes to prefer `Get-CimInstance` and fallback to `Get-WmiObject` when needed.
- Removed WMI-specific property access patterns that are not valid for CIM objects.

## Impact
- Eliminates invalid/host-specific command flag usage that previously caused silent failures.
- Improves pre-validation reliability and keeps behavior consistent across PowerShell versions.
- Reduces risk of false-negative reboot detection in PowerShell 7 environments.

## Validation
- Script parsing/syntax validation passed after changes.
- Command/parameter compatibility checks were performed against both PS5.1 and PS7 parameter behavior.

## Files Updated
- `Install-RemoteMSI.ps1`
- `changelog.md`
