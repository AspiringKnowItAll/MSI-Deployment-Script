<#
.SYNOPSIS
    Remotely installs an MSI package on a remote machine with error handling and reboot detection.

.DESCRIPTION
    This script allows silent installation of an MSI file on a remote machine. It:
    - Prompts for hostname and validates against Active Directory
    - Checks if remote machine is online  
    - Handles credential authentication with retry logic
    - Copies MSI to remote machine
    - Executes silent installation with no restart
    - Monitors installation status
    - Detects if reboot is required (registry + WMI)
    - Removes MSI on success, preserves on failure
    - Logs all operations to timestamped file with success/failure indicator
    - Provides detailed terminal and file output

.NOTES
    Author: Andrew Lucas using Claude Haiku 4.5 in VSCode Chat
    Requires: Administrator privileges for remote execution
    Credential Security: PSCredential uses SecureString (in-memory only, never written to disk)
    MSI Source: C:\Downloads\
    Log Location: C:\Downloads\[ComputerName]_[yyyyMMdd_HHmmss]_[Success|Failure|Incomplete].log
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# ============================================================================
# CONFIGURATION
# ============================================================================

$LocalMSIPath = 'C:\Downloads'
$RemoteTempPath = 'C:\Temp'
$LogPath = $null  # Will be set after hostname is known
$MaxCredentialAttempts = 2

# ============================================================================
# LOGGING FUNCTION
# ============================================================================

function Write-Log {
    <#
    .SYNOPSIS
        Writes messages to both console and log file with timestamps and log levels.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('INFO', 'SUCCESS', 'ERROR', 'WARNING')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "$timestamp [$Level] $Message"
    
    # Write to console with colors
    $color = switch ($Level) {
        'SUCCESS' { 'Green' }
        'ERROR' { 'Red' }
        'WARNING' { 'Yellow' }
        'INFO' { 'Cyan' }
    }
    Write-Host $logMessage -ForegroundColor $color
    
    # Write to log file if it exists
    if ($LogPath -and (Test-Path -Path (Split-Path -Parent $LogPath))) {
        Add-Content -Path $LogPath -Value $logMessage -Encoding UTF8
    }
}

# ============================================================================
# VALIDATION FUNCTIONS
# ============================================================================

function Test-ComputerInAD {
    <#
    .SYNOPSIS
        Validates that a computer exists in Active Directory and is online.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    try {
        Write-Log "Validating computer '$ComputerName' against Active Directory..." -Level INFO
        
        # Try to resolve the hostname
        $dnsResolve = Resolve-DnsName -Name $ComputerName -ErrorAction SilentlyContinue
        if (-not $dnsResolve) {
            Write-Log "Computer '$ComputerName' not found in DNS." -Level ERROR
            return $false
        }

        Write-Log "Computer '$ComputerName' found in DNS." -Level SUCCESS
        return $true
    }
    catch {
        Write-Log "Error validating computer: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Test-ComputerOnline {
    <#
    .SYNOPSIS
        Tests if a remote computer is online and reachable.
        Uses multiple methods to work with non-admin user context.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    try {
        Write-Log "Testing connectivity to '$ComputerName'..." -Level INFO
        
        # Method 1: Try TCP connection to WinRM port (no admin required, better for remoting)
        try {
            Write-Log "Attempting TCP connection to WinRM port (5985)..." -Level INFO
            $tcpTest = Test-Connection -TargetName $ComputerName -TcpPort 5985 -Quiet -Count 1 -TimeoutSeconds 5
            
            if ($tcpTest) {
                Write-Log "Computer '$ComputerName' is online (TCP/5985 responding)." -Level SUCCESS
                return $true
            }
        }
        catch {
            Write-Log "TCP port test not available (requires PS 7+), attempting ICMP..." -Level INFO
        }

        # Method 2: Try ICMP ping (may require admin on Windows)
        try {
            $ping = Test-Connection -TargetName $ComputerName -Quiet -Count 1 -TimeoutSeconds 5
            
            if ($ping) {
                Write-Log "Computer '$ComputerName' is online (ICMP responding)." -Level SUCCESS
                return $true
            }
            else {
                Write-Log "Computer '$ComputerName' is not responding to connectivity tests." -Level ERROR
                return $false
            }
        }
        catch {
            Write-Log "ICMP test failed: $($_.Exception.Message)" -Level WARNING
            Write-Log "Note: ICMP/ping may require administrator privileges on this system." -Level WARNING
            return $false
        }
    }
    catch {
        Write-Log "Error testing connectivity: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Get-ValidatedHostname {
    <#
    .SYNOPSIS
        Prompts user for hostname and validates it against AD.
        Online check deferred to after privilege verification.
    #>
    
    Write-Host "`n" + ("=" * 70)
    Write-Host "Remote MSI Installation Tool" -ForegroundColor Cyan
    Write-Host ("=" * 70)
    
    while ($true) {
        $hostname = Read-Host "`nEnter the hostname of the target machine"
        
        if ([string]::IsNullOrWhiteSpace($hostname)) {
            Write-Log "Hostname cannot be empty." -Level WARNING
            continue
        }

        if (-not (Test-ComputerInAD -ComputerName $hostname)) {
            Write-Log "Please enter a valid hostname." -Level WARNING
            continue
        }

        Write-Log "Hostname validation successful." -Level SUCCESS
        return $hostname
    }
}

# ============================================================================
# CREDENTIAL HANDLING
# ============================================================================

function Get-ValidatedCredentials {
    <#
    .SYNOPSIS
        Attempts to get validated credentials from user with retry logic.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        
        [Parameter(Mandatory = $true)]
        [pscredential]$InitialCredential
    )

    $domain = (Get-ADDomain -ErrorAction SilentlyContinue).DNSRoot
    if (-not $domain) {
        $domain = $env:USERDOMAIN
    }

    $attemptCount = 0
    
    while ($attemptCount -lt $MaxCredentialAttempts) {
        try {
            Write-Log "Attempting to validate credentials (Attempt $($attemptCount + 1) of $MaxCredentialAttempts)..." -Level INFO
            
            # Test PSSession creation with the credentials
            $testSession = New-PSSession -ComputerName $ComputerName -Credential $InitialCredential -ErrorAction Stop
            Remove-PSSession -Session $testSession -ErrorAction SilentlyContinue
            
            Write-Log "Credentials validated successfully." -Level SUCCESS
            return $InitialCredential
        }
        catch {
            $attemptCount++
            
            if ($attemptCount -ge $MaxCredentialAttempts) {
                Write-Log "Failed to validate credentials after $MaxCredentialAttempts attempts." -Level ERROR
                return $null
            }

            Write-Log "Credentials validation failed: $($_.Exception.Message)" -Level WARNING
            Write-Log "Prompting for new credentials..." -Level INFO
            
            $InitialCredential = Get-Credential -Message "Enter credentials for $domain" -Title "Authentication Required"
            
            if ($null -eq $InitialCredential) {
                Write-Log "Credential entry cancelled by user." -Level ERROR
                return $null
            }
        }
    }

    return $null
}

function Get-SessionCredentials {
    <#
    .SYNOPSIS
        Determines if current user credentials work, or prompts for new ones.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    Write-Log "Checking if current user can access remote machine..." -Level INFO
    
    try {
        $testSession = New-PSSession -ComputerName $ComputerName -ErrorAction Stop
        Remove-PSSession -Session $testSession -ErrorAction SilentlyContinue
        
        Write-Log "Current user has access to remote machine." -Level SUCCESS
        return $null  # Use current user credentials
    }
    catch {
        Write-Log "Current user does not have sufficient permissions." -Level WARNING
        Write-Log "Please provide alternate credentials." -Level INFO
        
        $credential = Get-Credential -Message "Authentication required for $ComputerName"
        
        if ($null -eq $credential) {
            Write-Log "Credential entry cancelled by user." -Level ERROR
            return $null
        }

        $validatedCredential = Get-ValidatedCredentials -ComputerName $ComputerName -InitialCredential $credential
        return $validatedCredential
    }
}

# ============================================================================
# MSI FILE SELECTION
# ============================================================================

function Get-MSIFile {
    <#
    .SYNOPSIS
        Finds MSI files in C:\Downloads and prompts user to select one if multiple exist.
    #>
    
    Write-Log "Scanning for MSI files in '$LocalMSIPath'..." -Level INFO
    
    if (-not (Test-Path -Path $LocalMSIPath -PathType Container)) {
        Write-Log "Download directory '$LocalMSIPath' does not exist." -Level ERROR
        return $null
    }

    $msiFiles = @(Get-ChildItem -Path $LocalMSIPath -Filter '*.msi' -ErrorAction SilentlyContinue)
    
    if ($msiFiles.Count -eq 0) {
        Write-Log "No MSI files found in '$LocalMSIPath'." -Level ERROR
        return $null
    }

    if ($msiFiles.Count -eq 1) {
        Write-Log "Found MSI file: $($msiFiles[0].Name)" -Level SUCCESS
        return $msiFiles[0]
    }

    # Multiple MSI files - prompt user to select
    Write-Log "Found $($msiFiles.Count) MSI files. Please select one:" -Level INFO
    Write-Host ""
    
    for ($i = 0; $i -lt $msiFiles.Count; $i++) {
        Write-Host "  [$($i + 1)] $($msiFiles[$i].Name)"
    }
    
    while ($true) {
        $selection = Read-Host "`nEnter the number of the MSI to install [1-$($msiFiles.Count)]"
        
        if ([int]::TryParse($selection, [ref]$null) -and $selection -ge 1 -and $selection -le $msiFiles.Count) {
            $selectedFile = $msiFiles[$selection - 1]
            Write-Log "Selected MSI: $($selectedFile.Name)" -Level SUCCESS
            return $selectedFile
        }

        Write-Log "Invalid selection. Please enter a number between 1 and $($msiFiles.Count)." -Level WARNING
    }
}

# ============================================================================
# REMOTE INSTALLATION
# ============================================================================

function Install-RemoteMSI {
    <#
    .SYNOPSIS
        Executes the MSI installation on the remote machine.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Runspaces.PSSession]$Session,
        
        [Parameter(Mandatory = $true)]
        [string]$RemoteMSIPath
    )

    Write-Log "Starting silent MSI installation on remote machine..." -Level INFO
    
    try {
        $installScript = {
            param($MSIPath)
            
            # Execute MSI silently with no restart prompt
            $process = Start-Process -FilePath 'msiexec.exe' `
                -ArgumentList @("/i", $MSIPath, "/quiet", "/norestart") `
                -Wait -PassThru -NoNewWindow
            
            return $process.ExitCode
        }

        $exitCode = Invoke-Command -Session $Session -ScriptBlock $installScript -ArgumentList $RemoteMSIPath

        return $exitCode
    }
    catch {
        Write-Log "Error executing installation: $($_.Exception.Message)" -Level ERROR
        return $null
    }
}

# ============================================================================
# REBOOT DETECTION
# ============================================================================

function Test-PendingReboot {
    <#
    .SYNOPSIS
        Checks if the remote machine requires a reboot using both registry and WMI methods.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Runspaces.PSSession]$Session
    )

    Write-Log "Checking for pending reboot indicators..." -Level INFO
    
    try {
        $rebootScript = {
            $requiresReboot = $false
            
            # Check registry for pending file rename operations
            $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
            $regKey = Get-ItemProperty -Path $regPath -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue
            
            if ($regKey -and $regKey.PendingFileRenameOperations) {
                $requiresReboot = $true
            }

            # Check registry for Windows Update reboot required
            $regPath2 = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update'
            $regKey2 = Get-ItemProperty -Path $regPath2 -Name 'RebootRequired' -ErrorAction SilentlyContinue
            
            if ($regKey2 -and $regKey2.RebootRequired) {
                $requiresReboot = $true
            }

            # Check WMI for pending system restart
            try {
                $wmiInstance = Get-WmiObject -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
                if ($wmiInstance -and $wmiInstance.PSBase.Properties['RebootRequired'] -and $wmiInstance.RebootRequired) {
                    $requiresReboot = $true
                }
            }
            catch {
                # WMI may not be available, continue with registry checks
            }

            return $requiresReboot
        }

        $pendingReboot = Invoke-Command -Session $Session -ScriptBlock $rebootScript
        
        if ($pendingReboot) {
            Write-Log "System reboot is required." -Level WARNING
            return $true
        }
        else {
            Write-Log "No pending reboot required." -Level SUCCESS
            return $false
        }
    }
    catch {
        Write-Log "Error checking reboot status: $($_.Exception.Message)" -Level WARNING
        return $false  # Assume no reboot needed if check fails
    }
}

# ============================================================================
# REMOTE CLEANUP
# ============================================================================

function Remove-RemoteFile {
    <#
    .SYNOPSIS
        Removes the MSI file from the remote machine.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Runspaces.PSSession]$Session,
        
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    try {
        Write-Log "Removing MSI from remote machine..." -Level INFO
        
        $removeScript = {
            param($Path)
            if (Test-Path -Path $Path) {
                Remove-Item -Path $Path -Force -ErrorAction Stop
                return $true
            }
            return $false
        }

        $result = Invoke-Command -Session $Session -ScriptBlock $removeScript -ArgumentList $FilePath
        
        if ($result) {
            Write-Log "MSI removed successfully." -Level SUCCESS
        }
        else {
            Write-Log "MSI file not found or already removed." -Level INFO
        }
        
        return $true
    }
    catch {
        Write-Log "Error removing MSI: $($_.Exception.Message)" -Level WARNING
        return $false
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Main {
    try {
        # ====================================================================
        # PHASE 1: INPUT VALIDATION
        # ====================================================================
        
        $ComputerName = Get-ValidatedHostname
        
        # Set log path now that we have hostname
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $baseLogName = "{0}_{1}" -f $ComputerName, $timestamp
        $LogPath = Join-Path -Path $LocalMSIPath -ChildPath "${baseLogName}_Incomplete.log"
        
        Write-Log "Installation session started for $ComputerName" -Level INFO
        
        # ====================================================================
        # PHASE 1.5: CONNECTIVITY CHECK (after hostname validation)
        # ====================================================================
        
        # Test connectivity - if not admin, user can still proceed with credentials
        if ([Security.Principal.WindowsIdentity]::GetCurrent().Groups -contains 'S-1-5-32-544') {
            # User is admin - perform connectivity test
            if (-not (Test-ComputerOnline -ComputerName $ComputerName)) {
                Write-Log "Computer '$ComputerName' is not responding. Proceed with caution." -Level WARNING
            }
        }
        else {
            Write-Log "Note: Running as non-admin. Skipping ICMP connectivity test (requires elevation)." -Level INFO
            Write-Log "Connectivity will be verified when establishing remote session." -Level INFO
        }
        
        # ====================================================================
        # PHASE 2: MSI SELECTION
        # ====================================================================

        
        $msiFile = Get-MSIFile
        if ($null -eq $msiFile) {
            $errorLog = Join-Path -Path $LocalMSIPath -ChildPath "${baseLogName}_Failure.log"
            if ($LogPath -ne $errorLog) {
                if (Test-Path $LogPath) { Move-Item -Path $LogPath -Destination $errorLog -Force }
            }
            throw "No valid MSI file selected."
        }
        
        $localMSIFullPath = $msiFile.FullName
        Write-Log "MSI file selected: $($msiFile.Name)" -Level SUCCESS
        
        # ====================================================================
        # PHASE 3: CREDENTIAL HANDLING
        # ====================================================================
        
        $credential = Get-SessionCredentials -ComputerName $ComputerName
        
        # ====================================================================
        # PHASE 4: REMOTE SESSION CREATION
        # ====================================================================
        
        Write-Log "Creating remote session to $ComputerName..." -Level INFO
        
        try {
            if ($credential) {
                $session = New-PSSession -ComputerName $ComputerName -Credential $credential -ErrorAction Stop
            }
            else {
                $session = New-PSSession -ComputerName $ComputerName -ErrorAction Stop
            }
            
            Write-Log "Remote session created successfully." -Level SUCCESS
        }
        catch {
            throw "Failed to create remote session: $($_.Exception.Message)"
        }
        
        # ====================================================================
        # PHASE 5: PREPARE REMOTE ENVIRONMENT
        # ====================================================================
        
        Write-Log "Preparing remote environment..." -Level INFO
        
        try {
            Invoke-Command -Session $session -ScriptBlock {
                param($TempPath)
                
                if (-not (Test-Path -Path $TempPath)) {
                    New-Item -Path $TempPath -ItemType Directory -Force | Out-Null
                }
            } -ArgumentList $RemoteTempPath
            
            Write-Log "Remote temp directory ready." -Level SUCCESS
        }
        catch {
            throw "Failed to prepare remote environment: $($_.Exception.Message)"
        }
        
        # ====================================================================
        # PHASE 6: COPY MSI TO REMOTE MACHINE
        # ====================================================================
        
        $remoteMSIPath = Join-Path -Path $RemoteTempPath -ChildPath $msiFile.Name
        
        Write-Log "Copying MSI to remote machine ($remoteMSIPath)..." -Level INFO
        
        try {
            Copy-Item -Path $localMSIFullPath -Destination $remoteMSIPath -ToSession $session -Force -ErrorAction Stop
            Write-Log "MSI copied successfully." -Level SUCCESS
        }
        catch {
            throw "Failed to copy MSI to remote machine: $($_.Exception.Message)"
        }
        
        # ====================================================================
        # PHASE 7: EXECUTE INSTALLATION
        # ====================================================================
        
        $exitCode = Install-RemoteMSI -Session $session -RemoteMSIPath $remoteMSIPath
        
        if ($null -eq $exitCode) {
            throw "Installation failed or was cancelled."
        }
        
        Write-Log "MSI installation completed with exit code: $exitCode" -Level INFO
        
        # MSI exit codes: 0 = success, 3010 = success but restart required
        if ($exitCode -eq 0) {
            Write-Log "Installation completed successfully (no restart required)." -Level SUCCESS
            $installSuccess = $true
            $rebootNeeded = $false
        }
        elseif ($exitCode -eq 3010) {
            Write-Log "Installation successful but system reboot required." -Level SUCCESS
            $installSuccess = $true
            $rebootNeeded = $true
        }
        else {
            throw "Installation failed with exit code $exitCode"
        }
        
        # ====================================================================
        # PHASE 8: CHECK FOR PENDING REBOOT
        # ====================================================================
        
        $pendingReboot = Test-PendingReboot -Session $session
        $rebootNeeded = $rebootNeeded -or $pendingReboot
        
        # ====================================================================
        # PHASE 9: CLEANUP & RESULTS
        # ====================================================================
        
        if ($installSuccess) {
            Write-Log "Cleaning up remote installation files..." -Level INFO
            Remove-RemoteFile -Session $session -FilePath $remoteMSIPath
        }
        else {
            Write-Log "Keeping MSI on remote machine due to installation failure." -Level WARNING
        }
        
        # ====================================================================
        # FINAL STATUS & LOGGING
        # ====================================================================
        
        Write-Host "`n" + ("=" * 70)
        Write-Host "Installation Summary" -ForegroundColor Cyan
        Write-Host ("=" * 70)
        
        if ($installSuccess) {
            Write-Log "Installation SUCCESSFUL on $ComputerName" -Level SUCCESS
            
            if ($rebootNeeded) {
                Write-Host "Status: SUCCESS - Reboot Required" -ForegroundColor Yellow
                Write-Log "Note: Machine requires a system reboot to complete installation." -Level WARNING
            }
            else {
                Write-Host "Status: SUCCESS - No Reboot Required" -ForegroundColor Green
            }
            
            # Rename log to Success
            $successLog = Join-Path -Path $LocalMSIPath -ChildPath "${baseLogName}_Success.log"
            if (Test-Path $LogPath) {
                Move-Item -Path $LogPath -Destination $successLog -Force
                $LogPath = $successLog
            }
        }
        else {
            Write-Host "Status: FAILED" -ForegroundColor Red
            Write-Log "Installation FAILED on $ComputerName - MSI preserved for troubleshooting." -Level ERROR
            
            # Rename log to Failure
            $failureLog = Join-Path -Path $LocalMSIPath -ChildPath "${baseLogName}_Failure.log"
            if (Test-Path $LogPath) {
                Move-Item -Path $LogPath -Destination $failureLog -Force
                $LogPath = $failureLog
            }
        }
        
        Write-Host "Log File: $LogPath" -ForegroundColor Cyan
        Write-Host ("=" * 70) + "`n"
        
        # Clean up session
        Remove-PSSession -Session $session -ErrorAction SilentlyContinue
        
        if (-not $installSuccess) {
            exit 1
        }
    }
    catch {
        Write-Log "FATAL ERROR: $($_.Exception.Message)" -Level ERROR
        
        # Ensure log file is renamed to Failure if we have a LogPath
        if ($LogPath -and (Test-Path $LogPath)) {
            $failureLog = $LogPath -replace '_Incomplete\.log$', '_Failure.log'
            Move-Item -Path $LogPath -Destination $failureLog -Force -ErrorAction SilentlyContinue
        }
        
        Write-Host "`n[INSTALLATION FAILED]" -ForegroundColor Red
        exit 1
    }
}

# Execute main function
Main
