<#
.SYNOPSIS
    Remotely installs an MSI/MSIX package on one or more remote Windows machines.

.DESCRIPTION
    Supports single-machine and batch execution with:
    - Credential validation before heavy processing
    - Hostname sanitization
    - Batch input file discovery (CSV/TXT)
    - AD and online pre-validation for batch lists
    - Throttled parallel installation batches
    - File transfer retry policy (5s, 10s, 30s, 60s)
    - Per-machine retry rounds after each batch (failed machines only)
    - One aggregated log file per script run
    - In-place success commenting in source machine file for reruns
#>

[CmdletBinding()]
param(
    [switch]$NonInteractive,
    [string]$RunLogPath
)

$ErrorActionPreference = 'Stop'

# ============================================================================
# CONFIGURATION
# ============================================================================

$ScriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$LocalMSIPath = $ScriptDirectory
$RemoteTempPath = 'C:\Temp'
$LogDirectory = Join-Path -Path $ScriptDirectory -ChildPath 'Logs'
$MaxCredentialAttempts = 2
$TransferRetryDelays = @(5, 10, 30, 60)
$LogPath = $null
$RunId = Get-Date -Format 'yyyyMMdd_HHmmss'
$ScriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }

# ============================================================================
# LOGGING
# ============================================================================

function Initialize-RunLog {
    if (-not (Test-Path -Path $LogDirectory)) {
        New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
    }

    if (-not [string]::IsNullOrWhiteSpace($RunLogPath)) {
        $resolvedPath = $RunLogPath
        $resolvedDirectory = Split-Path -Path $resolvedPath -Parent
        if ($resolvedDirectory -and -not (Test-Path -Path $resolvedDirectory)) {
            New-Item -ItemType Directory -Path $resolvedDirectory -Force | Out-Null
        }

        $script:LogPath = $resolvedPath
        if (-not (Test-Path -Path $script:LogPath -PathType Leaf)) {
            New-Item -Path $script:LogPath -ItemType File -Force | Out-Null
        }
        return
    }

    $script:LogPath = Join-Path -Path $LogDirectory -ChildPath "Deployment_$RunId.log"
    New-Item -Path $script:LogPath -ItemType File -Force | Out-Null
}

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet('INFO', 'SUCCESS', 'ERROR', 'WARNING')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "$timestamp [$Level] $Message"

    $color = switch ($Level) {
        'SUCCESS' { 'Green' }
        'ERROR' { 'Red' }
        'WARNING' { 'Yellow' }
        default { 'Cyan' }
    }

    Write-Host $logMessage -ForegroundColor $color

    if ($script:LogPath) {
        Add-Content -Path $script:LogPath -Value $logMessage -Encoding UTF8
    }
}

# ============================================================================
# INPUT / VALIDATION HELPERS
# ============================================================================

function Get-Confirmation {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Prompt
    )

    while ($true) {
        $response = (Read-Host "$Prompt [Y/N]").Trim().ToUpperInvariant()
        if ($response -in @('Y', 'YES')) { return $true }
        if ($response -in @('N', 'NO')) { return $false }
        Write-Log "Please enter Y or N." -Level WARNING
    }
}

function ConvertTo-Hostname {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RawName
    )

    $trimmed = $RawName.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed)) {
        return $null
    }

    $cleaned = ($trimmed -replace '[^a-zA-Z0-9\-\._]', '')
    if ([string]::IsNullOrWhiteSpace($cleaned)) {
        return $null
    }

    return $cleaned
}

function Test-ComputerInAD {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    try {
        if (Get-Command -Name Get-ADComputer -ErrorAction SilentlyContinue) {
            $adComputer = Get-ADComputer -Identity $ComputerName -ErrorAction SilentlyContinue
            if ($adComputer) {
                return $true
            }
            return $false
        }

        Write-Log "ActiveDirectory module not available. Falling back to DNS validation for '$ComputerName'." -Level WARNING
        $dnsResolve = Resolve-DnsName -Name $ComputerName -ErrorAction SilentlyContinue
        return [bool]$dnsResolve
    }
    catch {
        return $false
    }
}

function Test-ComputerOnline {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    try {
        try {
            $tcpTest = Test-Connection -TargetName $ComputerName -TcpPort 5985 -Quiet -Count 1 -TimeoutSeconds 5
            if ($tcpTest) { return $true }
        }
        catch {
            # ignore and fallback
        }

        $ping = Test-Connection -TargetName $ComputerName -Quiet -Count 1 -TimeoutSeconds 5
        return [bool]$ping
    }
    catch {
        return $false
    }
}

function Get-ValidatedSingleHostname {
    while ($true) {
        $rawHost = Read-Host "Enter the hostname of the target machine"
        $hostName = ConvertTo-Hostname -RawName $rawHost

        if (-not $hostName) {
            Write-Log "Hostname is empty or contains only invalid characters." -Level WARNING
            continue
        }

        if ($hostName -ne $rawHost.Trim()) {
            Write-Log "Hostname sanitized to '$hostName'." -Level INFO
        }

        return $hostName
    }
}

function Get-ExecutionMode {
    Write-Host "`n" + ('=' * 70)
    Write-Host 'Remote MSI Installation Tool' -ForegroundColor Cyan
    Write-Host ('=' * 70)
    Write-Host '[1] Single Machine'
    Write-Host '[2] Batch Deployment (CSV/TXT)'

    while ($true) {
        $selection = (Read-Host "Select mode [1-2]").Trim()
        if ($selection -eq '1') { return 'Single' }
        if ($selection -eq '2') { return 'Batch' }
        Write-Log 'Invalid selection. Enter 1 or 2.' -Level WARNING
    }
}

function Get-PowerShell7Details {
    $details = [pscustomobject]@{
        Available    = $false
        Path         = $null
        MajorVersion = 0
    }

    $candidatePaths = New-Object System.Collections.Generic.List[string]
    $seen = @{}

    function Add-CandidatePath {
        param([string]$Path)

        if ([string]::IsNullOrWhiteSpace($Path)) {
            return
        }

        $normalized = $Path.Trim()
        $key = $normalized.ToUpperInvariant()
        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            $candidatePaths.Add($normalized)
        }
    }

    try {
        $pwshCommand = Get-Command -Name 'pwsh' -ErrorAction SilentlyContinue
        if ($pwshCommand -and $pwshCommand.Source) {
            Add-CandidatePath -Path $pwshCommand.Source
        }
    }
    catch {
        # ignore and continue candidate discovery
    }

    if ($env:ProgramFiles) {
        Add-CandidatePath -Path (Join-Path -Path ${env:ProgramFiles} -ChildPath 'PowerShell\7\pwsh.exe')
    }

    if ($env:ProgramW6432) {
        Add-CandidatePath -Path (Join-Path -Path ${env:ProgramW6432} -ChildPath 'PowerShell\7\pwsh.exe')
    }

    if (${env:ProgramFiles(x86)}) {
        Add-CandidatePath -Path (Join-Path -Path ${env:ProgramFiles(x86)} -ChildPath 'PowerShell\7\pwsh.exe')
    }

    foreach ($registryPath in @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\pwsh.exe',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\pwsh.exe',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\pwsh.exe'
    )) {
        try {
            if (-not (Test-Path -Path $registryPath)) {
                continue
            }

            $regItem = Get-Item -Path $registryPath -ErrorAction SilentlyContinue
            if ($regItem) {
                $regPwshPath = $regItem.GetValue('')
                if ($regPwshPath) {
                    Add-CandidatePath -Path $regPwshPath
                }
            }
        }
        catch {
            # ignore registry read failures
        }
    }

    foreach ($candidate in $candidatePaths) {
        try {
            if (-not (Test-Path -Path $candidate -PathType Leaf)) {
                continue
            }

            $majorVersionOutput = & $candidate -NoProfile -NonInteractive -Command '$PSVersionTable.PSVersion.Major' 2>$null
            $majorVersionText = ($majorVersionOutput | Select-Object -First 1).ToString().Trim()

            $majorVersion = 0
            if (-not [int]::TryParse($majorVersionText, [ref]$majorVersion)) {
                continue
            }

            if ($majorVersion -gt $details.MajorVersion) {
                $details.MajorVersion = $majorVersion
                $details.Path = $candidate
            }

            if ($majorVersion -ge 7) {
                $details.Available = $true
                $details.Path = $candidate
                $details.MajorVersion = $majorVersion
                return $details
            }
        }
        catch {
            # ignore candidate execution failures
        }
    }

    return $details
}

function Test-IsInteractiveSession {
    if ($NonInteractive) {
        return $false
    }

    return [Environment]::UserInteractive -and $Host.Name -ne 'ServerRemoteHost'
}

function Test-IsLocalAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Read-YesNoChoice {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Prompt,

        [Parameter(Mandatory = $false)]
        [bool]$DefaultYes = $true
    )

    $suffix = if ($DefaultYes) { '[Y/n]' } else { '[y/N]' }
    while ($true) {
        $response = (Read-Host "$Prompt $suffix").Trim().ToUpperInvariant()

        if ([string]::IsNullOrWhiteSpace($response)) {
            return $DefaultYes
        }

        if ($response -in @('Y', 'YES')) { return $true }
        if ($response -in @('N', 'NO')) { return $false }

        Write-Log 'Please enter Y or N.' -Level WARNING
    }
}

function Install-PowerShell7ViaWindowsUpdate {
    $result = [pscustomobject]@{
        Success        = $false
        Message        = ''
        RebootRequired = $false
        InstalledCount = 0
    }

    if (-not (Test-IsLocalAdministrator)) {
        $result.Message = 'PowerShell 7 install via Windows Update requires running this script as local administrator.'
        return $result
    }

    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $searcher = $updateSession.CreateUpdateSearcher()
        $searchResult = $searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")

        $candidates = New-Object -ComObject Microsoft.Update.UpdateColl
        foreach ($update in $searchResult.Updates) {
            $title = [string]$update.Title
            if ($title -match '(?i)PowerShell' -and $title -match '(?i)\b7(\.\d+)?\b') {
                if (-not $update.EulaAccepted) {
                    $update.AcceptEula()
                }
                [void]$candidates.Add($update)
            }
        }

        if ($candidates.Count -eq 0) {
            $result.Message = 'No approved/applicable PowerShell 7 updates were found from the configured Windows Update service.'
            return $result
        }

        $downloader = $updateSession.CreateUpdateDownloader()
        $downloader.Updates = $candidates
        $downloadResult = $downloader.Download()
        if ($downloadResult.ResultCode -notin 2, 3) {
            $result.Message = "PowerShell 7 update download did not succeed (ResultCode=$($downloadResult.ResultCode))."
            return $result
        }

        $installer = $updateSession.CreateUpdateInstaller()
        $installer.Updates = $candidates
        $installResult = $installer.Install()

        $installedCount = 0
        for ($i = 0; $i -lt $candidates.Count; $i++) {
            $updateResultCode = $installResult.GetUpdateResult($i).ResultCode
            if ($updateResultCode -in 2, 3) {
                $installedCount++
            }
        }

        $result.InstalledCount = $installedCount
        $result.RebootRequired = [bool]$installResult.RebootRequired
        $result.Success = $installedCount -gt 0

        if ($result.Success) {
            $result.Message = "Installed $installedCount PowerShell update(s) through configured Windows Update service."
        }
        else {
            $result.Message = "PowerShell update install returned no successful updates (ResultCode=$($installResult.ResultCode))."
        }

        return $result
    }
    catch {
        $result.Message = "Windows Update install attempt failed: $($_.Exception.Message)"
        return $result
    }
}

function Invoke-PowerShell7Relaunch {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PwshPath
    )

    try {
        if ([string]::IsNullOrWhiteSpace($PwshPath) -or -not (Test-Path -LiteralPath $PwshPath -PathType Leaf)) {
            throw "PowerShell 7 executable path is invalid: '$PwshPath'"
        }

        if ([string]::IsNullOrWhiteSpace($ScriptPath) -or -not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) {
            throw "Script path for relaunch is invalid: '$ScriptPath'"
        }

        $launchArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $ScriptPath)
        if ($script:LogPath) {
            $launchArgs += @('-RunLogPath', $script:LogPath)
        }
        if ($NonInteractive) {
            $launchArgs += '-NonInteractive'
        }

        Write-Log "Launching PowerShell 7 process: '$PwshPath' (same console)." -Level INFO
        $childProcess = Start-Process -FilePath $PwshPath -ArgumentList $launchArgs -WorkingDirectory $ScriptDirectory -NoNewWindow -PassThru -Wait -ErrorAction Stop
        if ($null -eq $childProcess) {
            throw 'PowerShell 7 process failed to start.'
        }

        Write-Log "PowerShell 7 process exited with code $($childProcess.ExitCode)." -Level INFO
        if ($childProcess.ExitCode -ne 0) {
            Write-Log 'PowerShell 7 run ended with non-zero exit code. Check the latest child run log in Logs\Deployment_*.log for the exact failure reason.' -Level WARNING
        }
        return [int]$childProcess.ExitCode
    }
    catch {
        Write-Log "Failed to relaunch in PowerShell 7+: $($_.Exception.Message)" -Level ERROR
        return $null
    }
}

function Invoke-PowerShell7Bootstrap {
    $currentMajor = $PSVersionTable.PSVersion.Major
    $isInteractive = Test-IsInteractiveSession

    Write-Log "Runtime host version detected: PowerShell $currentMajor." -Level INFO

    if ($currentMajor -ge 7) {
        Write-Log 'PowerShell 7+ host detected. Startup bootstrap check complete.' -Level INFO
        return
    }

    $pwshDetails = Get-PowerShell7Details
    if ($pwshDetails.Available) {
        Write-Log "PowerShell 7+ is installed at '$($pwshDetails.Path)'." -Level INFO

        if ($isInteractive) {
            $relaunchNow = Read-YesNoChoice -Prompt 'Relaunch this script now in PowerShell 7+ for full parallel support?' -DefaultYes $true
            if ($relaunchNow) {
                Write-Log "Relaunching in PowerShell 7+ using '$($pwshDetails.Path)'..." -Level INFO
                $childExitCode = Invoke-PowerShell7Relaunch -PwshPath $pwshDetails.Path
                if ($null -eq $childExitCode) {
                    Write-Log 'Relaunch failed. Continuing in current host with sequential fallback behavior.' -Level WARNING
                    return
                }
                exit $childExitCode
            }

            Write-Log 'Operator declined relaunch. This run will continue and use sequential fallback if parallel is requested.' -Level WARNING
        }
        else {
            Write-Log 'Non-interactive session detected. Skipping relaunch prompt and continuing in current host.' -Level WARNING
        }

        return
    }

    Write-Log 'PowerShell 7+ is not currently installed on this machine.' -Level WARNING

    if (-not $isInteractive) {
        Write-Log 'Non-interactive session detected. Skipping PowerShell install attempt and continuing with sequential fallback behavior.' -Level WARNING
        return
    }

    $attemptInstall = Read-YesNoChoice -Prompt 'Attempt to install PowerShell 7+ now using configured Windows Update service (WSUS/Microsoft Update)?' -DefaultYes $true
    if (-not $attemptInstall) {
        Write-Log 'Operator skipped PowerShell 7 installation attempt. Continuing in current host.' -Level WARNING
        return
    }

    Write-Log 'Attempting PowerShell 7 install through configured Windows Update service...' -Level INFO
    $installResult = Install-PowerShell7ViaWindowsUpdate
    if ($installResult.Success) {
        Write-Log $installResult.Message -Level SUCCESS
        if ($installResult.RebootRequired) {
            Write-Log 'Windows Update reported a reboot requirement after install. Relaunch may fail until reboot is completed.' -Level WARNING
        }
    }
    else {
        Write-Log $installResult.Message -Level WARNING
    }

    $pwshAfterInstall = Get-PowerShell7Details
    if (-not $pwshAfterInstall.Available) {
        Write-Log 'PowerShell 7+ is still unavailable after install attempt. Continuing with sequential fallback behavior.' -Level WARNING
        return
    }

    Write-Log "PowerShell 7+ is now available at '$($pwshAfterInstall.Path)'." -Level SUCCESS
    $relaunchAfterInstall = Read-YesNoChoice -Prompt 'Relaunch this script now in PowerShell 7+?' -DefaultYes $true
    if (-not $relaunchAfterInstall) {
        Write-Log 'Operator declined relaunch after install. Continuing in current host.' -Level WARNING
        return
    }

    Write-Log "Relaunching in PowerShell 7+ using '$($pwshAfterInstall.Path)'..." -Level INFO
    $childExitCodeAfterInstall = Invoke-PowerShell7Relaunch -PwshPath $pwshAfterInstall.Path
    if ($null -eq $childExitCodeAfterInstall) {
        Write-Log 'Relaunch failed after install. Continuing in current host with sequential fallback behavior.' -Level WARNING
        return
    }
    exit $childExitCodeAfterInstall
}

function Get-InstallerFiles {
    if (-not (Test-Path -Path $LocalMSIPath -PathType Container)) {
        return @()
    }

    return @(Get-ChildItem -Path $LocalMSIPath -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in @('.msi', '.msix') })
}

function Test-InstallerFilesExist {
    if (-not (Test-Path -Path $LocalMSIPath -PathType Container)) {
        throw "Script directory does not exist: $LocalMSIPath"
    }

    $allInstallerFiles = Get-InstallerFiles
    if ($allInstallerFiles.Count -eq 0) {
        throw "No MSI or MSIX files found in $LocalMSIPath"
    }
}

function Get-MSIFile {
    $installerFiles = Get-InstallerFiles
    if ($installerFiles.Count -eq 0) { return $null }

    if ($installerFiles.Count -eq 1) {
        Write-Log "Installer selected automatically: $($installerFiles[0].Name)" -Level SUCCESS
        return $installerFiles[0]
    }

    Write-Log "Found $($installerFiles.Count) installer files. Select one:" -Level INFO
    for ($i = 0; $i -lt $installerFiles.Count; $i++) {
        Write-Host "  [$($i + 1)] $($installerFiles[$i].Name)"
    }

    while ($true) {
        $selection = (Read-Host "Enter installer number [1-$($installerFiles.Count)]").Trim()
        $selectionNumber = 0
        if ([int]::TryParse($selection, [ref]$selectionNumber) -and $selectionNumber -ge 1 -and $selectionNumber -le $installerFiles.Count) {
            $selectedFile = $installerFiles[$selectionNumber - 1]
            Write-Log "Installer selected: $($selectedFile.Name)" -Level SUCCESS
            return $selectedFile
        }

        Write-Log 'Invalid selection.' -Level WARNING
    }
}

# ============================================================================
# CREDENTIALS
# ============================================================================

function Request-Credentials {
    param(
        [string]$Message = 'Enter credentials'
    )

    Write-Host $Message -ForegroundColor Cyan
    $user = Read-Host 'User'
    if ([string]::IsNullOrWhiteSpace($user)) {
        return $null
    }

    $pass = Read-Host 'Password' -AsSecureString
    if ($null -eq $pass) {
        return $null
    }

    return New-Object System.Management.Automation.PSCredential($user.Trim(), $pass)
}

function Test-RemoteAdmin {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Runspaces.PSSession]$Session
    )

    $isAdmin = Invoke-Command -Session $Session -ScriptBlock {
        $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    return [bool]$isAdmin
}

function Get-ValidatedCredentialForProbe {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProbeComputer
    )

    Write-Log "Validating credentials first using probe machine '$ProbeComputer'." -Level INFO

    try {
        $probeSession = New-PSSession -ComputerName $ProbeComputer -ErrorAction Stop
        $probeAdmin = Test-RemoteAdmin -Session $probeSession
        Remove-PSSession -Session $probeSession -ErrorAction SilentlyContinue

        if ($probeAdmin) {
            Write-Log 'Current user credentials validated successfully (remote admin confirmed).' -Level SUCCESS
            return $null
        }

        Write-Log 'Current user can connect but is not remote administrator. Prompting for credentials.' -Level WARNING
    }
    catch {
        Write-Log "Current user credential probe failed: $($_.Exception.Message)" -Level WARNING
    }

    $attempt = 0
    while ($attempt -lt $MaxCredentialAttempts) {
        $attempt++
        $credential = Request-Credentials -Message "Enter administrator credentials for $ProbeComputer (attempt $attempt of $MaxCredentialAttempts)"
        if ($null -eq $credential) {
            throw 'Credential entry cancelled.'
        }

        try {
            $testSession = New-PSSession -ComputerName $ProbeComputer -Credential $credential -ErrorAction Stop
            $isAdmin = Test-RemoteAdmin -Session $testSession
            Remove-PSSession -Session $testSession -ErrorAction SilentlyContinue

            if (-not $isAdmin) {
                Write-Log 'Credentials authenticated but are not local admin on probe machine.' -Level WARNING
                continue
            }

            Write-Log 'Provided credentials validated successfully.' -Level SUCCESS
            return $credential
        }
        catch {
            Write-Log "Credential validation failed: $($_.Exception.Message)" -Level WARNING
        }
    }

    throw "Failed to validate credentials after $MaxCredentialAttempts attempts."
}

# ============================================================================
# BATCH FILE DISCOVERY / PARSING
# ============================================================================

function Find-BatchMachineFile {
    $candidates = @(
        Get-ChildItem -Path $ScriptDirectory -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in @('.txt', '.csv') } |
            Sort-Object -Property Name
    )

    if ($candidates.Count -gt 0) {
        Write-Host "`nCandidate batch files found in script directory:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $candidates.Count; $i++) {
            Write-Host "  [$($i + 1)] $($candidates[$i].Name)"
        }

        if ($candidates.Count -eq 1) {
            $useFound = Get-Confirmation -Prompt "Use '$($candidates[0].Name)' as machine list file?"
            if ($useFound) {
                return $candidates[0].FullName
            }
        }
        else {
            $useFound = Get-Confirmation -Prompt 'Use one of these discovered files?'
            if ($useFound) {
                while ($true) {
                    $selection = Read-Host "Select file number [1-$($candidates.Count)]"
                    $selectionNumber = 0
                    if ([int]::TryParse($selection, [ref]$selectionNumber) -and $selectionNumber -ge 1 -and $selectionNumber -le $candidates.Count) {
                        return $candidates[$selectionNumber - 1].FullName
                    }
                    Write-Log 'Invalid selection.' -Level WARNING
                }
            }
        }
    }

    while ($true) {
        $manualPath = (Read-Host 'Enter full path to machine list file (CSV/TXT)').Trim()
        if (Test-Path -Path $manualPath -PathType Leaf) {
            $ext = [System.IO.Path]::GetExtension($manualPath).ToLowerInvariant()
            if ($ext -in @('.txt', '.csv')) {
                return $manualPath
            }
            Write-Log 'File must be .txt or .csv.' -Level WARNING
            continue
        }

        Write-Log 'File path not found. Try again.' -Level WARNING
    }
}

function Get-MachineNamesFromFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    $lines = Get-Content -Path $FilePath -ErrorAction Stop
    $rawMachines = New-Object System.Collections.Generic.List[string]
    $invalidCount = 0

    foreach ($line in $lines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $trimmedLine = $line.Trim()
        if ($trimmedLine.StartsWith('#')) { continue }

        $firstColumn = ($trimmedLine -split ',', 2)[0]
        $sanitized = ConvertTo-Hostname -RawName $firstColumn

        if (-not $sanitized) {
            $invalidCount++
            continue
        }

        $rawMachines.Add($sanitized)
    }

    $uniqueMachines = $rawMachines | Sort-Object -Unique
    Write-Log "Parsed $($rawMachines.Count) machine entries from '$FilePath'." -Level INFO
    if ($invalidCount -gt 0) {
        Write-Log "Filtered $invalidCount invalid machine entries during sanitization." -Level WARNING
    }

    return @($uniqueMachines)
}

function Get-ValidatedBatchMachines {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$InputMachines
    )

    $validMachines = New-Object System.Collections.Generic.List[string]
    $notInAD = New-Object System.Collections.Generic.List[string]
    $offline = New-Object System.Collections.Generic.List[string]

    foreach ($machine in $InputMachines) {
        if (-not (Test-ComputerInAD -ComputerName $machine)) {
            $notInAD.Add($machine)
            continue
        }

        if (-not (Test-ComputerOnline -ComputerName $machine)) {
            $offline.Add($machine)
            continue
        }

        $validMachines.Add($machine)
    }

    Write-Log "Pre-validation summary: Total=$($InputMachines.Count), Valid=$($validMachines.Count), NotInAD=$($notInAD.Count), Offline=$($offline.Count)" -Level INFO

    if ($notInAD.Count -gt 0) {
        Write-Log "Excluded (Not in AD/DNS): $($notInAD -join ', ')" -Level WARNING
    }

    if ($offline.Count -gt 0) {
        Write-Log "Excluded (Offline): $($offline -join ', ')" -Level WARNING
    }

    return @($validMachines)
}

# ============================================================================
# INSTALL / RETRIES / RESULT MAPPING
# ============================================================================

function Get-MSIExitDescription {
    param(
        [Parameter(Mandatory = $true)]
        [int]$ExitCode
    )

    switch ($ExitCode) {
        0 { 'Success' }
        1641 { 'Success, restart initiated' }
        3010 { 'Success, reboot required' }
        1601 { 'Windows Installer service unavailable' }
        1602 { 'User cancelled installation' }
        1603 { 'Fatal installation error' }
        1618 { 'Another MSI installation is already in progress' }
        1619 { 'Installer package could not be opened (possible corruption/inaccessible file)' }
        1625 { 'Installation blocked by policy' }
        1632 { 'Temporary folder inaccessible/full' }
        1633 { 'Platform not supported' }
        1638 { 'Another version of this product is already installed' }
        default { 'Unknown MSI exit code' }
    }
}

function Copy-MSIWithRetry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LocalPath,

        [Parameter(Mandatory = $true)]
        [string]$RemotePath,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Runspaces.PSSession]$Session
    )

    while ($true) {
        $attempt = 0
        foreach ($delay in $TransferRetryDelays) {
            $attempt++
            try {
                Write-Log "Transfer attempt $attempt/$($TransferRetryDelays.Count) to $($Session.ComputerName)." -Level INFO
                $previousProgressPreference = $ProgressPreference
                $ProgressPreference = 'SilentlyContinue'
                try {
                    Copy-Item -Path $LocalPath -Destination $RemotePath -ToSession $Session -Force -ErrorAction Stop
                }
                finally {
                    $ProgressPreference = $previousProgressPreference
                }
                Write-Log "Transfer succeeded to $($Session.ComputerName)." -Level SUCCESS
                return $true
            }
            catch {
                Write-Log "Transfer failed on attempt $attempt for $($Session.ComputerName): $($_.Exception.Message)" -Level WARNING
                Write-Log "Waiting $delay second(s) before next transfer attempt..." -Level INFO
                Start-Sleep -Seconds $delay
            }
        }

        Write-Log "Transfer failed after all retry delays for $($Session.ComputerName)." -Level ERROR
        Write-Host "Options: [R]etry transfer cycle, [A]bort run" -ForegroundColor Yellow
        while ($true) {
            $choice = (Read-Host 'Select option').Trim().ToUpperInvariant()
            if ($choice -eq 'R') { break }
            if ($choice -eq 'A') { return $false }
            Write-Log 'Invalid choice. Enter R or A.' -Level WARNING
        }
    }
}

function Test-PendingReboot {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Runspaces.PSSession]$Session
    )

    try {
        $pendingReboot = Invoke-Command -Session $Session -ScriptBlock {
            $requiresReboot = $false

            $regPath1 = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
            $regPath2 = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update'

            $pendingRename = Get-ItemProperty -Path $regPath1 -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue
            if ($pendingRename -and $pendingRename.PendingFileRenameOperations) {
                $requiresReboot = $true
            }

            $wuReboot = Get-ItemProperty -Path $regPath2 -Name 'RebootRequired' -ErrorAction SilentlyContinue
            if ($wuReboot -and $wuReboot.RebootRequired) {
                $requiresReboot = $true
            }

            try {
                $wmi = Get-WmiObject -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
                if ($wmi -and $wmi.PSBase.Properties['RebootRequired'] -and $wmi.RebootRequired) {
                    $requiresReboot = $true
                }
            }
            catch {
                # ignore WMI probe errors
            }

            return $requiresReboot
        }

        return [bool]$pendingReboot
    }
    catch {
        Write-Log "Could not determine reboot state for $($Session.ComputerName): $($_.Exception.Message)" -Level WARNING
        return $false
    }
}

function Remove-RemoteMSI {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Runspaces.PSSession]$Session,

        [Parameter(Mandatory = $true)]
        [string]$RemotePath
    )

    try {
        Invoke-Command -Session $Session -ScriptBlock {
            param($Path)
            if (Test-Path -Path $Path) {
                Remove-Item -Path $Path -Force -ErrorAction Stop
            }
        } -ArgumentList $RemotePath

        Write-Log "Removed remote installer from $($Session.ComputerName): $RemotePath" -Level SUCCESS
    }
    catch {
        Write-Log "Failed to remove remote installer from $($Session.ComputerName): $($_.Exception.Message)" -Level WARNING
    }
}

function New-Result {
    param(
        [string]$MachineName,
        [string]$Status,
        [int]$ExitCode,
        [string]$Message,
        [bool]$RebootRequired,
        [int]$Attempt,
        [datetime]$StartTime,
        [datetime]$EndTime
    )

    [pscustomobject]@{
        MachineName     = $MachineName
        Status          = $Status
        ExitCode        = $ExitCode
        ExitDescription = if ($ExitCode -ge 0) { Get-MSIExitDescription -ExitCode $ExitCode } else { $null }
        Message         = $Message
        RebootRequired  = $RebootRequired
        Attempt         = $Attempt
        StartTime       = $StartTime
        EndTime         = $EndTime
        DurationSeconds = [int]($EndTime - $StartTime).TotalSeconds
    }
}

function Invoke-MachineInstall {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$InstallerFile,

        [Parameter(Mandatory = $false)]
        [pscredential]$Credential,

        [Parameter(Mandatory = $true)]
        [int]$Attempt
    )

    $startTime = Get-Date
    $session = $null
    $exitCode = -1

    try {
        Write-Log "[$ComputerName] Attempt ${Attempt}: Creating remote session..." -Level INFO
        if ($Credential) {
            $session = New-PSSession -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop
        }
        else {
            $session = New-PSSession -ComputerName $ComputerName -ErrorAction Stop
        }

        Invoke-Command -Session $session -ScriptBlock {
            param($TempPath)
            if (-not (Test-Path -Path $TempPath)) {
                New-Item -Path $TempPath -ItemType Directory -Force | Out-Null
            }
        } -ArgumentList $RemoteTempPath

        $remoteInstallerPath = Join-Path -Path $RemoteTempPath -ChildPath $InstallerFile.Name

        $copySucceeded = Copy-MSIWithRetry -LocalPath $InstallerFile.FullName -RemotePath $remoteInstallerPath -Session $session
        if (-not $copySucceeded) {
            $endTime = Get-Date
            return New-Result -MachineName $ComputerName -Status 'Failed' -ExitCode -1 -Message 'Transfer aborted by operator.' -RebootRequired $false -Attempt $Attempt -StartTime $startTime -EndTime $endTime
        }

        Write-Log "[$ComputerName] Starting installer execution..." -Level INFO
        $exitCode = Invoke-Command -Session $session -ScriptBlock {
            param($RemotePath)
            $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/i', $RemotePath, '/quiet', '/norestart') -Wait -PassThru -NoNewWindow
            return [int]$process.ExitCode
        } -ArgumentList $remoteInstallerPath

        $desc = Get-MSIExitDescription -ExitCode $exitCode
        Write-Log "[$ComputerName] Installer completed with exit code $exitCode ($desc)." -Level INFO

        $success = $exitCode -in @(0, 1641, 3010)
        $rebootRequired = $exitCode -in @(1641, 3010)

        if ($success) {
            $pendingReboot = Test-PendingReboot -Session $session
            $rebootRequired = $rebootRequired -or $pendingReboot

            Remove-RemoteMSI -Session $session -RemotePath $remoteInstallerPath

            $endTime = Get-Date
            return New-Result -MachineName $ComputerName -Status 'Success' -ExitCode $exitCode -Message 'Installation completed successfully.' -RebootRequired $rebootRequired -Attempt $Attempt -StartTime $startTime -EndTime $endTime
        }

        if ($exitCode -eq 1619) {
            Write-Log "[$ComputerName] Exit code 1619 indicates package open/corruption issue. Removing remote installer copy." -Level WARNING
            Remove-RemoteMSI -Session $session -RemotePath $remoteInstallerPath
        }
        else {
            Write-Log "[$ComputerName] Installation failed. Preserving MSI on remote machine for retry/troubleshooting." -Level WARNING
        }

        $endTime = Get-Date
        return New-Result -MachineName $ComputerName -Status 'Failed' -ExitCode $exitCode -Message "Installation failed: $desc" -RebootRequired $false -Attempt $Attempt -StartTime $startTime -EndTime $endTime
    }
    catch {
        $endTime = Get-Date
        return New-Result -MachineName $ComputerName -Status 'Failed' -ExitCode $exitCode -Message "Execution error: $($_.Exception.Message)" -RebootRequired $false -Attempt $Attempt -StartTime $startTime -EndTime $endTime
    }
    finally {
        if ($session) {
            Remove-PSSession -Session $session -ErrorAction SilentlyContinue
        }
    }
}

function Read-RetryChoice {
    param(
        [Parameter(Mandatory = $true)]
        [string]$MachineName,

        [Parameter(Mandatory = $true)]
        [int]$Attempt,

        [Parameter(Mandatory = $true)]
        [int]$ExitCode,

        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter(Mandatory = $true)]
        [string]$FailureMessage
    )

    Write-Host "`nFAILED MACHINE: $MachineName" -ForegroundColor Red
    Write-Host "Attempt: $Attempt" -ForegroundColor Yellow
    Write-Host "Exit Code: $ExitCode" -ForegroundColor Yellow
    Write-Host "Description: $Description" -ForegroundColor Yellow
    Write-Host "Details: $FailureMessage" -ForegroundColor Yellow
    Write-Host 'Retry will run ONLY on failed machine(s), not the next batch.' -ForegroundColor Cyan
    Write-Host 'Options: [R]etry failed machine, [S]kip machine, [A]bort run' -ForegroundColor Cyan

    while ($true) {
        $choice = (Read-Host 'Select option').Trim().ToUpperInvariant()
        if ($choice -in @('R', 'S', 'A')) { return $choice }
        Write-Log 'Invalid choice. Enter R, S, or A.' -Level WARNING
    }
}

function Get-ChunkedArrays {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$InputArray,

        [Parameter(Mandatory = $true)]
        [int]$ChunkSize
    )

    $chunks = @()
    for ($i = 0; $i -lt $InputArray.Count; $i += $ChunkSize) {
        $end = [Math]::Min($i + $ChunkSize - 1, $InputArray.Count - 1)
        $chunks += ,(@($InputArray[$i..$end]))
    }
    return $chunks
}

function Update-BatchFileForSuccesses {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string[]]$SuccessfulMachines
    )

    if (-not (Test-Path -Path $FilePath -PathType Leaf)) {
        Write-Log "Batch file not found for update: $FilePath" -Level WARNING
        return
    }

    if ($SuccessfulMachines.Count -eq 0) {
        Write-Log 'No successful machines to mark in source file.' -Level INFO
        return
    }

    $successSet = @{}
    foreach ($machine in $SuccessfulMachines) {
        $successSet[$machine.ToUpperInvariant()] = $true
    }

    $lines = Get-Content -Path $FilePath
    $updatedLines = New-Object System.Collections.Generic.List[string]
    $commentedCount = 0

    foreach ($line in $lines) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            $updatedLines.Add($line)
            continue
        }

        $trimmed = $line.Trim()
        if ($trimmed.StartsWith('#')) {
            $updatedLines.Add($line)
            continue
        }

        $firstColumn = ($trimmed -split ',', 2)[0]
        $sanitized = ConvertTo-Hostname -RawName $firstColumn

        if ($sanitized -and $successSet.ContainsKey($sanitized.ToUpperInvariant())) {
            $updatedLines.Add("# $line")
            $commentedCount++
        }
        else {
            $updatedLines.Add($line)
        }
    }

    Set-Content -Path $FilePath -Value $updatedLines -Encoding UTF8
    Write-Log "Marked $commentedCount successful machine line(s) in '$FilePath'." -Level SUCCESS
}

function Invoke-Deployment {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Machines,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$InstallerFile,

        [Parameter(Mandatory = $false)]
        [pscredential]$Credential,

        [Parameter(Mandatory = $true)]
        [int]$ThrottleLimit,

        [Parameter(Mandatory = $true)]
        [bool]$InteractiveRetries
    )

    $results = New-Object System.Collections.Generic.List[object]
    $attemptMap = @{}

    $batchSize = [Math]::Max($ThrottleLimit, 1)
    $chunks = Get-ChunkedArrays -InputArray $Machines -ChunkSize $batchSize

    for ($chunkIndex = 0; $chunkIndex -lt $chunks.Count; $chunkIndex++) {
        $chunk = @($chunks[$chunkIndex])
        Write-Log "Starting batch $($chunkIndex + 1)/$($chunks.Count) with $($chunk.Count) machine(s)." -Level INFO

        $batchResults = New-Object System.Collections.Generic.List[object]
        foreach ($machine in $chunk) {
            if (-not $attemptMap.ContainsKey($machine)) {
                $attemptMap[$machine] = 0
            }
            $attemptMap[$machine]++
        }

        $canRunParallel = $batchSize -gt 1 -and $PSVersionTable.PSVersion.Major -ge 7
        if ($canRunParallel) {
            Write-Log "Running this batch in parallel with throttle $batchSize." -Level INFO
            Write-Log 'Multiple installer transfers are running concurrently. Transfer progress bars are intentionally suppressed.' -Level INFO

            $parallelResults = $chunk | ForEach-Object -Parallel {
                $installerFile = $using:InstallerFile
                $credential = $using:Credential
                $remoteTempPath = $using:RemoteTempPath
                $delays = $using:TransferRetryDelays

                $machine = $_
                $attempt = 1
                $startTime = Get-Date
                $session = $null
                $exitCode = -1

                function Get-ExitDesc {
                    param([int]$Code)
                    switch ($Code) {
                        0 { 'Success' }
                        1641 { 'Success, restart initiated' }
                        3010 { 'Success, reboot required' }
                        1601 { 'Windows Installer service unavailable' }
                        1602 { 'User cancelled installation' }
                        1603 { 'Fatal installation error' }
                        1618 { 'Another MSI installation is already in progress' }
                        1619 { 'Installer package could not be opened (possible corruption/inaccessible file)' }
                        1625 { 'Installation blocked by policy' }
                        1632 { 'Temporary folder inaccessible/full' }
                        1633 { 'Platform not supported' }
                        1638 { 'Another version of this product is already installed' }
                        default { 'Unknown MSI exit code' }
                    }
                }

                try {
                    if ($credential) {
                        $session = New-PSSession -ComputerName $machine -Credential $credential -ErrorAction Stop
                    }
                    else {
                        $session = New-PSSession -ComputerName $machine -ErrorAction Stop
                    }

                    Invoke-Command -Session $session -ScriptBlock {
                        param($TempPath)
                        if (-not (Test-Path -Path $TempPath)) {
                            New-Item -Path $TempPath -ItemType Directory -Force | Out-Null
                        }
                    } -ArgumentList $remoteTempPath

                    $remoteInstallerPath = Join-Path -Path $remoteTempPath -ChildPath $installerFile.Name
                    $copied = $false
                    for ($i = 0; $i -lt $delays.Count; $i++) {
                        try {
                            $previousProgressPreference = $ProgressPreference
                            $ProgressPreference = 'SilentlyContinue'
                            try {
                                Copy-Item -Path $installerFile.FullName -Destination $remoteInstallerPath -ToSession $session -Force -ErrorAction Stop
                            }
                            finally {
                                $ProgressPreference = $previousProgressPreference
                            }
                            $copied = $true
                            break
                        }
                        catch {
                            Start-Sleep -Seconds $delays[$i]
                        }
                    }

                    if (-not $copied) {
                        $endTime = Get-Date
                        return [pscustomobject]@{
                            MachineName     = $machine
                            Status          = 'Failed'
                            ExitCode        = -1
                            ExitDescription = $null
                            Message         = 'Transfer failed after retry delays in parallel mode.'
                            RebootRequired  = $false
                            Attempt         = $attempt
                            StartTime       = $startTime
                            EndTime         = $endTime
                            DurationSeconds = [int]($endTime - $startTime).TotalSeconds
                        }
                    }

                    $exitCode = Invoke-Command -Session $session -ScriptBlock {
                        param($RemotePath)
                        $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/i', $RemotePath, '/quiet', '/norestart') -Wait -PassThru -NoNewWindow
                        return [int]$process.ExitCode
                    } -ArgumentList $remoteInstallerPath

                    $success = $exitCode -in @(0, 1641, 3010)
                    $rebootRequired = $exitCode -in @(1641, 3010)

                    if ($success) {
                        try {
                            $pendingReboot = Invoke-Command -Session $session -ScriptBlock {
                                $requiresReboot = $false
                                $regPath1 = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
                                $regPath2 = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update'
                                $pendingRename = Get-ItemProperty -Path $regPath1 -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue
                                if ($pendingRename -and $pendingRename.PendingFileRenameOperations) { $requiresReboot = $true }
                                $wuReboot = Get-ItemProperty -Path $regPath2 -Name 'RebootRequired' -ErrorAction SilentlyContinue
                                if ($wuReboot -and $wuReboot.RebootRequired) { $requiresReboot = $true }
                                try {
                                    $wmi = Get-WmiObject -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
                                    if ($wmi -and $wmi.PSBase.Properties['RebootRequired'] -and $wmi.RebootRequired) { $requiresReboot = $true }
                                }
                                catch {}
                                return $requiresReboot
                            }
                            $rebootRequired = $rebootRequired -or [bool]$pendingReboot
                        }
                        catch {}

                        try {
                            Invoke-Command -Session $session -ScriptBlock {
                                param($Path)
                                if (Test-Path -Path $Path) { Remove-Item -Path $Path -Force -ErrorAction Stop }
                            } -ArgumentList $remoteInstallerPath
                        }
                        catch {}

                        $endTime = Get-Date
                        return [pscustomobject]@{
                            MachineName     = $machine
                            Status          = 'Success'
                            ExitCode        = $exitCode
                            ExitDescription = Get-ExitDesc -Code $exitCode
                            Message         = 'Installation completed successfully.'
                            RebootRequired  = $rebootRequired
                            Attempt         = $attempt
                            StartTime       = $startTime
                            EndTime         = $endTime
                            DurationSeconds = [int]($endTime - $startTime).TotalSeconds
                        }
                    }

                    if ($exitCode -eq 1619) {
                        try {
                            Invoke-Command -Session $session -ScriptBlock {
                                param($Path)
                                if (Test-Path -Path $Path) { Remove-Item -Path $Path -Force -ErrorAction Stop }
                            } -ArgumentList $remoteInstallerPath
                        }
                        catch {}
                    }

                    $endTime = Get-Date
                    return [pscustomobject]@{
                        MachineName     = $machine
                        Status          = 'Failed'
                        ExitCode        = $exitCode
                        ExitDescription = Get-ExitDesc -Code $exitCode
                        Message         = "Installation failed: $(Get-ExitDesc -Code $exitCode)"
                        RebootRequired  = $false
                        Attempt         = $attempt
                        StartTime       = $startTime
                        EndTime         = $endTime
                        DurationSeconds = [int]($endTime - $startTime).TotalSeconds
                    }
                }
                catch {
                    $endTime = Get-Date
                    return [pscustomobject]@{
                        MachineName     = $machine
                        Status          = 'Failed'
                        ExitCode        = $exitCode
                        ExitDescription = if ($exitCode -ge 0) { Get-ExitDesc -Code $exitCode } else { $null }
                        Message         = "Execution error: $($_.Exception.Message)"
                        RebootRequired  = $false
                        Attempt         = $attempt
                        StartTime       = $startTime
                        EndTime         = $endTime
                        DurationSeconds = [int]($endTime - $startTime).TotalSeconds
                    }
                }
                finally {
                    if ($session) {
                        Remove-PSSession -Session $session -ErrorAction SilentlyContinue
                    }
                }
            } -ThrottleLimit $batchSize

            foreach ($parallelResult in $parallelResults) {
                $parallelResult.Attempt = $attemptMap[$parallelResult.MachineName]
                $batchResults.Add($parallelResult)
                $results.Add($parallelResult)

                $desc = if ($parallelResult.ExitCode -ge 0) { "$($parallelResult.ExitCode) ($($parallelResult.ExitDescription))" } else { 'N/A' }
                Write-Log "[$($parallelResult.MachineName)] Result=$($parallelResult.Status), Attempt=$($parallelResult.Attempt), Exit=$desc" -Level INFO
            }
        }
        else {
            if ($batchSize -gt 1 -and $PSVersionTable.PSVersion.Major -lt 7) {
                Write-Log 'Parallel mode requested but PowerShell 7+ is required for runspace parallelism. Falling back to sequential execution.' -Level WARNING
            }

            foreach ($machine in $chunk) {
                $currentAttempt = $attemptMap[$machine]
                $result = Invoke-MachineInstall -ComputerName $machine -InstallerFile $InstallerFile -Credential $Credential -Attempt $currentAttempt
                $batchResults.Add($result)
                $results.Add($result)
            }
        }

        $remainingFailures = @($batchResults | Where-Object { $_.Status -eq 'Failed' })
        while ($InteractiveRetries -and $remainingFailures.Count -gt 0) {
            Write-Log "Batch $($chunkIndex + 1) completed with $($remainingFailures.Count) failed machine(s)." -Level WARNING
            $retryQueue = New-Object System.Collections.Generic.List[string]

            foreach ($failed in $remainingFailures) {
                $description = if ($failed.ExitCode -ge 0) { $failed.ExitDescription } else { 'Execution/connection error' }
                $choice = Read-RetryChoice -MachineName $failed.MachineName -Attempt $failed.Attempt -ExitCode $failed.ExitCode -Description $description -FailureMessage $failed.Message

                if ($choice -eq 'A') {
                    Write-Log 'Operator selected abort during retry prompt.' -Level ERROR
                    return $results
                }

                if ($choice -eq 'R') {
                    $retryQueue.Add($failed.MachineName)
                }
                else {
                    Write-Log "Operator skipped retry for $($failed.MachineName)." -Level INFO
                }
            }

            if ($retryQueue.Count -eq 0) {
                break
            }

            Write-Log "Retry round starting for failed machine(s) only: $($retryQueue -join ', ')" -Level INFO
            $newFailures = New-Object System.Collections.Generic.List[object]

            foreach ($retryMachine in $retryQueue) {
                $attemptMap[$retryMachine]++
                $retryAttempt = $attemptMap[$retryMachine]
                $retryResult = Invoke-MachineInstall -ComputerName $retryMachine -InstallerFile $InstallerFile -Credential $Credential -Attempt $retryAttempt
                $results.Add($retryResult)

                if ($retryResult.Status -eq 'Failed') {
                    $newFailures.Add($retryResult)
                }
            }

            $remainingFailures = @($newFailures)
        }
    }

    return $results
}

function Get-FinalResultPerMachine {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$AllResults
    )

    return $AllResults |
        Group-Object -Property MachineName |
        ForEach-Object {
            $_.Group | Sort-Object -Property EndTime -Descending | Select-Object -First 1
        }
}

function Write-Summary {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$FinalResults,

        [Parameter(Mandatory = $true)]
        [datetime]$RunStart
    )

    $successCount = @($FinalResults | Where-Object { $_.Status -eq 'Success' }).Count
    $failedCount = @($FinalResults | Where-Object { $_.Status -eq 'Failed' }).Count
    $totalCount = $FinalResults.Count
    $rebootCount = @($FinalResults | Where-Object { $_.RebootRequired }).Count
    $duration = (Get-Date) - $RunStart

    Write-Host "`n" + ('=' * 70)
    Write-Host 'Deployment Summary' -ForegroundColor Cyan
    Write-Host ('=' * 70)
    Write-Host "Total Machines: $totalCount"
    Write-Host "Successful: $successCount"
    Write-Host "Failed: $failedCount"
    Write-Host "Reboot Required: $rebootCount"
    Write-Host "Total Duration: $([int]$duration.TotalMinutes)m $($duration.Seconds)s"
    Write-Host "Log File: $script:LogPath"
    Write-Host ('=' * 70)

    Write-Log "Summary: Total=$totalCount, Success=$successCount, Failed=$failedCount, RebootRequired=$rebootCount, DurationSeconds=$([int]$duration.TotalSeconds)" -Level INFO

    $failureRows = @($FinalResults | Where-Object { $_.Status -eq 'Failed' })
    if ($failureRows.Count -gt 0) {
        Write-Log 'Failed machines detail:' -Level WARNING
        foreach ($row in $failureRows) {
            $desc = if ($row.ExitCode -ge 0) { "$($row.ExitCode) ($($row.ExitDescription))" } else { 'N/A' }
            Write-Log "  $($row.MachineName) | Attempts=$($row.Attempt) | Exit=$desc | Message=$($row.Message)" -Level WARNING
        }
    }
}

# ============================================================================
# MAIN FLOW
# ============================================================================

function Main {
    $runStart = Get-Date
    Initialize-RunLog
    Write-Log 'Run started.' -Level INFO

    try {
        Invoke-PowerShell7Bootstrap

        Test-InstallerFilesExist
        $installer = Get-MSIFile
        if ($null -eq $installer) {
            throw 'No installer selected.'
        }

        $mode = Get-ExecutionMode
        $machineListFile = $null
        $rawBatchMachines = @()

        if ($mode -eq 'Single') {
            $singleHost = Get-ValidatedSingleHostname
            Write-Log "Single-machine mode selected for '$singleHost'." -Level INFO

            $credential = Get-ValidatedCredentialForProbe -ProbeComputer $singleHost

            if (-not (Test-ComputerInAD -ComputerName $singleHost)) {
                throw "Target '$singleHost' failed AD/DNS validation."
            }

            if (-not (Test-ComputerOnline -ComputerName $singleHost)) {
                Write-Log "Target '$singleHost' did not pass online check. Execution will continue and may fail on session creation." -Level WARNING
            }

            $finalResults = Invoke-Deployment -Machines @($singleHost) -InstallerFile $installer -Credential $credential -ThrottleLimit 1 -InteractiveRetries $true
            $collapsed = Get-FinalResultPerMachine -AllResults $finalResults
            Write-Summary -FinalResults $collapsed -RunStart $runStart

            $failedFinal = @($collapsed | Where-Object { $_.Status -eq 'Failed' })
            if ($failedFinal.Count -gt 0) {
                exit 1
            }

            exit 0
        }

        # Batch mode
        $machineListFile = Find-BatchMachineFile
        Write-Log "Batch machine file selected: $machineListFile" -Level INFO

        $rawBatchMachines = Get-MachineNamesFromFile -FilePath $machineListFile
        if ($rawBatchMachines.Count -eq 0) {
            throw 'No valid machine names found in the selected file.'
        }

        $probeMachine = $rawBatchMachines[0]
        $credential = Get-ValidatedCredentialForProbe -ProbeComputer $probeMachine

        Write-Log 'Starting AD and online pre-validation for batch list.' -Level INFO
        $validatedMachines = Get-ValidatedBatchMachines -InputMachines $rawBatchMachines

        if ($validatedMachines.Count -eq 0) {
            throw 'No machines passed AD/online pre-validation.'
        }

        Write-Host "`nValidated machines ready for execution: $($validatedMachines.Count)" -ForegroundColor Cyan
        while ($true) {
            $parallelInput = (Read-Host 'Enter parallel thread count (1 for sequential)').Trim()
            $parallelCount = 0
            if ([int]::TryParse($parallelInput, [ref]$parallelCount) -and $parallelCount -ge 1) {
                break
            }
            Write-Log 'Invalid value. Enter a whole number >= 1.' -Level WARNING
        }

        if ($parallelCount -gt 1 -and $PSVersionTable.PSVersion.Major -lt 7) {
            Write-Log 'Parallel execution requested while current host is below PowerShell 7. Switching to sequential mode (throttle=1).' -Level WARNING
            $parallelCount = 1
        }

        Write-Log "Execution configured for $($validatedMachines.Count) machine(s) with throttle=$parallelCount." -Level INFO

        $allResults = Invoke-Deployment -Machines $validatedMachines -InstallerFile $installer -Credential $credential -ThrottleLimit $parallelCount -InteractiveRetries $true
        $finalPerMachine = Get-FinalResultPerMachine -AllResults $allResults

        $successfulMachines = @($finalPerMachine | Where-Object { $_.Status -eq 'Success' } | Select-Object -ExpandProperty MachineName)
        Update-BatchFileForSuccesses -FilePath $machineListFile -SuccessfulMachines $successfulMachines

        Write-Summary -FinalResults $finalPerMachine -RunStart $runStart

        $failedFinalBatch = @($finalPerMachine | Where-Object { $_.Status -eq 'Failed' })
        if ($failedFinalBatch.Count -gt 0) {
            exit 1
        }

        exit 0
    }
    catch {
        Write-Log "FATAL ERROR: $($_.Exception.Message)" -Level ERROR
        Write-Host "`n[DEPLOYMENT FAILED]" -ForegroundColor Red
        Write-Host "Log File: $script:LogPath" -ForegroundColor Yellow
        exit 1
    }
}

Main

Write-Host "`nScript execution finished. Press Enter to close this window..."
Read-Host | Out-Null



