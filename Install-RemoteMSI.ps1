<#
.SYNOPSIS
    Remotely installs an MSI/MSIX package on one or more remote Windows machines.

.DESCRIPTION
    Supports single-machine and batch execution with:
    - Domain credential validation before heavy processing
    - Hostname sanitization
    - Batch input file discovery (CSV/TXT)
    - Five-state machine pre-validation (AD/DNS/reachability/WinRM)
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

function Resolve-ComputerIPAddresses {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    try {
        $records = Resolve-DnsName -Name $ComputerName -ErrorAction Stop
        $ips = @(
            $records |
                Where-Object { $_.IPAddress -and $_.Type -in @('A', 'AAAA') } |
                Select-Object -ExpandProperty IPAddress -Unique
        )

        return @($ips)
    }
    catch {
        return @()
    }
}

function Test-ComputerWinRM {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    try {
        Test-WSMan -ComputerName $ComputerName -ErrorAction Stop | Out-Null
        return $true
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

function Test-CurrentUserDomainAuth {
    try {
        $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        if ($null -eq $currentIdentity -or [string]::IsNullOrWhiteSpace($currentIdentity.Name)) {
            return $false
        }

        if (-not ($currentIdentity.Name.Contains('\'))) {
            return $false
        }

        $rootDse = [ADSI]'LDAP://RootDSE'
        $defaultNamingContext = [string]$rootDse.defaultNamingContext
        return -not [string]::IsNullOrWhiteSpace($defaultNamingContext)
    }
    catch {
        return $false
    }
}

function Test-DomainCredential {
    param(
        [Parameter(Mandatory = $true)]
        [pscredential]$Credential
    )

    $result = [pscustomobject]@{
        IsValid = $false
        Message = ''
    }

    try {
        $userNameRaw = [string]$Credential.UserName
        if ([string]::IsNullOrWhiteSpace($userNameRaw)) {
            $result.Message = 'Username is empty.'
            return $result
        }

        $userNameRaw = $userNameRaw.Trim()
        $domainName = $null
        $userNameForValidate = $userNameRaw

        if ($userNameRaw -match '^(?<domain>[^\\]+)\\(?<user>.+)$') {
            $domainName = $Matches['domain']
            $userNameForValidate = $Matches['user']
        }
        elseif ($userNameRaw -match '^(?<user>[^@]+)@(?<domain>.+)$') {
            $domainName = $Matches['domain']
            $userNameForValidate = $Matches['user']
        }
        else {
            if (-not [string]::IsNullOrWhiteSpace($env:USERDNSDOMAIN)) {
                $domainName = $env:USERDNSDOMAIN
            }
            elseif (-not [string]::IsNullOrWhiteSpace($env:USERDOMAIN)) {
                $domainName = $env:USERDOMAIN
            }
        }

        if ([string]::IsNullOrWhiteSpace($domainName)) {
            $result.Message = 'Could not determine domain for credential validation. Use DOMAIN\User or User@Domain.'
            return $result
        }

        $securePtr = [IntPtr]::Zero
        try {
            $securePtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)
            $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($securePtr)

            $context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext(
                [System.DirectoryServices.AccountManagement.ContextType]::Domain,
                $domainName
            )

            try {
                $isValid = $context.ValidateCredentials(
                    $userNameForValidate,
                    $plainPassword,
                    [System.DirectoryServices.AccountManagement.ContextOptions]::Negotiate
                )

                $result.IsValid = [bool]$isValid
                if ($result.IsValid) {
                    $result.Message = "Domain credential authentication succeeded for '$userNameRaw'."
                }
                else {
                    $result.Message = "Domain credential authentication failed for '$userNameRaw'."
                }
            }
            finally {
                if ($context) {
                    $context.Dispose()
                }
            }
        }
        finally {
            if ($securePtr -ne [IntPtr]::Zero) {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($securePtr)
            }
        }
    }
    catch {
        $result.Message = "Domain credential validation error: $($_.Exception.Message)"
    }

    return $result
}

function Get-ValidatedCredentialForDomain {
    Write-Log 'Validating credentials against domain services before deployment.' -Level INFO

    if (Test-CurrentUserDomainAuth) {
        Write-Log 'Current user domain authentication validated successfully.' -Level SUCCESS
        return $null
    }

    Write-Log 'Current user domain authentication could not be validated. Prompting for explicit credentials.' -Level WARNING

    $attempt = 0
    while ($attempt -lt $MaxCredentialAttempts) {
        $attempt++
        $credential = Request-Credentials -Message "Enter domain administrator credentials (attempt $attempt of $MaxCredentialAttempts)"
        if ($null -eq $credential) {
            throw 'Credential entry cancelled.'
        }

        $validationResult = Test-DomainCredential -Credential $credential
        if ($validationResult.IsValid) {
            Write-Log $validationResult.Message -Level SUCCESS
            return $credential
        }

        Write-Log $validationResult.Message -Level WARNING
    }

    throw "Failed to validate domain credentials after $MaxCredentialAttempts attempts."
}

function Get-EffectiveCredentialIdentity {
    param(
        [Parameter(Mandatory = $false)]
        [pscredential]$Credential
    )

    if ($Credential -and -not [string]::IsNullOrWhiteSpace($Credential.UserName)) {
        return $Credential.UserName
    }

    try {
        $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        if ($currentIdentity -and -not [string]::IsNullOrWhiteSpace($currentIdentity.Name)) {
            return $currentIdentity.Name
        }
    }
    catch {
        # ignore and fallback
    }

    if (-not [string]::IsNullOrWhiteSpace($env:USERDOMAIN) -and -not [string]::IsNullOrWhiteSpace($env:USERNAME)) {
        return "$($env:USERDOMAIN)\$($env:USERNAME)"
    }

    return 'UnknownIdentity'
}

function Get-CredentialAfterUserConfirmation {
    param(
        [Parameter(Mandatory = $false)]
        [pscredential]$CurrentCredential
    )

    $effectiveIdentity = Get-EffectiveCredentialIdentity -Credential $CurrentCredential
    Write-Log "Current account selected for remote execution: '$effectiveIdentity'." -Level INFO

    if (-not (Test-IsInteractiveSession)) {
        Write-Log 'Non-interactive session detected. Skipping credential switch prompt and continuing with selected account.' -Level WARNING
        return $CurrentCredential
    }

    $useAlternate = Read-YesNoChoice -Prompt "Current account is '$effectiveIdentity'. Use alternate credentials for remote execution?" -DefaultYes $false
    if (-not $useAlternate) {
        Write-Log "Operator accepted current account '$effectiveIdentity' for execution." -Level INFO
        return $CurrentCredential
    }

    $attempt = 0
    while ($attempt -lt $MaxCredentialAttempts) {
        $attempt++
        $alternateCredential = Request-Credentials -Message "Enter alternate domain credentials (attempt $attempt of $MaxCredentialAttempts)"
        if ($null -eq $alternateCredential) {
            throw 'Credential entry cancelled.'
        }

        $validationResult = Test-DomainCredential -Credential $alternateCredential
        if ($validationResult.IsValid) {
            Write-Log $validationResult.Message -Level SUCCESS
            Write-Log "Operator switched execution account to '$($alternateCredential.UserName)'." -Level INFO
            return $alternateCredential
        }

        Write-Log $validationResult.Message -Level WARNING
    }

    throw "Failed to validate alternate domain credentials after $MaxCredentialAttempts attempts."
}

function Invoke-AuthorizationCanaryCheck {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ReadyMachines,

        [Parameter(Mandatory = $false)]
        [pscredential]$Credential,

        [Parameter(Mandatory = $false)]
        [int]$MaxCanaryMachines = 3
    )

    if ($ReadyMachines.Count -eq 0) {
        return [pscustomobject]@{
            Success = $false
            TestedMachines = @()
            FailedChecks = @('No ready machines available for authorization canary check.')
        }
    }

    $canaryCount = [Math]::Min([Math]::Max($MaxCanaryMachines, 1), $ReadyMachines.Count)
    $testedMachines = @($ReadyMachines | Select-Object -First $canaryCount)

    Write-Log "Running authorization canary check on $canaryCount machine(s): $($testedMachines -join ', ')." -Level INFO

    $failedChecks = New-Object System.Collections.Generic.List[string]
    foreach ($machine in $testedMachines) {
        $session = $null
        try {
            if ($Credential) {
                $session = New-PSSession -ComputerName $machine -Credential $Credential -ErrorAction Stop
            }
            else {
                $session = New-PSSession -ComputerName $machine -ErrorAction Stop
            }

            $isAdmin = Test-RemoteAdmin -Session $session
            if (-not $isAdmin) {
                $failedChecks.Add("${machine}: Connected, but account is not local administrator.")
                Write-Log "[$machine] Canary authorization failed: account is not local administrator." -Level WARNING
                continue
            }

            Write-Log "[$machine] Canary authorization succeeded (remote admin confirmed)." -Level SUCCESS
        }
        catch {
            $failedChecks.Add("${machine}: $($_.Exception.Message)")
            Write-Log "[$machine] Canary authorization failed: $($_.Exception.Message)" -Level WARNING
        }
        finally {
            if ($session) {
                Remove-PSSession -Session $session -ErrorAction SilentlyContinue
            }
        }
    }

    return [pscustomobject]@{
        Success = $failedChecks.Count -eq 0
        TestedMachines = $testedMachines
        FailedChecks = @($failedChecks)
    }
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

function Get-MachineAvailabilityReport {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$InputMachines,

        [Parameter(Mandatory = $false)]
        [bool]$ShowProgressSpinner = $false,

        [Parameter(Mandatory = $false)]
        [string]$ProgressMessage = 'Machine-state validation in progress'
    )

    $readyMachines = New-Object System.Collections.Generic.List[string]
    $notInAD = New-Object System.Collections.Generic.List[string]
    $noDnsIp = New-Object System.Collections.Generic.List[string]
    $unreachable = New-Object System.Collections.Generic.List[string]
    $winRmUnavailable = New-Object System.Collections.Generic.List[string]
    $machineStates = New-Object System.Collections.Generic.List[object]

    # spinner animation removed because checks are blocking; we only display a static status line
    $totalMachines = $InputMachines.Count
    $machineIndex = 0
    $spinnerState = @{ LastLength = 0 }

    function Write-SpinnerStatusLine {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Text,

            [Parameter(Mandatory = $false)]
            [string]$Color = 'Cyan',

            [Parameter(Mandatory = $false)]
            [bool]$TerminateLine = $false
        )

        $padLength = [Math]::Max($spinnerState.LastLength - $Text.Length, 0)
        $padding = if ($padLength -gt 0) { ' ' * $padLength } else { '' }

        if ($TerminateLine) {
            Write-Host "`r$Text$padding" -ForegroundColor $Color
            $spinnerState.LastLength = 0
        }
        else {
            Write-Host "`r$Text$padding" -NoNewline -ForegroundColor $Color
            $spinnerState.LastLength = $Text.Length
        }
    }

    function Update-ValidationSpinner {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Stage
        )

        if (-not $ShowProgressSpinner) {
            return
        }

        $displayIndex = [Math]::Min($machineIndex + 1, [Math]::Max($totalMachines, 1))
        Write-SpinnerStatusLine -Text "$ProgressMessage [$displayIndex/$totalMachines] $Stage"
    }

    foreach ($machine in $InputMachines) {
        Update-ValidationSpinner -Stage "Evaluating $machine"
        Update-ValidationSpinner -Stage "[$machine] AD"

        if (-not (Test-ComputerInAD -ComputerName $machine)) {
            $notInAD.Add($machine)
            $machineStates.Add([pscustomobject]@{ MachineName = $machine; DerivedState = 'InvalidNameNotInAD' })
            $machineIndex++
            continue
        }

        Update-ValidationSpinner -Stage "[$machine] DNS"
        $ips = Resolve-ComputerIPAddresses -ComputerName $machine
        if ($ips.Count -eq 0) {
            $noDnsIp.Add($machine)
            $machineStates.Add([pscustomobject]@{ MachineName = $machine; DerivedState = 'ValidNoDNSIP' })
            $machineIndex++
            continue
        }

        Update-ValidationSpinner -Stage "[$machine] Reachability"
        if (-not (Test-ComputerOnline -ComputerName $machine)) {
            $unreachable.Add($machine)
            $machineStates.Add([pscustomobject]@{ MachineName = $machine; DerivedState = 'ReachabilityFailed' })
            $machineIndex++
            continue
        }

        Update-ValidationSpinner -Stage "[$machine] WinRM"
        if (-not (Test-ComputerWinRM -ComputerName $machine)) {
            $winRmUnavailable.Add($machine)
            $machineStates.Add([pscustomobject]@{ MachineName = $machine; DerivedState = 'WinRMUnavailable' })
            $machineIndex++
            continue
        }

        $readyMachines.Add($machine)
        $machineStates.Add([pscustomobject]@{ MachineName = $machine; DerivedState = 'ReadyMachines' })
        $machineIndex++
    }

    if ($ShowProgressSpinner -and $totalMachines -gt 0) {
        Write-SpinnerStatusLine -Text "$ProgressMessage completed ($totalMachines/$totalMachines)" -TerminateLine $true
    }

    Write-Log "Pre-validation summary: Total=$($InputMachines.Count), Ready=$($readyMachines.Count), InvalidNameNotInAD=$($notInAD.Count), ValidNoDNSIP=$($noDnsIp.Count), ReachabilityFailed=$($unreachable.Count), WinRMDisabled=$($winRmUnavailable.Count)" -Level INFO

    if ($notInAD.Count -gt 0) {
        Write-Log "Excluded (Invalid machine name - not found in AD/DC): $($notInAD -join ', ')" -Level WARNING
    }

    if ($noDnsIp.Count -gt 0) {
        Write-Log "Excluded (Valid in AD/DC but DNS returned no IP): $($noDnsIp -join ', ')" -Level WARNING
    }

    if ($unreachable.Count -gt 0) {
        Write-Log "Excluded (Valid name + IP, but unreachable by connection tests): $($unreachable -join ', ')" -Level WARNING
    }

    if ($winRmUnavailable.Count -gt 0) {
        Write-Log "Excluded (Reachable host, but WinRM/PS-Remoting unavailable): $($winRmUnavailable -join ', ')" -Level WARNING
    }

    if ($readyMachines.Count -gt 0) {
        Write-Log "Ready for deployment (fully reachable): $($readyMachines -join ', ')" -Level SUCCESS
    }

    return [pscustomobject]@{
        ReadyMachines      = @($readyMachines)
        InvalidNameNotInAD = @($notInAD)
        ValidNoDNSIP       = @($noDnsIp)
        ReachabilityFailed = @($unreachable)
        WinRMUnavailable   = @($winRmUnavailable)
        MachineStates      = $machineStates.ToArray()
    }
}

function Write-MachineStateValidationSummary {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$MachineStates,

        [Parameter(Mandatory = $true)]
        [datetime]$RunStart
    )

    $normalizedStates = @($MachineStates)
    $flattenedStates = New-Object System.Collections.Generic.List[object]
    foreach ($entry in $normalizedStates) {
        if ($entry -is [System.Collections.IEnumerable] -and -not ($entry -is [string]) -and -not ($entry -is [pscustomobject])) {
            foreach ($nested in $entry) {
                if ($null -ne $nested) {
                    $flattenedStates.Add($nested)
                }
            }
            continue
        }

        if ($null -ne $entry) {
            $flattenedStates.Add($entry)
        }
    }

    $states = $flattenedStates.ToArray()

    $duration = New-TimeSpan -Start $RunStart -End (Get-Date)
    $totalCount = $states.Count
    $readyCount = @($states | Where-Object { $_.DerivedState -eq 'ReadyMachines' }).Count

    Write-Host "`n" + ('=' * 70)
    Write-Host 'Deployment Summary' -ForegroundColor Cyan
    Write-Host ('=' * 70)
    Write-Host 'OVERALL RESULT: FAILED' -ForegroundColor Red
    Write-Host ('=' * 70)
    Write-Host "Total Machines: $totalCount"
    Write-Host "Successful: 0"
    Write-Host "Failed: $totalCount"
    Write-Host "Reboot Required: 0"
    Write-Host "Total Duration: $([int]$duration.TotalMinutes)m $($duration.Seconds)s"
    Write-Host "Log File: $script:LogPath"
    Write-Host ('=' * 70)

    $machineWidth = 22
    $stateWidth = 43

    $line = '+' + ('-' * $machineWidth) + '+' + ('-' * $stateWidth) + '+'
    $header = "|{0}|{1}|" -f @(
        'Machine'.PadRight($machineWidth),
        'Derived State'.PadRight($stateWidth)
    )

    Write-Host ''
    Write-Host 'Result Table' -ForegroundColor Cyan
    Write-Host $line
    Write-Host $header
    Write-Host $line

    foreach ($row in $states | Sort-Object -Property MachineName) {
        $machineValue = [string]$row.MachineName
        if ([string]::IsNullOrWhiteSpace($machineValue)) {
            $machineValue = 'Unknown'
        }
        if ($machineValue.Length -gt $machineWidth) {
            $machineValue = $machineValue.Substring(0, $machineWidth)
        }

        $stateValue = [string]$row.DerivedState
        if ([string]::IsNullOrWhiteSpace($stateValue)) {
            $stateValue = 'UnknownState'
        }
        if ($stateValue.Length -gt $stateWidth) {
            $stateValue = $stateValue.Substring(0, $stateWidth)
        }

        $machineCell = $machineValue.PadRight($machineWidth)
        $stateCell = $stateValue.PadRight($stateWidth)
        $rowLine = "|$machineCell|$stateCell|"

        $rowColor = if ($row.DerivedState -eq 'ReadyMachines') { 'Green' } else { 'Red' }
        Write-Host $rowLine -ForegroundColor $rowColor
    }

    Write-Host $line
    Write-Log "Pre-validation-only summary: Total=$totalCount, Ready=$readyCount, Excluded=$($totalCount - $readyCount), DurationSeconds=$([int]$duration.TotalSeconds)" -Level INFO
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
                Copy-Item -Path $LocalPath -Destination $RemotePath -ToSession $Session -Force -ErrorAction Stop
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

function Get-PendingRebootState {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Runspaces.PSSession]$Session
    )

    try {
        $pendingRebootState = Invoke-Command -Session $Session -ScriptBlock {
            $state = [ordered]@{
                PendingFileRenameOperations = $false
                WindowsUpdateRebootRequired = $false
                ComponentBasedServicingRebootPending = $false
                WmiRebootRequired = $false
            }

            try {
                $regPath1 = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
                $pendingRename = Get-ItemProperty -Path $regPath1 -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue
                if ($pendingRename -and $pendingRename.PendingFileRenameOperations) {
                    $state.PendingFileRenameOperations = $true
                }
            }
            catch {
                # ignore probe errors
            }

            try {
                $wuRebootPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
                if (Test-Path -Path $wuRebootPath) {
                    $state.WindowsUpdateRebootRequired = $true
                }
            }
            catch {
                # ignore probe errors
            }

            try {
                $cbsRebootPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
                if (Test-Path -Path $cbsRebootPath) {
                    $state.ComponentBasedServicingRebootPending = $true
                }
            }
            catch {
                # ignore probe errors
            }

            try {
                $wmi = Get-WmiObject -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
                if ($wmi -and $wmi.PSBase.Properties['RebootRequired'] -and $wmi.RebootRequired) {
                    $state.WmiRebootRequired = $true
                }
            }
            catch {
                # ignore WMI probe errors
            }

            $any = $state.PendingFileRenameOperations -or
                $state.WindowsUpdateRebootRequired -or
                $state.ComponentBasedServicingRebootPending -or
                $state.WmiRebootRequired

            [pscustomobject]@{
                ProbeSucceeded = $true
                Any = [bool]$any
                PendingFileRenameOperations = [bool]$state.PendingFileRenameOperations
                WindowsUpdateRebootRequired = [bool]$state.WindowsUpdateRebootRequired
                ComponentBasedServicingRebootPending = [bool]$state.ComponentBasedServicingRebootPending
                WmiRebootRequired = [bool]$state.WmiRebootRequired
            }
        }

        return $pendingRebootState
    }
    catch {
        Write-Log "Could not determine reboot state for $($Session.ComputerName): $($_.Exception.Message)" -Level WARNING
        return [pscustomobject]@{
            ProbeSucceeded = $false
            Any = $false
            PendingFileRenameOperations = $false
            WindowsUpdateRebootRequired = $false
            ComponentBasedServicingRebootPending = $false
            WmiRebootRequired = $false
        }
    }
}

function Get-RebootRequirementEvaluation {
    param(
        [Parameter(Mandatory = $true)]
        [int]$InstallerExitCode,

        [Parameter(Mandatory = $true)]
        [object]$BeforeState,

        [Parameter(Mandatory = $true)]
        [object]$AfterState
    )

    $exitCodeRequiresReboot = $InstallerExitCode -in @(1641, 3010)
    $beforeKnown = [bool]($BeforeState -and $BeforeState.ProbeSucceeded)
    $afterKnown = [bool]($AfterState -and $AfterState.ProbeSucceeded)

    $newPendingIndicators = $false
    if ($beforeKnown -and $afterKnown) {
        $newPendingIndicators =
            ((-not [bool]$BeforeState.PendingFileRenameOperations) -and [bool]$AfterState.PendingFileRenameOperations) -or
            ((-not [bool]$BeforeState.WindowsUpdateRebootRequired) -and [bool]$AfterState.WindowsUpdateRebootRequired) -or
            ((-not [bool]$BeforeState.ComponentBasedServicingRebootPending) -and [bool]$AfterState.ComponentBasedServicingRebootPending) -or
            ((-not [bool]$BeforeState.WmiRebootRequired) -and [bool]$AfterState.WmiRebootRequired)
    }

    $installationTriggered = $exitCodeRequiresReboot -or $newPendingIndicators
    $rebootRequired = $installationTriggered

    $message = if (-not $rebootRequired) {
        'No reboot is required due to this installation.'
    }
    else {
        'Reboot required due to this installation.'
    }

    return [pscustomobject]@{
        RebootRequired = [bool]$rebootRequired
        Message = $message
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

        $preInstallRebootState = Get-PendingRebootState -Session $session

        $copySucceeded = Copy-MSIWithRetry -LocalPath $InstallerFile.FullName -RemotePath $remoteInstallerPath -Session $session
        if (-not $copySucceeded) {
            $endTime = Get-Date
            return New-Result -MachineName $ComputerName -Status 'Failed' -ExitCode -1 -Message 'Transfer aborted by operator.' -RebootRequired $false -Attempt $Attempt -StartTime $startTime -EndTime $endTime
        }

        Write-Log "[$ComputerName] Starting installer execution..." -Level INFO
        $installJob = Invoke-Command -Session $session -AsJob -ScriptBlock {
            param($RemotePath)
            $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/i', $RemotePath, '/quiet', '/norestart') -Wait -PassThru -NoNewWindow
            return [int]$process.ExitCode
        } -ArgumentList $remoteInstallerPath

        $installSpinnerFrames = @('|', '/', '-', '\')
        $installSpinnerIndex = 0
        $installSpinnerMessage = "[$ComputerName] MSI installation in progress"

        while ($installJob.State -in @('NotStarted', 'Running', 'Blocked')) {
            $frame = $installSpinnerFrames[$installSpinnerIndex % $installSpinnerFrames.Count]
            Write-Host "`r[$frame] $installSpinnerMessage" -NoNewline -ForegroundColor Cyan
            $installSpinnerIndex++
            Start-Sleep -Milliseconds 150
        }

        Write-Host "`r[OK] $installSpinnerMessage" -ForegroundColor Cyan

        if ($installJob.State -ne 'Completed') {
            $state = $installJob.State
            Remove-Job -Job $installJob -Force -ErrorAction SilentlyContinue
            throw "Installer execution job ended in unexpected state '$state'."
        }

        $exitCodeOutput = @($installJob | Receive-Job -Keep)
        Remove-Job -Job $installJob -Force -ErrorAction SilentlyContinue
        if ($exitCodeOutput.Count -eq 0) {
            throw 'Installer execution did not return an exit code.'
        }

        $exitCode = [int]$exitCodeOutput[0]

        $desc = Get-MSIExitDescription -ExitCode $exitCode
        Write-Log "[$ComputerName] Installer completed with exit code $exitCode ($desc)." -Level INFO

        $success = $exitCode -in @(0, 1641, 3010)

        if ($success) {
            $postInstallRebootState = Get-PendingRebootState -Session $session
            $rebootEvaluation = Get-RebootRequirementEvaluation -InstallerExitCode $exitCode -BeforeState $preInstallRebootState -AfterState $postInstallRebootState
            $rebootRequired = [bool]$rebootEvaluation.RebootRequired
            $successMessage = "Installation completed successfully. $($rebootEvaluation.Message)"

            Write-Log "[$ComputerName] $($rebootEvaluation.Message)" -Level INFO

            Remove-RemoteMSI -Session $session -RemotePath $remoteInstallerPath

            $endTime = Get-Date
            return New-Result -MachineName $ComputerName -Status 'Success' -ExitCode $exitCode -Message $successMessage -RebootRequired $rebootRequired -Attempt $Attempt -StartTime $startTime -EndTime $endTime
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
    return ,$chunks
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
    Write-Log "Batch planner: Machines=$($Machines.Count), RequestedThrottle=$ThrottleLimit, EffectiveThrottle=$batchSize, PlannedBatches=$($chunks.Count), HostPS=$($PSVersionTable.PSVersion.Major)." -Level INFO

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

            $parallelJob = $chunk | ForEach-Object -Parallel {
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

                    function Get-RebootState {
                        param([System.Management.Automation.Runspaces.PSSession]$Session)

                        try {
                            $rebootState = Invoke-Command -Session $Session -ScriptBlock {
                                $state = [ordered]@{
                                    PendingFileRenameOperations = $false
                                    WindowsUpdateRebootRequired = $false
                                    ComponentBasedServicingRebootPending = $false
                                    WmiRebootRequired = $false
                                }

                                try {
                                    $regPath1 = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
                                    $pendingRename = Get-ItemProperty -Path $regPath1 -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue
                                    if ($pendingRename -and $pendingRename.PendingFileRenameOperations) {
                                        $state.PendingFileRenameOperations = $true
                                    }
                                }
                                catch {}

                                try {
                                    $wuRebootPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
                                    if (Test-Path -Path $wuRebootPath) {
                                        $state.WindowsUpdateRebootRequired = $true
                                    }
                                }
                                catch {}

                                try {
                                    $cbsRebootPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
                                    if (Test-Path -Path $cbsRebootPath) {
                                        $state.ComponentBasedServicingRebootPending = $true
                                    }
                                }
                                catch {}

                                try {
                                    $wmi = Get-WmiObject -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
                                    if ($wmi -and $wmi.PSBase.Properties['RebootRequired'] -and $wmi.RebootRequired) {
                                        $state.WmiRebootRequired = $true
                                    }
                                }
                                catch {}

                                $any = $state.PendingFileRenameOperations -or
                                    $state.WindowsUpdateRebootRequired -or
                                    $state.ComponentBasedServicingRebootPending -or
                                    $state.WmiRebootRequired

                                return [pscustomobject]@{
                                    ProbeSucceeded = $true
                                    Any = [bool]$any
                                    PendingFileRenameOperations = [bool]$state.PendingFileRenameOperations
                                    WindowsUpdateRebootRequired = [bool]$state.WindowsUpdateRebootRequired
                                    ComponentBasedServicingRebootPending = [bool]$state.ComponentBasedServicingRebootPending
                                    WmiRebootRequired = [bool]$state.WmiRebootRequired
                                }
                            }

                            return $rebootState
                        }
                        catch {
                            return [pscustomobject]@{
                                ProbeSucceeded = $false
                                Any = $false
                                PendingFileRenameOperations = $false
                                WindowsUpdateRebootRequired = $false
                                ComponentBasedServicingRebootPending = $false
                                WmiRebootRequired = $false
                            }
                        }
                    }

                    function Get-RebootEval {
                        param(
                            [int]$InstallerExitCode,
                            [object]$BeforeState,
                            [object]$AfterState
                        )

                        $exitCodeRequiresReboot = $InstallerExitCode -in @(1641, 3010)
                        $beforeKnown = [bool]($BeforeState -and $BeforeState.ProbeSucceeded)
                        $afterKnown = [bool]($AfterState -and $AfterState.ProbeSucceeded)

                        $newPendingIndicators = $false
                        if ($beforeKnown -and $afterKnown) {
                            $newPendingIndicators =
                                ((-not [bool]$BeforeState.PendingFileRenameOperations) -and [bool]$AfterState.PendingFileRenameOperations) -or
                                ((-not [bool]$BeforeState.WindowsUpdateRebootRequired) -and [bool]$AfterState.WindowsUpdateRebootRequired) -or
                                ((-not [bool]$BeforeState.ComponentBasedServicingRebootPending) -and [bool]$AfterState.ComponentBasedServicingRebootPending) -or
                                ((-not [bool]$BeforeState.WmiRebootRequired) -and [bool]$AfterState.WmiRebootRequired)
                        }

                        $installationTriggered = $exitCodeRequiresReboot -or $newPendingIndicators
                        $rebootRequired = $installationTriggered

                        $message = if (-not $rebootRequired) {
                            'No reboot is required due to this installation.'
                        }
                        else {
                            'Reboot required due to this installation.'
                        }

                        return [pscustomobject]@{
                            RebootRequired = [bool]$rebootRequired
                            Message = $message
                        }
                    }

                    Invoke-Command -Session $session -ScriptBlock {
                        param($TempPath)
                        if (-not (Test-Path -Path $TempPath)) {
                            New-Item -Path $TempPath -ItemType Directory -Force | Out-Null
                        }
                    } -ArgumentList $remoteTempPath

                    $preInstallRebootState = Get-RebootState -Session $session

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
                    $rebootRequired = $false
                    $successMessage = 'Installation completed successfully.'

                    if ($success) {
                        $postInstallRebootState = Get-RebootState -Session $session
                        $rebootEval = Get-RebootEval -InstallerExitCode $exitCode -BeforeState $preInstallRebootState -AfterState $postInstallRebootState
                        $rebootRequired = [bool]$rebootEval.RebootRequired
                        $successMessage = "Installation completed successfully. $($rebootEval.Message)"

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
                            Message         = $successMessage
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
            } -ThrottleLimit $batchSize -AsJob

            $batchSpinnerFrames = @('|', '/', '-', '\')
            $batchSpinnerIndex = 0
            $batchSpinnerMessage = "Batch $($chunkIndex + 1)/$($chunks.Count) active (parallel transfer/install in progress)"

            while ($parallelJob.State -in @('NotStarted', 'Running', 'Blocked')) {
                $frame = $batchSpinnerFrames[$batchSpinnerIndex % $batchSpinnerFrames.Count]
                Write-Host "`r[$frame] $batchSpinnerMessage" -NoNewline -ForegroundColor Cyan
                $batchSpinnerIndex++
                Start-Sleep -Milliseconds 150
            }

            Write-Host "`r[OK] $batchSpinnerMessage" -ForegroundColor Cyan

            if ($parallelJob.State -ne 'Completed') {
                $parallelState = $parallelJob.State
                Remove-Job -Job $parallelJob -Force -ErrorAction SilentlyContinue
                throw "Parallel batch processing ended with state '$parallelState'."
            }

            $parallelResults = @($parallelJob | Receive-Job -Keep)
            Remove-Job -Job $parallelJob -Force -ErrorAction SilentlyContinue

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
    $overallStatus = if ($failedCount -eq 0) { 'SUCCESS' } elseif ($successCount -gt 0) { 'PARTIAL SUCCESS' } else { 'FAILED' }
    $overallColor = if ($failedCount -eq 0) { 'Green' } elseif ($successCount -gt 0) { 'Yellow' } else { 'Red' }
    Write-Host "OVERALL RESULT: $overallStatus" -ForegroundColor $overallColor
    Write-Host ('=' * 70)
    Write-Host "Total Machines: $totalCount"
    Write-Host "Successful: $successCount"
    Write-Host "Failed: $failedCount"
    Write-Host "Reboot Required: $rebootCount"
    Write-Host "Total Duration: $([int]$duration.TotalMinutes)m $($duration.Seconds)s"
    Write-Host "Log File: $script:LogPath"
    Write-Host ('=' * 70)

    $machineWidth = 22
    $statusWidth = 10
    $attemptWidth = 8
    $exitWidth = 22
    $rebootWidth = 8
    $durationWidth = 10

    $line = '+' + ('-' * $machineWidth) + '+' + ('-' * $statusWidth) + '+' + ('-' * $attemptWidth) + '+' + ('-' * $exitWidth) + '+' + ('-' * $rebootWidth) + '+' + ('-' * $durationWidth) + '+'
    $header = "|{0}|{1}|{2}|{3}|{4}|{5}|" -f @(
        'Machine'.PadRight($machineWidth),
        'Status'.PadRight($statusWidth),
        'Attempt'.PadRight($attemptWidth),
        'Exit'.PadRight($exitWidth),
        'Reboot'.PadRight($rebootWidth),
        'Seconds'.PadRight($durationWidth)
    )

    Write-Host ''
    Write-Host 'Result Table' -ForegroundColor Cyan
    Write-Host $line
    Write-Host $header
    Write-Host $line

    foreach ($row in $FinalResults | Sort-Object -Property MachineName) {
        $machineValue = [string]$row.MachineName
        if ($machineValue.Length -gt $machineWidth) {
            $machineValue = $machineValue.Substring(0, $machineWidth)
        }

        $statusValue = [string]$row.Status
        $attemptValue = [string]$row.Attempt
        $exitValue = if ($row.ExitCode -ge 0) { "$($row.ExitCode) ($($row.ExitDescription))" } else { 'N/A' }
        if ($exitValue.Length -gt $exitWidth) {
            $exitValue = $exitValue.Substring(0, $exitWidth)
        }

        $rebootValue = if ($row.RebootRequired) { 'Yes' } else { 'No' }
        $secondsValue = [string]$row.DurationSeconds

        $rowLine = "|{0}|{1}|{2}|{3}|{4}|{5}|" -f @(
            $machineValue.PadRight($machineWidth),
            $statusValue.PadRight($statusWidth),
            $attemptValue.PadRight($attemptWidth),
            $exitValue.PadRight($exitWidth),
            $rebootValue.PadRight($rebootWidth),
            $secondsValue.PadRight($durationWidth)
        )

        $rowColor = if ($row.Status -eq 'Success') { 'Green' } else { 'Red' }
        Write-Host $rowLine -ForegroundColor $rowColor
    }

    Write-Host $line

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

            $credential = Get-ValidatedCredentialForDomain
            $credential = Get-CredentialAfterUserConfirmation -CurrentCredential $credential

            $singleReport = Get-MachineAvailabilityReport -InputMachines @($singleHost)
            if ($singleReport.ReadyMachines.Count -eq 0) {
                if ($singleReport.InvalidNameNotInAD.Count -gt 0) {
                    throw "Target '$singleHost' is invalid (not found in AD/DC)."
                }

                if ($singleReport.ValidNoDNSIP.Count -gt 0) {
                    throw "Target '$singleHost' is valid in AD/DC but DNS returned no IP."
                }

                if ($singleReport.ReachabilityFailed.Count -gt 0) {
                    throw "Target '$singleHost' has valid name/IP but is not reachable by connection tests."
                }

                if ($singleReport.WinRMUnavailable.Count -gt 0) {
                    throw "Target '$singleHost' is reachable but WinRM/PS-Remoting is not enabled."
                }

                throw "Target '$singleHost' failed availability validation."
            }

            $singleCanary = Invoke-AuthorizationCanaryCheck -ReadyMachines @($singleHost) -Credential $credential -MaxCanaryMachines 3
            if (-not $singleCanary.Success) {
                throw "Authorization canary check failed for single-machine run: $($singleCanary.FailedChecks -join ' | ')"
            }

            $finalResults = Invoke-Deployment -Machines @($singleHost) -InstallerFile $installer -Credential $credential -ThrottleLimit 1 -InteractiveRetries $true
            $collapsed = Get-FinalResultPerMachine -AllResults $finalResults
            Write-Summary -FinalResults $collapsed -RunStart $runStart

            $failedFinal = @($collapsed | Where-Object { $_.Status -eq 'Failed' })
            if ($failedFinal.Count -gt 0) {
                return 1
            }

            return 0
        }

        # Batch mode
        $machineListFile = Find-BatchMachineFile
        Write-Log "Batch machine file selected: $machineListFile" -Level INFO

        $rawBatchMachines = Get-MachineNamesFromFile -FilePath $machineListFile
        if ($rawBatchMachines.Count -eq 0) {
            throw 'No valid machine names found in the selected file.'
        }

        $credential = Get-ValidatedCredentialForDomain
        $credential = Get-CredentialAfterUserConfirmation -CurrentCredential $credential

        Write-Log 'Executing machine-state validation for batch processing list.' -Level INFO
        $availabilityReport = Get-MachineAvailabilityReport -InputMachines $rawBatchMachines -ShowProgressSpinner $true -ProgressMessage 'Machine-state validation in progress for batch processing list'
        $validatedMachines = @($availabilityReport.ReadyMachines)

        if ($validatedMachines.Count -eq 0) {
            Write-MachineStateValidationSummary -MachineStates $availabilityReport.MachineStates -RunStart $runStart
            throw 'No machines are fully reachable for deployment after pre-validation.'
        }

        $batchCanary = Invoke-AuthorizationCanaryCheck -ReadyMachines $validatedMachines -Credential $credential -MaxCanaryMachines 3
        if (-not $batchCanary.Success) {
            throw "Authorization canary check failed: $($batchCanary.FailedChecks -join ' | ')"
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
            return 1
        }

        return 0
    }
    catch {
        Write-Log "FATAL ERROR: $($_.Exception.Message)" -Level ERROR
        Write-Host "`n[DEPLOYMENT FAILED]" -ForegroundColor Red
        Write-Host "Log File: $script:LogPath" -ForegroundColor Yellow
        return 1
    }
}

$finalExitCode = Main

Write-Host "`nScript execution finished. Press Enter to close this window..."
Read-Host | Out-Null

exit $finalExitCode



