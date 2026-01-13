<#
    .SYNOPSIS
    Installs the required modules and launches the AutopilotOOBE module with the parameters defined in this script

    .DESCRIPTION
    This is a wrapper around the AutopilotOOBE module that allows specifying the parameters used to configure it
    without having to dump a json to $env:ProgramData\OSDeploy\OSDeploy.AutopilotOOBE.json that would get left
    on the PC after provisioning.

    Authentication is handled via an Entra App Registration with certificate-based authentication.
    The certificate is embedded in the script (Base64 encoded) for fully automated, zero-prompt deployment.

    Info about the AutopilotOOBE module can be found here: https://autopilotoobe.osdeploy.com/parameters/reference

    .INPUTS
    None

    .OUTPUTS
    None

    .EXAMPLE
    The below URL will launch this script on the PC without having to do anything else.

    irm tinyurl.com/au-autopilot-test | iex

    .NOTES
    Version:        5.0
    Author:         Mark Newton
    Creation Date:  07/02/2024
    Updated by:     Robert Kocsis & Joe Laskowski
    Update Date:    01/13/2026
    Purpose/Change: Initial script development
    Update 2.0:     Added bypass for WAM (Web Account Manager) to avoid "Personal" or "Work Account" prompt
    Update 2.1:     Code cleanup - extracted WAM functions, added module version constraints
    Update 2.2:     Added duplicate device detection - removes existing Autopilot registration
    Update 3.0:     Added pre-flight checks, PSWriteColor module, transcript logging
    Update 3.1:     Microsoft documentation alignment - added group validation
    Update 4.0:     Enterprise authentication with Azure Key Vault
    Update 5.0:     Certificate-based authentication - fully automated, zero user interaction required.
                    Removed Key Vault dependency. Certificate embedded in script per MS best practices.

    #>

#Requires -Version 5.1
#Requires -RunAsAdministrator

##############################################################################################################
#                                          CONFIGURATION                                                     #
##############################################################################################################

$script:Config = @{
    # Entra App Registration
    TenantId = '34996142-c2c2-49f6-a30d-ccf73f568c9c'
    ClientId = 'bf98483c-c034-4338-802a-8bb0d84fb462'

    # Certificate (Base64-encoded PFX)
    CertificateBase64 = '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'
    CertificatePassword = 'TempExportPass123!'
}

##############################################################################################################
#                                                Functions                                                   #
##############################################################################################################

function Test-NetworkConnectivity {
    <#
    .SYNOPSIS
    Tests network connectivity to required Microsoft endpoints.
    #>
    [CmdletBinding()]
    param()

    $endpoints = @(
        @{ Name = 'Microsoft Graph'; Host = 'graph.microsoft.com' },
        @{ Name = 'Microsoft Login'; Host = 'login.microsoftonline.com' },
        @{ Name = 'PowerShell Gallery'; Host = 'www.powershellgallery.com' }
    )

    $allPassed = $true

    foreach ($endpoint in $endpoints) {
        try {
            $result = Test-NetConnection -ComputerName $endpoint.Host -Port 443 -WarningAction SilentlyContinue -ErrorAction Stop
            if ($result.TcpTestSucceeded) {
                Write-Host "  [OK] $($endpoint.Name) ($($endpoint.Host))" -ForegroundColor Green
            }
            else {
                Write-Host "  [FAIL] $($endpoint.Name) ($($endpoint.Host))" -ForegroundColor Red
                $allPassed = $false
            }
        }
        catch {
            Write-Host "  [FAIL] $($endpoint.Name) ($($endpoint.Host)) - $($_.Exception.Message)" -ForegroundColor Red
            $allPassed = $false
        }
    }

    return $allPassed
}

function Set-WAMState {
    <#
    .SYNOPSIS
    Enables or disables Web Account Manager (WAM) via registry settings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Enabled,
        [switch]$Silent
    )

    $regPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}',
        'HKLM:\SOFTWARE\Microsoft\IdentityStore\LoadParameters\{B16898C6-A148-4967-9171-64D755DA8520}',
        'HKLM:\SOFTWARE\Policies\Microsoft\AzureADAccount'
    )

    $value = if ($Enabled) { 1 } else { 0 }
    $errorAction = if ($Silent) { 'SilentlyContinue' } else { 'Stop' }

    foreach ($path in $regPaths) {
        try {
            if (-not (Test-Path $path)) {
                New-Item -Path $path -Force | Out-Null
            }
            Set-ItemProperty -Path $path -Name 'Enabled' -Value $value -Type DWord -Force -ErrorAction $errorAction
        }
        catch {
            if (-not $Silent) {
                Write-Warning "Failed to set WAM registry at $path : $($_.Exception.Message)"
            }
        }
    }
}

function Get-CertificateFromBase64 {
    <#
    .SYNOPSIS
    Creates an X509Certificate2 object from a Base64-encoded PFX string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Base64Pfx,
        [Parameter(Mandatory = $true)]
        [string]$Password
    )

    try {
        $pfxBytes = [System.Convert]::FromBase64String($Base64Pfx)
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            $pfxBytes,
            $Password,
            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
        )
        return $cert
    }
    catch {
        throw "Failed to load certificate from Base64: $($_.Exception.Message)"
    }
}

function Connect-GraphWithCertificate {
    <#
    .SYNOPSIS
    Connects to Microsoft Graph using certificate-based authentication.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    Write-Color -Text "Connecting to Microsoft Graph using certificate authentication..." -Color Yellow -ShowTime

    try {
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -Certificate $Certificate -NoWelcome -ErrorAction Stop

        $context = Get-MgContext
        if ($context) {
            Write-Color -Text "  Connected to tenant: ", "$($context.TenantId)" -Color Green, White -ShowTime
            Write-Color -Text "  Auth type: ", "Certificate (App-Only)" -Color Green, Cyan -ShowTime
            return $true
        }
        else {
            throw "Graph connection failed - no context available"
        }
    }
    catch {
        throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
    }
}

function Test-MgGraphConnection {
    <#
    .SYNOPSIS
    Validates that a Microsoft Graph connection exists.
    #>
    [CmdletBinding()]
    param()

    $context = Get-MgContext
    return ($null -ne $context)
}

function Remove-ExistingAutopilotDevice {
    <#
    .SYNOPSIS
    Checks if this device is already registered in Autopilot and removes it if found.
    #>
    [CmdletBinding()]
    param()

    $serialNumber = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
    if ([string]::IsNullOrWhiteSpace($serialNumber)) {
        Write-Color -Text "WARNING: Could not retrieve device serial number" -Color Yellow -ShowTime
        return $false
    }

    Write-Color -Text "Checking for existing Autopilot registration (Serial: ", "$serialNumber", ")..." -Color White, Cyan, White -ShowTime

    try {
        $existingDevices = Get-MgDeviceManagementWindowsAutopilotDeviceIdentity -Filter "contains(serialNumber,'$serialNumber')" -ErrorAction Stop

        if ($existingDevices) {
            $deviceCount = @($existingDevices).Count
            Write-Color -Text "Found ", "$deviceCount", " existing Autopilot registration(s)" -Color Yellow, Cyan, Yellow -ShowTime

            foreach ($device in $existingDevices) {
                Write-Color -Text "Removing existing registration: ", "$($device.Id)" -Color Yellow, White -ShowTime
                Remove-MgDeviceManagementWindowsAutopilotDeviceIdentity -WindowsAutopilotDeviceIdentityId $device.Id -ErrorAction Stop
                Write-Color -Text "Successfully removed existing Autopilot registration" -Color Green -ShowTime
            }

            Write-Color -Text "Waiting 10 seconds for deletion to propagate..." -Color Yellow -ShowTime
            Start-Sleep -Seconds 10
            return $true
        }
        else {
            Write-Color -Text "No existing Autopilot registration found - proceeding with fresh registration" -Color Green -ShowTime
            return $false
        }
    }
    catch {
        Write-Color -Text "WARNING: Error checking/removing existing Autopilot device: ", "$($_.Exception.Message)" -Color Yellow, White -ShowTime
        Write-Color -Text "Proceeding with registration anyway..." -Color Yellow -ShowTime
        return $false
    }
}

function Install-RequiredModule {
    <#
    .SYNOPSIS
    Installs a PowerShell module with progress indication.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [string]$MinimumVersion
    )

    $installParams = @{
        Name        = $Name
        Force       = $true
        ErrorAction = 'Stop'
    }

    if ($MinimumVersion) {
        $installParams['MinimumVersion'] = $MinimumVersion
    }

    $existing = Get-Module -Name $Name -ListAvailable | Where-Object {
        -not $MinimumVersion -or $_.Version -ge [version]$MinimumVersion
    } | Select-Object -First 1

    if ($existing) {
        Write-Color -Text "  [SKIP] ", "$Name", " v$($existing.Version) already installed" -Color DarkGray, White, DarkGray -ShowTime
        return
    }

    Write-Color -Text "  [INSTALL] ", "$Name", $(if ($MinimumVersion) { " (>= $MinimumVersion)" } else { "" }) -Color Yellow, White, DarkGray -ShowTime -NoNewLine

    try {
        Install-Module @installParams
        Write-Host " OK" -ForegroundColor Green
    }
    catch {
        Write-Host " FAILED" -ForegroundColor Red
        throw
    }
}

function Test-EntraGroupExists {
    <#
    .SYNOPSIS
    Validates that specified Entra ID groups exist before running AutopilotOOBE.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$GroupNames
    )

    $allExist = $true
    $missingGroups = @()

    Write-Color -Text "Validating Entra ID groups:" -Color Yellow -ShowTime

    foreach ($groupName in $GroupNames) {
        try {
            $group = Get-MgGroup -Filter "displayName eq '$groupName'" -ErrorAction Stop
            if ($group) {
                Write-Host "  [OK] $groupName" -ForegroundColor Green
            }
            else {
                Write-Host "  [MISSING] $groupName" -ForegroundColor Red
                $missingGroups += $groupName
                $allExist = $false
            }
        }
        catch {
            Write-Host "  [ERROR] $groupName - $($_.Exception.Message)" -ForegroundColor Red
            $missingGroups += $groupName
            $allExist = $false
        }
    }

    if (-not $allExist) {
        Write-Color -Text " "
        Write-Color -Text "WARNING: Some groups were not found in Entra ID" -Color Yellow -ShowTime
        foreach ($missing in $missingGroups) {
            Write-Color -Text "  - $missing" -Color White
        }
    }

    return $allExist
}

function Show-Banner {
    <#
    .SYNOPSIS
    Displays the Aunalytics ASCII banner.
    #>
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Color -Text "  __ _ ", " _   _ ", " _ __   __ _ | |_   _ | |_ (_) ___ ___ " -Color White, Cyan, White
    Write-Color -Text " / _` |", "| | | |", "| '_ \ / _` || | | | || __|| |/ __/ __|" -Color White, Cyan, White
    Write-Color -Text "| (_| |", "| |_| |", "| | | || (_| || | |_| || |_ | | (__\__ \" -Color White, Cyan, White
    Write-Color -Text " \__,_|", " \__,_|", "|_| |_| \__,_||_|\__, | \__||_|\___|___/" -Color White, Cyan, White
    Write-Color -Text "       ", "       ", "                 |___/                  " -Color White, Cyan, White
    Write-Host ""
    Write-Color -Text "AutopilotOOBE Prep ", "v5.0" -Color White, Cyan
    Write-Color -Text "Certificate Authentication (Zero-Prompt)" -Color DarkGray
    Write-Host ""
}

##############################################################################################################
#                                                   Main                                                     #
##############################################################################################################

$transcriptPath = Join-Path $env:TEMP "AutopilotOOBE_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $transcriptPath -Force | Out-Null

try {
    Clear-Host

    Set-ExecutionPolicy Unrestricted -Scope Process -Force
    Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted

    if ((Get-PackageProvider).Name -notcontains 'NuGet') {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
    }

    # Install PSWriteColor first for banner
    $psWriteColorInstalled = Get-Module -Name 'PSWriteColor' -ListAvailable
    if (-not $psWriteColorInstalled) {
        Write-Host "[SETUP] Installing PSWriteColor module..." -ForegroundColor Yellow
        Install-Module -Name 'PSWriteColor' -Force -ErrorAction Stop
    }
    Import-Module 'PSWriteColor' -Force

    Show-Banner

    Write-Color -Text "Note: ", "You can use Alt+Tab to switch to windows hidden behind OOBE. Naming: WAU####" -Color Red, White -LinesAfter 1
    Write-Color -Text "Log: ", "$transcriptPath" -Color DarkGray, White -ShowTime -LinesAfter 1

    # ==================== PRE-FLIGHT CHECKS ====================
    Write-Color -Text "Running pre-flight checks..." -Color White -ShowTime
    Write-Color -Text "Checking network connectivity:" -Color Yellow -ShowTime
    if (-not (Test-NetworkConnectivity)) {
        throw "Network connectivity check failed. Please ensure you have internet access."
    }
    Write-Color -Text "All network checks passed" -Color Green -ShowTime -LinesAfter 1

    # ==================== MODULE INSTALLATION ====================
    Write-Color -Text "Installing required PowerShell modules:" -Color White -ShowTime

    $modules = @(
        @{ Name = 'Microsoft.Graph.Authentication'; MinimumVersion = '2.0.0' },
        @{ Name = 'Microsoft.Graph.Groups'; MinimumVersion = '2.0.0' },
        @{ Name = 'Microsoft.Graph.Identity.DirectoryManagement'; MinimumVersion = '2.0.0' },
        @{ Name = 'Microsoft.Graph.DeviceManagement.Enrollment'; MinimumVersion = '2.0.0' },
        @{ Name = 'AutopilotOOBE'; MinimumVersion = '24.1.29' }
    )

    foreach ($module in $modules) {
        Install-RequiredModule -Name $module.Name -MinimumVersion $module.MinimumVersion
    }

    Write-Color -Text "Importing modules..." -Color Yellow -ShowTime
    Import-Module 'Microsoft.Graph.Authentication' -Force
    Import-Module 'Microsoft.Graph.Groups' -Force
    Import-Module 'Microsoft.Graph.Identity.DirectoryManagement' -Force
    Import-Module 'Microsoft.Graph.DeviceManagement.Enrollment' -Force
    Import-Module 'AutopilotOOBE' -Force
    Write-Color -Text "All modules loaded successfully" -Color Green -ShowTime -LinesAfter 1

    # ==================== WAM BYPASS ====================
    Write-Color -Text "Disabling Web Account Manager (WAM) via registry..." -Color Yellow -ShowTime
    Set-WAMState -Enabled $false

    # ==================== CERTIFICATE AUTHENTICATION ====================
    Write-Color -Text " "
    Write-Color -Text "Loading authentication certificate..." -Color Yellow -ShowTime
    $cert = Get-CertificateFromBase64 -Base64Pfx $script:Config.CertificateBase64 -Password $script:Config.CertificatePassword
    Write-Color -Text "  Certificate loaded: ", "$($cert.Subject)" -Color Green, White -ShowTime
    Write-Color -Text "  Thumbprint: ", "$($cert.Thumbprint)" -Color Green, White -ShowTime
    Write-Color -Text "  Expires: ", "$($cert.NotAfter)" -Color Green, White -ShowTime

    # ==================== GRAPH CONNECTION ====================
    Write-Color -Text " "
    if (-not (Test-MgGraphConnection)) {
        Connect-GraphWithCertificate `
            -TenantId $script:Config.TenantId `
            -ClientId $script:Config.ClientId `
            -Certificate $cert
    }
    else {
        Write-Color -Text "Already connected to Microsoft Graph" -Color Green -ShowTime
    }

    # Clear certificate from memory
    $cert = $null
    [System.GC]::Collect()

    # ==================== AUTOPILOT OOBE CONFIGURATION ====================
    $Params = [ordered]@{
        Title                       = 'Aunalytics Autopilot Registration'
        AssignedUserExample         = 'username@aunalytics.com'
        AddToGroup                  = 'AzPC - ENR - Enterprise'
        AddToGroupOptions           = 'AzPC - ENR - Enterprise', 'AzPC - ENR - Kiosk', 'AzPC - ENR - Shared'
        GroupTag                    = 'Enterprise'
        GroupTagOptions             = 'Enterprise', 'Kiosk', 'Shared'
        AssignedComputerNameExample = 'WAU####'
        PostAction                  = 'Restart'
        Assign                      = $true
        Run                         = 'WindowsSettings'
        Docs                        = 'https://autopilotoobe.osdeploy.com/'
    }

    # ==================== GROUP VALIDATION ====================
    Write-Color -Text " "
    $groupsToValidate = $Params['AddToGroupOptions']
    if (-not (Test-EntraGroupExists -GroupNames $groupsToValidate)) {
        Write-Color -Text "WARNING: Some groups could not be validated. Continuing anyway." -Color Yellow -ShowTime
    }
    else {
        Write-Color -Text "All groups validated successfully" -Color Green -ShowTime
    }

    # ==================== DUPLICATE DEVICE CHECK ====================
    Write-Color -Text " "
    Remove-ExistingAutopilotDevice | Out-Null

    # ==================== LAUNCH AUTOPILOT OOBE ====================
    Write-Color -Text " "
    Write-Color -Text "Starting AutopilotOOBE with configured parameters:" -Color White -ShowTime
    ForEach ($Param in $Params.Keys) {
        If ($Params[$Param].Count -gt 1) {
            Write-Color -Text "  $($Param): ", "$($Params[$Param] -join ', ')" -Color Yellow, White -ShowTime
        }
        Else {
            Write-Color -Text "  $($Param): ", "$($Params[$Param])" -Color Yellow, White -ShowTime
        }
    }

    Write-Color -Text " "

    AutopilotOOBE @Params

    Write-Color -Text "Restoring Web Account Manager (WAM) registry settings..." -Color Yellow -ShowTime
    Set-WAMState -Enabled $true
}
catch {
    Write-Color -Text " "
    Write-Color -Text "==================== ERROR ====================" -Color Red -ShowTime
    Write-Color -Text "Line: ", "$($_.InvocationInfo.ScriptLineNumber)" -Color Red, Magenta -ShowTime
    Write-Color -Text "Type: ", "$($_.Exception.GetType().FullName)" -Color Red, Magenta -ShowTime
    Write-Color -Text "Message: ", "$($_.Exception.Message)" -Color Red, White -ShowTime
    Write-Color -Text "===============================================" -Color Red -ShowTime
    Write-Color -Text " "

    $errorMessage = $_.Exception.Message
    if ($errorMessage -match 'certificate|pfx|base64') {
        Write-Color -Text "TROUBLESHOOTING: Certificate issue detected" -Color Cyan -ShowTime
        Write-Color -Text "  1. Verify the certificate was uploaded to the App Registration" -Color White
        Write-Color -Text "  2. Check that the Base64 string in the script is correct" -Color White
        Write-Color -Text "  3. Ensure the certificate hasn't expired" -Color White
    }
    elseif ($errorMessage -match 'Network|connection|timeout') {
        Write-Color -Text "TROUBLESHOOTING: Network issue detected" -Color Cyan -ShowTime
        Write-Color -Text "  1. Verify the device has internet access" -Color White
        Write-Color -Text "  2. Check if firewall is blocking HTTPS (port 443)" -Color White
    }
    elseif ($errorMessage -match 'permission|unauthorized|forbidden|403|AADSTS') {
        Write-Color -Text "TROUBLESHOOTING: Permission issue detected" -Color Cyan -ShowTime
        Write-Color -Text "  1. Verify App Registration has required API permissions" -Color White
        Write-Color -Text "  2. Ensure admin consent was granted" -Color White
        Write-Color -Text "  3. Check certificate is uploaded to App Registration" -Color White
    }

    Write-Color -Text " "
    Write-Color -Text "Log file: ", "$transcriptPath" -Color Yellow, White -ShowTime
}
finally {
    try {
        $cert = $null
        [System.GC]::Collect()
        Set-WAMState -Enabled $true -Silent
        Set-PSRepository -Name 'PSGallery' -InstallationPolicy Untrusted -ErrorAction SilentlyContinue | Out-Null
        Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
    }
    catch { }
}
