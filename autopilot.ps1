<#
    .SYNOPSIS
    Installs the required modules and launches the AutopilotOOBE module with the parameters defined in this script

    .DESCRIPTION
    This is a wrapper around the AutopilotOOBE module that allows specifying the parameters used to configure it
    without having to dump a json to $env:ProgramData\OSDeploy\OSDeploy.AutopilotOOBE.json that would get left
    on the PC after provisioning.

    Authentication is handled via an Entra App Registration with client credentials stored in Azure Key Vault,
    eliminating the need for interactive device code authentication during OOBE.

    Info about the AutopilotOOBE module can be found here: https://autopilotoobe.osdeploy.com/parameters/reference

    .INPUTS
    None

    .OUTPUTS
    None

    .EXAMPLE
    The below URL will launch this script on the PC without having to do anything else. It loads the raw github
    of this script from: https://github.com/AU-RKocsis/AU-Autopilot/blob/main/AU-Autopilot.ps1

    irm https://tinyurl.com/AU-Autopilot | iex

    .NOTES
    Version:        4.0
    Author:         Mark Newton
    Creation Date:  07/02/2024
    Updated by:     Robert Kocsis & Joe Laskowski
    Update Date:    01/13/2025
    Purpose/Change: Initial script development
    Update 2.0:     Added bypass for WAM (Web Account Manager) to avoid "Personal" or "Work Account" prompt
                    Added connection success message, updated GUI to reflect current Computer Naming Standards
                    Moved to IIT GitHub Repository, updated URL in example, need to update tinyurl link as well
    Update 2.1:     Code cleanup - extracted WAM functions, added module version constraints,
                    scoped ExecutionPolicy to Process, added Graph connection validation,
                    removed duplicate code blocks
    Update 2.2:     Added duplicate device detection - removes existing Autopilot registration before
                    re-registering to prevent duplicate device records in Intune
    Update 3.0:     Major improvements - added pre-flight checks (admin, PowerShell version, network),
                    replaced embedded Write-Color with PSWriteColor module, added transcript logging,
                    added progress indicators for long operations
    Update 3.1:     Microsoft documentation alignment - added Group.ReadWrite.All scope for AddToGroup
                    functionality, added Entra group validation before AutopilotOOBE runs,
                    improved error messages with actionable guidance
    Update 4.0:     Enterprise authentication - replaced interactive device code flow with Entra App
                    Registration using client credentials from Azure Key Vault. No user interaction
                    required for Graph authentication. Added Az.KeyVault and Az.Accounts modules.

    #>

#Requires -Version 5.1
#Requires -RunAsAdministrator

##############################################################################################################
#                                          CONFIGURATION                                                     #
#  Update these values with your Entra App Registration and Key Vault details                               #
##############################################################################################################

$script:Config = @{
    # Entra App Registration (from Azure Portal > Entra ID > App registrations)
    TenantId     = '34996142-c2c2-49f6-a30d-ccf73f568c9c'   # Directory (tenant) ID
    ClientId     = 'bf98483c-c034-4338-802a-8bb0d84fb462'   # Application (client) ID

    # Azure Key Vault (where the client secret is stored)
    KeyVaultName = 'IITScriptKeyVault'             # Key Vault name
    SecretName   = 'AutopilotOOBE-ClientSecret'    # Secret name in Key Vault
}

##############################################################################################################
#                                                Functions                                                   #
##############################################################################################################

function Test-NetworkConnectivity {
    <#
    .SYNOPSIS
    Tests network connectivity to required Microsoft endpoints.

    .OUTPUTS
    Returns $true if connectivity is available, $false otherwise.
    #>
    [CmdletBinding()]
    param()

    $endpoints = @(
        @{ Name = 'Microsoft Graph'; Host = 'graph.microsoft.com' },
        @{ Name = 'Microsoft Login'; Host = 'login.microsoftonline.com' },
        @{ Name = 'Azure Key Vault'; Host = "$($script:Config.KeyVaultName).vault.azure.net" },
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

    .PARAMETER Enabled
    Set to $true to enable WAM, $false to disable it.

    .PARAMETER Silent
    Suppress error output if registry operations fail.
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

function Get-KeyVaultSecret {
    <#
    .SYNOPSIS
    Retrieves a secret from Azure Key Vault using managed identity or device code.

    .PARAMETER VaultName
    The name of the Key Vault.

    .PARAMETER SecretName
    The name of the secret to retrieve.

    .OUTPUTS
    Returns the secret value as a SecureString.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VaultName,

        [Parameter(Mandatory = $true)]
        [string]$SecretName
    )

    Write-Color -Text "Retrieving client secret from Azure Key Vault..." -Color Yellow -ShowTime

    try {
        # First, try to connect using managed identity (works in Azure VMs, Azure Arc, etc.)
        try {
            Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
            Write-Color -Text "  Connected to Azure using Managed Identity" -Color Green -ShowTime
        }
        catch {
            # Fall back to device code for non-Azure environments
            Write-Color -Text "  Managed Identity not available, using device code authentication..." -Color Yellow -ShowTime
            Write-Color -Text "  A code will be displayed. Enter it at ", "https://microsoft.com/devicelogin" -Color Cyan, White -ShowTime
            Connect-AzAccount -UseDeviceAuthentication -ErrorAction Stop | Out-Null
            Write-Color -Text "  Connected to Azure" -Color Green -ShowTime
        }

        # Retrieve the secret
        $secret = Get-AzKeyVaultSecret -VaultName $VaultName -Name $SecretName -ErrorAction Stop
        if (-not $secret) {
            throw "Secret '$SecretName' not found in Key Vault '$VaultName'"
        }

        Write-Color -Text "  Successfully retrieved secret from Key Vault" -Color Green -ShowTime
        return $secret.SecretValue
    }
    catch {
        throw "Failed to retrieve secret from Key Vault: $($_.Exception.Message)"
    }
}

function Connect-GraphWithAppRegistration {
    <#
    .SYNOPSIS
    Connects to Microsoft Graph using an Entra App Registration with client credentials.

    .PARAMETER TenantId
    The Entra tenant ID.

    .PARAMETER ClientId
    The application (client) ID.

    .PARAMETER ClientSecret
    The client secret as a SecureString.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,

        [Parameter(Mandatory = $true)]
        [string]$ClientId,

        [Parameter(Mandatory = $true)]
        [SecureString]$ClientSecret
    )

    Write-Color -Text "Connecting to Microsoft Graph using App Registration..." -Color Yellow -ShowTime

    try {
        # Create credential object
        $credential = New-Object System.Management.Automation.PSCredential($ClientId, $ClientSecret)

        # Connect to Graph with client credentials
        Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $credential -NoWelcome -ErrorAction Stop

        # Verify connection
        $context = Get-MgContext
        if ($context) {
            Write-Color -Text "  Connected as: ", "$($context.AppName)" -Color Green, White -ShowTime
            Write-Color -Text "  Tenant: ", "$($context.TenantId)" -Color Green, White -ShowTime
            Write-Color -Text "  Auth Type: ", "Client Credentials (App Registration)" -Color Green, Cyan -ShowTime
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

    .OUTPUTS
    Returns $true if connection exists, $false otherwise.
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

    .DESCRIPTION
    Queries Intune for existing Autopilot device registrations matching this device's
    serial number. If found, removes the existing registration to prevent duplicates.

    .OUTPUTS
    Returns $true if a device was found and removed, $false if no existing device was found.
    #>
    [CmdletBinding()]
    param()

    # Get the device serial number
    $serialNumber = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
    if ([string]::IsNullOrWhiteSpace($serialNumber)) {
        Write-Color -Text "WARNING: Could not retrieve device serial number" -Color Yellow -ShowTime
        return $false
    }

    Write-Color -Text "Checking for existing Autopilot registration (Serial: ", "$serialNumber", ")..." -Color White, Cyan, White -ShowTime

    try {
        # Query for existing Autopilot devices with this serial number
        $existingDevices = Get-MgDeviceManagementWindowsAutopilotDeviceIdentity -Filter "contains(serialNumber,'$serialNumber')" -ErrorAction Stop

        if ($existingDevices) {
            $deviceCount = @($existingDevices).Count
            Write-Color -Text "Found ", "$deviceCount", " existing Autopilot registration(s) for this device" -Color Yellow, Cyan, Yellow -ShowTime

            foreach ($device in $existingDevices) {
                Write-Color -Text "Removing existing registration: ", "$($device.Id)" -Color Yellow, White -ShowTime
                Remove-MgDeviceManagementWindowsAutopilotDeviceIdentity -WindowsAutopilotDeviceIdentityId $device.Id -ErrorAction Stop
                Write-Color -Text "Successfully removed existing Autopilot registration" -Color Green -ShowTime
            }

            # Wait for deletion to propagate before re-registering
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

    .PARAMETER Name
    The name of the module to install.

    .PARAMETER MinimumVersion
    The minimum version required.
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

    # Check if module is already installed with required version
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

    .PARAMETER GroupNames
    Array of group display names to validate.

    .OUTPUTS
    Returns $true if all groups exist, $false if any are missing.
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
        Write-Color -Text "WARNING: The following groups were not found in Entra ID:" -Color Yellow -ShowTime
        foreach ($missing in $missingGroups) {
            Write-Color -Text "  - $missing" -Color White -ShowTime
        }
        Write-Color -Text " "
        Write-Color -Text "Please verify:" -Color Cyan -ShowTime
        Write-Color -Text "  1. Group names are spelled correctly in the script" -Color White
        Write-Color -Text "  2. Groups exist in your Entra ID tenant" -Color White
        Write-Color -Text "  3. The App Registration has Group.Read.All permission" -Color White
    }

    return $allExist
}

function Test-ConfigurationValid {
    <#
    .SYNOPSIS
    Validates that the configuration values have been updated from placeholders.

    .OUTPUTS
    Returns $true if configuration is valid, throws error if placeholders detected.
    #>
    [CmdletBinding()]
    param()

    $errors = @()

    if ($script:Config.TenantId -eq 'YOUR-TENANT-ID-HERE' -or [string]::IsNullOrWhiteSpace($script:Config.TenantId)) {
        $errors += "TenantId is not configured"
    }

    if ($script:Config.ClientId -eq 'YOUR-CLIENT-ID-HERE' -or [string]::IsNullOrWhiteSpace($script:Config.ClientId)) {
        $errors += "ClientId is not configured"
    }

    if ($script:Config.KeyVaultName -eq 'YOUR-KEYVAULT-NAME' -or [string]::IsNullOrWhiteSpace($script:Config.KeyVaultName)) {
        $errors += "KeyVaultName is not configured"
    }

    if ($errors.Count -gt 0) {
        Write-Color -Text " "
        Write-Color -Text "CONFIGURATION ERROR: Please update the configuration section at the top of this script" -Color Red -ShowTime
        Write-Color -Text " "
        foreach ($err in $errors) {
            Write-Color -Text "  - $err" -Color Yellow
        }
        Write-Color -Text " "
        Write-Color -Text "Required values:" -Color Cyan -ShowTime
        Write-Color -Text "  TenantId     : Your Entra Directory (tenant) ID" -Color White
        Write-Color -Text "  ClientId     : Your App Registration Application (client) ID" -Color White
        Write-Color -Text "  KeyVaultName : Your Azure Key Vault name" -Color White
        Write-Color -Text "  SecretName   : Name of the secret containing the client secret" -Color White
        throw "Configuration is incomplete. Please update the values in the CONFIGURATION section."
    }

    return $true
}

function Show-Banner {
    <#
    .SYNOPSIS
    Displays the Aunalytics ASCII banner matching company branding.
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
    Write-Color -Text "AutopilotOOBE Prep ", "v4.0" -Color White, Cyan
    Write-Color -Text "Entra App + Azure Key Vault" -Color DarkGray
    Write-Host ""
}

##############################################################################################################
#                                                   Main                                                     #
##############################################################################################################

# Initialize transcript logging
$transcriptPath = Join-Path $env:TEMP "AutopilotOOBE_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $transcriptPath -Force | Out-Null

try {
    Clear-Host

    # Set execution policy to Unrestricted for this process only
    Set-ExecutionPolicy Unrestricted -Scope Process -Force

    # Set the PSGallery to trusted to automate installing modules
    Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted

    # Install NuGet provider if needed
    if ((Get-PackageProvider).Name -notcontains 'NuGet') {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
    }

    # Install PSWriteColor first so we can use it for the banner
    $psWriteColorInstalled = Get-Module -Name 'PSWriteColor' -ListAvailable
    if (-not $psWriteColorInstalled) {
        Write-Host "[SETUP] Installing PSWriteColor module..." -ForegroundColor Yellow
        Install-Module -Name 'PSWriteColor' -Force -ErrorAction Stop
    }
    Import-Module 'PSWriteColor' -Force

    # Now show the banner
    Show-Banner

    Write-Color -Text "Note: " , "You can use Alt+Tab to switch to windows that get hidden behind OOBE. Naming convention: WAU####" -Color Red, White -LinesAfter 1
    Write-Color -Text "Log file: ", "$transcriptPath" -Color DarkGray, White -ShowTime -LinesAfter 1

    # ==================== CONFIGURATION VALIDATION ====================
    Write-Color -Text "Validating configuration..." -Color White -ShowTime
    Test-ConfigurationValid | Out-Null
    Write-Color -Text "Configuration validated" -Color Green -ShowTime -LinesAfter 1

    # ==================== PRE-FLIGHT CHECKS ====================
    Write-Color -Text "Running pre-flight checks..." -Color White -ShowTime

    # Check network connectivity
    Write-Color -Text "Checking network connectivity:" -Color Yellow -ShowTime
    if (-not (Test-NetworkConnectivity)) {
        throw "Network connectivity check failed. Please ensure you have internet access and try again."
    }
    Write-Color -Text "All network checks passed" -Color Green -ShowTime -LinesAfter 1

    # ==================== MODULE INSTALLATION ====================
    Write-Color -Text "Installing required PowerShell modules:" -Color White -ShowTime

    $modules = @(
        @{ Name = 'Az.Accounts'; MinimumVersion = '2.0.0' },
        @{ Name = 'Az.KeyVault'; MinimumVersion = '4.0.0' },
        @{ Name = 'Microsoft.Graph.Authentication'; MinimumVersion = '2.0.0' },
        @{ Name = 'Microsoft.Graph.Groups'; MinimumVersion = '2.0.0' },
        @{ Name = 'Microsoft.Graph.Identity.DirectoryManagement'; MinimumVersion = '2.0.0' },
        @{ Name = 'Microsoft.Graph.DeviceManagement.Enrollment'; MinimumVersion = '2.0.0' },
        @{ Name = 'AutopilotOOBE'; MinimumVersion = '24.10.1' }
    )

    foreach ($module in $modules) {
        Install-RequiredModule -Name $module.Name -MinimumVersion $module.MinimumVersion
    }

    Write-Color -Text "Importing modules..." -Color Yellow -ShowTime
    Import-Module 'Az.Accounts' -Force
    Import-Module 'Az.KeyVault' -Force
    Import-Module 'Microsoft.Graph.Authentication' -Force
    Import-Module 'Microsoft.Graph.Groups' -Force
    Import-Module 'Microsoft.Graph.Identity.DirectoryManagement' -Force
    Import-Module 'Microsoft.Graph.DeviceManagement.Enrollment' -Force
    Import-Module 'AutopilotOOBE' -Force
    Write-Color -Text "All modules loaded successfully" -Color Green -ShowTime -LinesAfter 1

    # ==================== WAM BYPASS ====================
    Write-Color -Text "Disabling Web Account Manager (WAM) via registry..." -Color Yellow -ShowTime
    Set-WAMState -Enabled $false

    # ==================== AZURE KEY VAULT - RETRIEVE SECRET ====================
    Write-Color -Text " "
    $clientSecret = Get-KeyVaultSecret -VaultName $script:Config.KeyVaultName -SecretName $script:Config.SecretName

    # ==================== GRAPH CONNECTION ====================
    Write-Color -Text " "
    if (-not (Test-MgGraphConnection)) {
        Connect-GraphWithAppRegistration `
            -TenantId $script:Config.TenantId `
            -ClientId $script:Config.ClientId `
            -ClientSecret $clientSecret
    }
    else {
        Write-Color -Text "Already connected to Microsoft Graph" -Color Green -ShowTime
    }

    # Clear the secret from memory
    $clientSecret = $null
    [System.GC]::Collect()

    # ==================== AUTOPILOT OOBE CONFIGURATION ====================
    # Define AutopilotOOBE parameters first so we can validate groups
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
        Write-Color -Text " "
        Write-Color -Text "WARNING: Some groups could not be validated. AutopilotOOBE may fail if groups don't exist." -Color Yellow -ShowTime
        Write-Color -Text "Continuing anyway - AutopilotOOBE will show an error if the selected group is invalid." -Color Yellow -ShowTime
    }
    else {
        Write-Color -Text "All groups validated successfully" -Color Green -ShowTime
    }

    # ==================== DUPLICATE DEVICE CHECK ====================
    Write-Color -Text " "
    Remove-ExistingAutopilotDevice | Out-Null

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

    # Run AutopilotOOBE
    AutopilotOOBE @Params

    # Restore WAM
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

    # Provide actionable guidance based on error type
    $errorMessage = $_.Exception.Message
    if ($errorMessage -match 'Configuration is incomplete') {
        Write-Color -Text "TROUBLESHOOTING: Configuration not set" -Color Cyan -ShowTime
        Write-Color -Text "  1. Edit this script and find the CONFIGURATION section near the top" -Color White
        Write-Color -Text "  2. Replace placeholder values with your Entra App Registration details" -Color White
        Write-Color -Text "  3. Ensure your Key Vault name and secret name are correct" -Color White
    }
    elseif ($errorMessage -match 'Key Vault|secret|vault') {
        Write-Color -Text "TROUBLESHOOTING: Azure Key Vault issue detected" -Color Cyan -ShowTime
        Write-Color -Text "  1. Verify the Key Vault name is correct: $($script:Config.KeyVaultName)" -Color White
        Write-Color -Text "  2. Verify the secret exists: $($script:Config.SecretName)" -Color White
        Write-Color -Text "  3. Ensure the App Registration has 'Key Vault Secrets User' role on the vault" -Color White
        Write-Color -Text "  4. Check if Key Vault firewall allows access from this network" -Color White
    }
    elseif ($errorMessage -match 'Network|connection|timeout|unable to connect') {
        Write-Color -Text "TROUBLESHOOTING: Network connectivity issue detected" -Color Cyan -ShowTime
        Write-Color -Text "  1. Verify the device has internet access" -Color White
        Write-Color -Text "  2. Check if firewall is blocking outbound HTTPS (port 443)" -Color White
        Write-Color -Text "  3. Ensure graph.microsoft.com and login.microsoftonline.com are accessible" -Color White
    }
    elseif ($errorMessage -match 'scope|permission|unauthorized|forbidden|403|AADSTS') {
        Write-Color -Text "TROUBLESHOOTING: Permission issue detected" -Color Cyan -ShowTime
        Write-Color -Text "  1. Verify App Registration has these API permissions (Application type):" -Color White
        Write-Color -Text "     - DeviceManagementServiceConfig.ReadWrite.All" -Color White
        Write-Color -Text "     - Group.Read.All" -Color White
        Write-Color -Text "     - GroupMember.ReadWrite.All" -Color White
        Write-Color -Text "     - Device.ReadWrite.All" -Color White
        Write-Color -Text "  2. Ensure admin consent was granted for all permissions" -Color White
        Write-Color -Text "  3. Verify the client secret hasn't expired" -Color White
    }
    elseif ($errorMessage -match 'client.?secret|credential|AADSTS7000215') {
        Write-Color -Text "TROUBLESHOOTING: Client secret issue detected" -Color Cyan -ShowTime
        Write-Color -Text "  1. Verify the client secret in Key Vault is correct and not expired" -Color White
        Write-Color -Text "  2. Regenerate the secret in Entra if needed and update Key Vault" -Color White
        Write-Color -Text "  3. Ensure the secret value (not ID) was stored in Key Vault" -Color White
    }
    elseif ($errorMessage -match 'group|not found') {
        Write-Color -Text "TROUBLESHOOTING: Entra ID group issue detected" -Color Cyan -ShowTime
        Write-Color -Text "  1. Verify groups exist in Entra ID: AzPC - ENR - Enterprise, Kiosk, Shared" -Color White
        Write-Color -Text "  2. Ensure group names match exactly (case-sensitive)" -Color White
        Write-Color -Text "  3. Check the App Registration has Group.Read.All permission" -Color White
    }
    elseif ($errorMessage -match 'module|install') {
        Write-Color -Text "TROUBLESHOOTING: Module installation issue detected" -Color Cyan -ShowTime
        Write-Color -Text "  1. Ensure PowerShell Gallery (powershellgallery.com) is accessible" -Color White
        Write-Color -Text "  2. Try running: Install-Module Microsoft.Graph -Force" -Color White
        Write-Color -Text "  3. Check if TLS 1.2 is enabled: [Net.ServicePointManager]::SecurityProtocol" -Color White
    }

    Write-Color -Text " "
    Write-Color -Text "Log file: ", "$transcriptPath" -Color Yellow, White -ShowTime
    Write-Color -Text "For support, share the log file with your IT administrator." -Color DarkGray -ShowTime
}
finally {
    try {
        # Clear any sensitive data from memory
        $clientSecret = $null
        [System.GC]::Collect()

        # Disconnect from Azure (clear cached credentials)
        Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null

        # Ensure WAM is restored even if script errors out
        Set-WAMState -Enabled $true -Silent

        # Reset PSGallery trust
        Set-PSRepository -Name 'PSGallery' -InstallationPolicy Untrusted -ErrorAction SilentlyContinue | Out-Null

        # Stop transcript
        Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
    }
    catch {
        # Do nothing - cleanup should not throw
    }
}
