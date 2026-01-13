# Windows Autopilot OOBE Deployment Script

Automated Windows Autopilot device registration script designed for zero-touch deployment during OOBE (Out-of-Box Experience).

## Features

- **Zero-Prompt Authentication**: Certificate-based authentication via Entra App Registration
- **Duplicate Device Prevention**: Automatically removes existing Autopilot registrations before re-registering
- **Entra Group Validation**: Validates target group exists before running AutopilotOOBE
- **Transcript Logging**: Full session logging for troubleshooting
- **Progress Indicators**: Visual feedback during module installation and device registration

## Prerequisites

### Azure/Entra ID Setup

1. **Entra App Registration** with the following API permissions (Application type):
   - `DeviceManagementServiceConfig.ReadWrite.All`
   - `Device.ReadWrite.All`
   - `DeviceManagementManagedDevices.ReadWrite.All`
   - `Group.Read.All`

2. **Certificate Authentication**:
   - Upload the public key (`.cer`) to the App Registration under **Certificates & secrets**
   - Embed the Base64-encoded PFX in the script configuration

### PowerShell Modules (Auto-Installed)

- `Microsoft.Graph.Authentication` (v2.0.0+)
- `Microsoft.Graph.DeviceManagement` (v2.0.0+)
- `Microsoft.Graph.Identity.DirectoryManagement` (v2.0.0+)
- `WindowsAutopilotIntune` (v5.0+)
- `AutopilotOOBE` (v24.1.29+)
- `PSWriteColor` (v1.0.1+)

## Quick Start

### One-Line Deployment (During OOBE)

Press `Shift + F10` to open Command Prompt, then run:

```cmd
powershell -ExecutionPolicy Bypass -Command "irm https://tinyurl.com/au-autopilot-test | iex"
```

### Manual Execution

```powershell
.\autopilot.ps1
```

## Configuration

Edit the `$script:Config` hashtable in `autopilot.ps1`:

```powershell
$script:Config = @{
    TenantId           = 'your-tenant-id'
    ClientId           = 'your-app-registration-client-id'
    CertificateBase64  = 'your-base64-encoded-pfx'
    CertificatePassword = 'your-pfx-password'
    GroupTag           = 'YourGroupTag'
    AssignedUser       = 'user@domain.com'  # Optional
}
```

## Certificate Generation

Use the included `Generate-Certificate.ps1` script to create a self-signed certificate:

```powershell
.\Generate-Certificate.ps1
```

This creates:
- `AutopilotOOBE-Auth.cer` - Upload to App Registration
- `AutopilotOOBE-Auth.pfx` - Private key (keep secure)
- `AutopilotOOBE-Auth-Base64.txt` - Base64 string to embed in script

## Workflow

1. Checks for admin privileges and network connectivity
2. Installs required PowerShell modules from PSGallery
3. Authenticates to Microsoft Graph using certificate
4. Retrieves device hardware hash
5. Removes any existing Autopilot registration for this device
6. Registers device with Autopilot
7. Validates target Entra group exists
8. Launches AutopilotOOBE for user assignment

## Troubleshooting

Transcript logs are saved to:
```
C:\Windows\Temp\Autopilot-YYYYMMDD-HHmmss.log
```

## Security Notes

- Never commit certificate files (`.pfx`, `.cer`) or Base64 text files to source control
- The `.gitignore` file excludes sensitive files by default
- Consider rotating certificates before expiration (2-year validity)
- Use Azure Key Vault for production environments requiring centralized secret management

## Version

**v5.0** - Certificate Authentication (Zero-Prompt)

## License

Internal use only - Aunalytics
