# Generate self-signed certificate for AutopilotOOBE App Registration
# Run this script on your local machine, NOT during OOBE

$certName = 'AutopilotOOBE-Auth'
$outputPath = 'C:\GitHub\Autopilot'
$pfxPassword = 'TempExportPass123!'

# Create the certificate (valid for 2 years)
$cert = New-SelfSignedCertificate `
    -Subject "CN=$certName" `
    -CertStoreLocation 'Cert:\CurrentUser\My' `
    -KeyExportPolicy Exportable `
    -KeySpec Signature `
    -KeyLength 2048 `
    -KeyAlgorithm RSA `
    -HashAlgorithm SHA256 `
    -NotAfter (Get-Date).AddYears(2)

# Export public key (.cer) - upload this to Azure App Registration
$cerPath = Join-Path $outputPath "$certName.cer"
Export-Certificate -Cert $cert -FilePath $cerPath | Out-Null

# Export private key (.pfx) - for Base64 encoding
$pfxPath = Join-Path $outputPath "$certName.pfx"
$securePassword = ConvertTo-SecureString -String $pfxPassword -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $securePassword | Out-Null

# Convert PFX to Base64 string
$pfxBytes = [System.IO.File]::ReadAllBytes($pfxPath)
$base64Pfx = [System.Convert]::ToBase64String($pfxBytes)

# Display results
Write-Host ""
Write-Host "=== CERTIFICATE CREATED ===" -ForegroundColor Green
Write-Host "Thumbprint: $($cert.Thumbprint)" -ForegroundColor Cyan
Write-Host "Subject: $($cert.Subject)"
Write-Host "Expires: $($cert.NotAfter)"
Write-Host ""
Write-Host "=== FILES CREATED ===" -ForegroundColor Green
Write-Host "Public key: $cerPath"
Write-Host "Private key: $pfxPath"
Write-Host ""
Write-Host "=== NEXT STEPS ===" -ForegroundColor Yellow
Write-Host "1. Upload '$cerPath' to your App Registration in Azure Portal"
Write-Host "   (App Registration > Certificates & secrets > Certificates > Upload)"
Write-Host ""
Write-Host "2. Copy the Base64 string below and save it - you'll need it for the script"
Write-Host ""
Write-Host "=== BASE64 PFX ===" -ForegroundColor Yellow
Write-Host $base64Pfx
Write-Host ""
Write-Host "=== PFX PASSWORD ===" -ForegroundColor Yellow
Write-Host $pfxPassword
Write-Host ""

# Also save Base64 to a file for convenience
$base64Path = Join-Path $outputPath "$certName-Base64.txt"
$base64Pfx | Out-File -FilePath $base64Path -Encoding UTF8
Write-Host "Base64 also saved to: $base64Path" -ForegroundColor DarkGray
