<#
.SYNOPSIS
Collect information for SecureBoot configuration
	
.DESCRIPTION
Collect information for SecureBoot configuration

.EXAMPLE 
C:\PS> get-UEFISecureBootInfo.ps1

.PARAMETER 	LogPath 
Path to Logfile.

.NOTES
Author     : Fabian Niesen (Dell EMC)
Filename   : get-UEFISecureBootInfo.ps1
Requires   : PowerShell Version 3.0
Version    : 1.1
History    : 1.0.0   FN  29.10.2018  initial version
             1.1.    FN  06.11.2018  Proxy Support
#>

Param(
  [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$False)]
  [String]$LogPath="C:\Temp\",
  [Boolean]$DellTools,
  [Boolean]$InstallDellTools=$false,
  [Boolean]$UseProxy
)

Write-Verbose "Check Admin privilages"
### Proof for administrative permissions (UAC) and start EventLog Handling
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole( [Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Error -Category PermissionDenied -Exception "Administrative Permissions required" -RecommendedAction "Run as administrator"
    break   
}

IF ($UseProxy -eq $true) 
{
  $proxy = [System.Net.WebRequest]::GetSystemWebProxy()
  $proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
  $IPPC = Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Proxy $proxy -ProxyCredential $($proxy.credentials)
  $IMC = Install-Module -Name DellBIOSProvider -RequiredVersion 1.0 -Force -Proxy $proxy -ProxyCredential $($proxy.credentials)
} ELSE {
  $IPPC = Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force 
  $IMC = Install-Module -Name DellBIOSProvider -RequiredVersion 1.0 -Force
} 

IF ($LogPath.EndsWith("\") -like "False") { $LogPath =$LogPath+"\" }
IF (!(Test-Path $LogPath)) { new-item -Path $LogPath -ItemType directory }
$hostname = Hostname
$date = get-date -format yyyyMMdd-HHmm
$file = $LogPath+$date+"-"+$hostname+"-UEFILog.txt"
$filebytes = $LogPath+$date+"-"+$hostname+"-UEFILog-Bytes.txt"

"Vendor: "+(Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer | Out-File $file -Append
"Device: "+(Get-WmiObject -Class:Win32_ComputerSystem).Model | Out-File $file -Append
"Serial: "+(Get-WmiObject -Class:Win32_BIOS).SerialNumber | Out-File $file -Append
"Bios Ver.: "+(Get-WmiObject -Class:Win32_BIOS).SMBIOSBIOSVersion | Out-File $file -Append

IF ( (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer -like "Dell*")
{
  # Test VC2010 und VC2012

  Write-Output "Dell detected, starting BIOS analysis"
  IF ((get-Module -Name DellBIOSProvider).count -lt 1) 
    {
    Write-Verbose "Test DellBIOSProvider"
      Try
        {
          Import-Module DellBIOSProvider
        }
      Catch
        {         
          Write-Verbose "Modul DellBiosProvider not found"
        }
    }
    IF ( (get-Module -Name DellBIOSProvider).count -lt 1)
    {
      Write-Output "Install needed Modules"
      Write-Verbose "Install NuGet"
      Try { $IPPC } catch {Write-Warning "NuGet installation failed"}
      Write-Verbose "Install DellBIOSProvider"
      Try { $IMC } catch {Write-Warning "DellBIOSProvider installation failed"}
      Import-Module DellBIOSProvider
    }
    Write-Verbose "Test DellBIOSProvider Path"
  $DellTools = $true
  Try { ( Test-Path DellSmbios:\ ) -eq $true } Catch { Write-Warning "Dell Bios Tools failed"; $DellTools = $false }
  Write-Verbose "DellTools: $DellTools"
  IF ( $DellTools -eq $true)
  { 
  Write-Verbose "Start Dell Bios query"
  $DellBIOS = get-childitem -path DellSmbios:\ | select category | foreach { get-childitem -path @("DellSmbios:\" + $_.Category)  | select attribute, currentvalue, possiblevalues } | Sort-Object -Property attribute
  $DellBIOS | FT -AutoSize |Out-File $file -Append
  } ELSE { "Dell Tools Failed"|Out-File $file -Append}
}
IF (Confirm-SecureBootUEFI) {"SecureBoot enabled" | Out-File $file -Append}
ELSE {"SecureBoot disabled" | Out-File $file -Append}

"--- SecureBoot Policy ---"| Out-File $file -Append
Get-SecureBootPolicy | ft -AutoSize | Out-File $file -Append

### Start Get-SecureBootUEFI queries ###

"--- db ---" | Out-File $file -Append
"--- db ---" | Out-File $filebytes -Append
try
{
  Get-SecureBootUEFI -Name db | fl | Out-File $file -Append 
}
catch
{
  "No Values provided" | Out-File $file -Append
}

Try
{
  [System.BitConverter]::ToString((Get-SecureBootUEFI -Name db).Bytes) | Out-File $filebytes -Append
}
catch
{
  "No Bytes provided" | Out-File $filebytes -Append
}

"--- dbt ---" | Out-File $file -Append
"--- dbt ---" | Out-File $filebytes -Append 

try
{
Get-SecureBootUEFI -Name dbt | fl | Out-File $file -Append
}
catch
{
  "No Values provided" | Out-File $file -Append
}
Try
{
  [System.BitConverter]::ToString((Get-SecureBootUEFI -Name dbt).Bytes) | Out-File $filebytes -Append
}
catch
{
  "No Bytes provided" | Out-File $filebytes -Append
}

"--- dbx ---" | Out-File $file -Append
"--- dbx ---" | Out-File $filebytes -Append
try
{
Get-SecureBootUEFI -Name dbx | fl -Expand| Out-File $file -Append
}
catch
{
  "No Values provided" | Out-File $file -Append
}
Try
{
  [System.BitConverter]::ToString((Get-SecureBootUEFI -Name dbx).Bytes) | Out-File $filebytes -Append
}
catch
{
  "No Bytes provided" | Out-File $filebytes -Append
}

"--- dbDefault ---" | Out-File $file -Append
"--- dbDefault ---" | Out-File $filebytes -Append
try
{
Get-SecureBootUEFI -Name dbDefault | fl | Out-File $file -Append
}
catch
{
  "No Values provided" | Out-File $file -Append
}
Try
{
  [System.BitConverter]::ToString((Get-SecureBootUEFI -Name dbDefault).Bytes) | Out-File $filebytes -Append
}
catch
{
  "No Bytes provided" | Out-File $filebytes -Append
}

"--- dbtDefault ---" | Out-File $file -Append
"--- dbtDefault ---" | Out-File $filebytes -Append
try
{
Get-SecureBootUEFI -Name dbtDefault | fl | Out-File $file -Append
}
catch
{
  "No Values provided" | Out-File $file -Append
}
Try
{
  [System.BitConverter]::ToString((Get-SecureBootUEFI -Name dbtDefault).Bytes) | Out-File $filebytes -Append
}
catch
{
  "No Bytes provided" | Out-File $filebytes -Append
}

"--- dbxDefault ---" | Out-File $file -Append
"--- dbxDefault ---" | Out-File $filebytes -Append
try
{
Get-SecureBootUEFI -Name dbxDefault | fl | Out-File $file -Append
}
catch
{
  "No Values provided" | Out-File $file -Append
}
Try
{
  [System.BitConverter]::ToString((Get-SecureBootUEFI -Name dbxDefault).Bytes) | Out-File $filebytes -Append
}
catch
{
  "No Bytes provided" | Out-File $filebytes -Append
}

"--- KEK ---" | Out-File $file -Append
"--- KEK ---" | Out-File $filebytes -Append
try
{
Get-SecureBootUEFI -Name KEK | fl | Out-File $file -Append
}
catch
{
  "No Values provided" | Out-File $file -Append
}
Try
{
  [System.BitConverter]::ToString((Get-SecureBootUEFI -Name KEK).Bytes) | Out-File $filebytes -Append
}
catch
{
  "No Bytes provided" | Out-File $filebytes -Append
}

"--- KEKDefault --" | Out-File $file -Append
"--- KEKDefault --" | Out-File $filebytes -Append
try
{
Get-SecureBootUEFI -Name KEKDefault | fl | Out-File $file -Append
}
catch
{
  "No Values provided" | Out-File $file -Append
}
Try
{
  [System.BitConverter]::ToString((Get-SecureBootUEFI -Name KEKDefault).Bytes) | Out-File $filebytes -Append
}
catch
{
  "No Bytes provided" | Out-File $filebytes -Append
}

"--- PK ---" | Out-File $file -Append
"--- PK ---" | Out-File $filebytes -Append
try
{
Get-SecureBootUEFI -Name PK | fl | Out-File $file -Append
}
catch
{
  "No Values provided" | Out-File $file -Append
}
Try
{
  [System.BitConverter]::ToString((Get-SecureBootUEFI -Name PK).Bytes) | Out-File $filebytes -Append
}
catch
{
  "No Bytes provided" | Out-File $filebytes -Append
}
"--- PKDefault ---" | Out-File $file -Append
"--- PKDefault ---" | Out-File $filebytes -Append
try
{
Get-SecureBootUEFI -Name PKDefault | fl | Out-File $file -Append
}
catch
{
  "No Values provided" | Out-File $file -Append
}
Try
{
  [System.BitConverter]::ToString((Get-SecureBootUEFI -Name PKDefault).Bytes) | Out-File $filebytes -Append
}
catch
{
  "No Bytes provided" | Out-File $filebytes -Append
}
"--- SecureBoot ---" | Out-File $file -Append
"--- SecureBoot ---" | Out-File $filebytes -Append
try
{
Get-SecureBootUEFI -Name SecureBoot | fl | Out-File $file -Append
}
catch
{
  "No Values provided" | Out-File $file -Append
}
Try
{
  [System.BitConverter]::ToString((Get-SecureBootUEFI -Name SecureBoot).Bytes) | Out-File $filebytes -Append
}
catch
{
  "No Bytes provided" | Out-File $filebytes -Append
}
"--- SetupMode ---"  | Out-File $file -Append
"--- SetupMode ---"  | Out-File $filebytes -Append

try
{
Get-SecureBootUEFI -Name SetupMode | fl | Out-File $file -Append
}
catch
{
  "No Values provided" | Out-File $file -Append
}
Try
{
  [System.BitConverter]::ToString((Get-SecureBootUEFI -Name SetupMode).Bytes) | Out-File $filebytes -Append
}
catch
{
  "No Bytes provided" | Out-File $filebytes -Append
}
Write-Output "Logfile written to $file"
Write-Output "Bytes Logfile written to $filebytes"