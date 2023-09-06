# Standalone application install script for VDI environment - (C)2023 Jonathan Pitre

#Requires -Version 5.1
#Requires -RunAsAdministrator

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

#region Initialisations

$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"
# Set the script execution policy for this process
Try { Set-ExecutionPolicy -ExecutionPolicy 'ByPass' -Scope 'Process' -Force } Catch {}
# Unblock ps1 script
Get-ChildItem -Recurse *.ps*1 | Unblock-File
$env:SEE_MASK_NOZONECHECKS = 1
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
[array]$Modules = @("PSADT") # Modules list

Function Get-ScriptPath
{
    <#
    .SYNOPSIS
        Get-ScriptPath returns the path of the current script.
    .OUTPUTS
        System.string
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param()

    Begin
    {
        Remove-Variable appScriptPath
    }
    Process
    {
        If ($psEditor) { Split-Path -Path $psEditor.GetEditorContext().CurrentFile.Path } # Visual Studio Code
        ElseIf ($MyInvocation.MyCommand.CommandType -eq "ExternalScript") { Split-Path -Path $My$MyInvocation.MyCommand.Source } # PS1 converted to EXE
        ElseIf ($null -ne $HostInvocation) { $HostInvocation.MyCommand.Path } # SAPIEN PowerShell Studio
        ElseIf ($psISE) { Split-Path -Path $psISE.CurrentFile.FullPath } # Windows PowerShell ISE
        ElseIf ($MyInvocation.PSScriptRoot) { $MyInvocation.PSScriptRoot } # Windows PowerShell 3.0+
        ElseIf ($MyInvocation.MyCommand.Path) { Split-Path -Path $MyInvocation.MyCommand.Path -Parent } # Windows PowerShell
        Else
        {
            Write-Host -Object "Unable to resolve script's file path!" -ForegroundColor Red
            Exit 1
        }
    }
}

Function Get-ScriptName
{
    <#
    .SYNOPSIS
        Get-ScriptName returns the name of the current script.
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param()
    Begin
    {
        Remove-Variable appScriptName
    }
    Process
    {
        If ($psEditor) { Split-Path -Path $psEditor.GetEditorContext().CurrentFile.Path -Leaf } # Visual Studio Code Host
        ElseIf ($psEXE) { [System.Diagnotics.Process]::GetCurrentProcess.Name } # PS1 converted to EXE
        ElseIf ($null -ne $HostInvocation) { $HostInvocation.MyCommand.Name } # SAPIEN PowerShell Studio
        ElseIf ($psISE) { $psISE.CurrentFile.DisplayName.Trim("*") } # Windows PowerShell ISE
        ElseIf ($MyInvocation.PSCommandPath) { Split-Path -Path $MyInvocation.PSCommandPath -Leaf } # Windows PowerShell
        Else
        {
            Write-Host -Object "Uanble to resolve script's file name!" -ForegroundColor Red
            Exit 1
        }
    }
}

Function Initialize-Module
{
    <#
    .SYNOPSIS
        Initialize-Module install and import modules from PowerShell Galllery.
    .OUTPUTS
        System.string
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Module
    )
    Write-Host -Object "Importing $Module module..." -ForegroundColor Green

    # If module is imported say that and do nothing
    If (Get-Module | Where-Object { $_.Name -eq $Module })
    {
        Write-Host -Object "Module $Module is already imported." -ForegroundColor Green
    }
    Else
    {
        # If module is not imported, but available on disk then import
        If ( [bool] (Get-Module -ListAvailable | Where-Object { $_.Name -eq $Module }) )

        {
            $InstalledModuleVersion = (Get-InstalledModule -Name $Module).Version
            $ModuleVersion = (Find-Module -Name $Module).Version
            $ModulePath = (Get-InstalledModule -Name $Module).InstalledLocation
            $ModulePath = (Get-Item -Path $ModulePath).Parent.FullName
            If ([version]$ModuleVersion -gt [version]$InstalledModuleVersion)
            {
                Update-Module -Name $Module -Force
                Remove-Item -Path $ModulePath\$InstalledModuleVersion -Force -Recurse
                Write-Host -Object "Module $Module was updated." -ForegroundColor Green
            }
            Import-Module -Name $Module -Force -Global -DisableNameChecking
            Write-Host -Object "Module $Module was imported." -ForegroundColor Green
        }
        Else
        {
            # Install Nuget
            If (-not(Get-PackageProvider -ListAvailable -Name NuGet))
            {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
                Write-Host -Object "Package provider NuGet was installed." -ForegroundColor Green
            }

            # Add the Powershell Gallery as trusted repository
            If ((Get-PSRepository -Name "PSGallery").InstallationPolicy -eq "Untrusted")
            {
                Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
                Write-Host -Object "PowerShell Gallery is now a trusted repository." -ForegroundColor Green
            }

            # Update PowerShellGet
            $InstalledPSGetVersion = (Get-PackageProvider -Name PowerShellGet).Version
            $PSGetVersion = [version] (Find-PackageProvider -Name PowerShellGet).Version
            If ($PSGetVersion -gt $InstalledPSGetVersion)
            {
                Install-PackageProvider -Name PowerShellGet -Force
                Write-Host -Object "PowerShellGet Gallery was updated." -ForegroundColor Green
            }

            # If module is not imported, not available on disk, but is in online gallery then install and import
            If (Find-Module -Name $Module | Where-Object { $_.Name -eq $Module })
            {
                # Install and import module
                Install-Module -Name $Module -AllowClobber -Force -Scope AllUsers
                Import-Module -Name $Module -Force -Global -DisableNameChecking
                Write-Host -Object "Module $Module was installed and imported." -ForegroundColor Green
            }
            Else
            {
                # If the module is not imported, not available and not in the online gallery then abort
                Write-Host -Object "Module $Module was not imported, not available and not in an online gallery, exiting." -ForegroundColor Red
                Exit 1
            }
        }
    }
}

[string]$appScriptPath = Get-ScriptPath # Get the current script path
[string]$appScriptName = Get-ScriptName # Get the current script name

# Install and import modules list
Foreach ($Module in $Modules)
{
    Initialize-Module -Module $Module
}

#endregion

#-----------------------------------------------------------[Functions]------------------------------------------------------------

#region Functions
#endregion

#----------------------------------------------------------[Declarations]----------------------------------------------------------

#region Declarations
#endregion

#-----------------------------------------------------------[Execution]------------------------------------------------------------

#region Execution

# Set current path
Set-Location -Path $appScriptPath

# Install latest version of VMware Tools
$appName = "VMware Tools"
$appURL = "https://raw.githubusercontent.com/JonathanPitre/Apps/master/VMWare/Tools/Install.ps1"
$appScript = Split-Path -Path $appURL -Leaf
New-Folder -Path "$appScriptPath\$appName"
Set-Location -Path "$appScriptPath\$appName"
Invoke-WebRequest -Uri $appURL -UseBasicParsing -OutFile .\$appScript
& ".\$appScript"

# Enable Automatic Updates for Microsoft Store Apps - https://winbuzzer.com/2020/07/17/how-to-turn-off-automatic-updates-for-microsoft-store-apps-in-windows-10-xcxwbt
Set-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -Value "4" -Type DWord
Remove-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Recurse
Restart-Service -Name wuauserv -Force
# Update Microsoft Store Apps
$null = Get-CimInstance -Namespace "Root\cimv2\mdm\dmmap" -ClassName "MDM_EnterpriseModernAppManagement_AppManagement01" | Invoke-CimMethod -MethodName UpdateScanMethod
Write-Host -Object "Windows Store apps were updated successfully!" -ForegroundColor Green

# Microsoft Updates
# PSWindowsUpdate log can be found here C:\ProgramData\Logs\Software\PSWindowsUpdate.log
$appName = "Microsoft Updates"
$appURL = "https://raw.githubusercontent.com/JonathanPitre/Apps/master/Microsoft/Windows%20Updates/Install.ps1"
$appScript = Split-Path -Path $appURL -Leaf
New-Folder -Path "$appScriptPath\$appName"
Set-Location -Path "$appScriptPath\$appName"
Invoke-WebRequest -Uri $appURL -UseBasicParsing -OutFile .\$appScript
& ".\$appScript"

# Install required DigiCert certificates for Citrix Cloud Connector
# https://support.citrix.com/article/CTX477396/unable-to-install-the-cloud-connector-due-to-being-unable-to-validate-certificate-chain
# https://support.citrix.com/article/CTX223828/citrix-cloud-connector-installation-does-not-complete-unable-to-validate-certificate-chain

# Download and install DigiCertTrustedRootG4.crt
Invoke-WebRequest -Uri "https://cacerts.digicert.com/DigiCertTrustedRootG4.crt" -OutFile "$appScriptPath\DigiCertTrustedRootG4.crt" -UseBasicParsing
Import-Certificate -FilePath $appScriptPath\DigiCertTrustedRootG4.crt -CertStoreLocation Cert:\LocalMachine\Root
Import-Certificate -FilePath $appScriptPath\DigiCertTrustedRootG4.crt -CertStoreLocation Cert:\LocalMachine\AuthRoot

# Download and install DigiCertAssuredIDRootCA.crt
Invoke-WebRequest -Uri "https://dl.cacerts.digicert.com/DigiCertAssuredIDRootCA.crt" -OutFile "$appScriptPath\DigiCertAssuredIDRootCA.crt" -UseBasicParsing
Import-Certificate -FilePath $appScriptPath\DigiCertAssuredIDRootCA.crt -CertStoreLocation Cert:\LocalMachine\Root

# Download and install DigiCertSHA2AssuredIDCodeSigningCA.crt
Invoke-WebRequest -Uri "https://dl.cacerts.digicert.com/DigiCertSHA2AssuredIDCodeSigningCA.crt" -OutFile "$appScriptPath\DigiCertSHA2AssuredIDCodeSigningCA.crt" -UseBasicParsing
Import-Certificate -FilePath $appScriptPath\DigiCertSHA2AssuredIDCodeSigningCA.crt -CertStoreLocation Cert:\LocalMachine\CA

# Download and install DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crt
Invoke-WebRequest -Uri "https://cacerts.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crt" -OutFile $appScriptPath\DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crt -UseBasicParsing
Import-Certificate -FilePath $appScriptPath\DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crt -CertStoreLocation Cert:\LocalMachine\CA

# Remove downloaded certs
Remove-Item -Path $appScriptPath\*.crt -Force

# Turn on Automatic Root Certificates Update
Set-RegistryKey -Key "HKLM:\Software\Policies\Microsoft\SystemCertificates\AuthRoot" -Name "DisableRootAutoUpdate" -Value 0 -Type DWord

# Install latest version of Microsoft Visual C++ Runtimes
$appName = "Microsoft Visual C++ Runtimes"
$appURL = "https://raw.githubusercontent.com/JonathanPitre/Apps/master/Microsoft/Visual%20C%2B%2B%20Runtimes/Install-LatestOnly.ps1"
$appScript = Split-Path -Path $appURL -Leaf
New-Folder -Path "$appScriptPath\$appName"
Set-Location -Path "$appScriptPath\$appName"
Invoke-WebRequest -Uri $appURL -UseBasicParsing -OutFile .\$appScript
& ".\$appScript"

# Install latest Microsoft VCLibs
$appName = "Microsoft VCLibs"
$appURL = "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx"
$appSetup = Split-Path -Path $appURL -Leaf
New-Folder -Path "$appScriptPath\$appName"
Set-Location -Path "$appScriptPath\$appName"
Invoke-WebRequest -Uri $appURL -UseBasicParsing -OutFile .\$appSetup
Add-AppxPackage -Path .\$appSetup
Remove-Item -Path $appSetup -Force

# Install latest version Microsoft DesktopAppInstaller (aka WinGet)
$appName = "Microsoft DesktopAppInstaller"
$appURL = $(Invoke-RestMethod https://api.github.com/repos/microsoft/winget-cli/releases/latest).assets.browser_download_url | Where-Object { $_.EndsWith(".msixbundle") }
$appSetup = Split-Path -Path $appURL -Leaf
New-Folder -Path "$appScriptPath\$appName"
Set-Location -Path "$appScriptPath\$appName"
Invoke-WebRequest -Uri $appURL -UseBasicParsing -OutFile .\$appSetup
Add-AppPackage -Path .\$appSetup
Add-AppxPackage -Path .\$appSetup
Add-ProvisionedAppPackage -Online -PackagePath .\$appSetup -Verbose
Remove-Item -Path $appSetup -Force


# Test if winget has been successfully installed
if ($result -and (Test-Path -Path "$env:LOCALAPPDATA\Microsoft\WindowsApps\winget.exe"))
{
    Write-Host "Congratulations! Windows Package Manager (winget) $(winget --version) installed successfully" -ForegroundColor "Green"
}
else
{
    Write-Host "Failed to install Windows Package Manager (winget)" -ForegroundColor "Red"
}


#winget install --id=Microsoft.DotNet.HostingBundle.6  -e

# Run Winget update
#winget upgrade --all --include-unknown --accept-source-agreements

<#
# Validate certificate install
reg query HKLM\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\Certificates\DDFB16CD4931C973A2037D3FC83A4D7D775D05E4
#reg query HKLM\SOFTWARE\Microsoft\SystemCertificates\root\Certificates\DDFB16CD4931C973A2037D3FC83A4D7D775D05E4
#reg query HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\root\Certificates\DDFB16CD4931C973A2037D3FC83A4D7D775D05E4

reg query HKLM\SOFTWARE\Microsoft\SystemCertificates\CA\Certificates\7B0F360B775F76C94A12CA48445AA2D2A875701C
#reg query HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\CA\Certificates\7B0F360B775F76C94A12CA48445AA2D2A875701C
#reg query HKU\S-1-5-20\Software\Microsoft\SystemCertificates\CA\Certificates\7B0F360B775F76C94A12CA48445AA2D2A875701C
Get-ChildItem Cert:\ -Recurse | Where-Object -Property Subject -like "*DigiCert*"
#>

#endregion