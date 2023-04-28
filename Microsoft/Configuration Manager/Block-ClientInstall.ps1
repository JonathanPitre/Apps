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
$Modules = @("PSADT") # Modules list

Function Get-ScriptPath
{
    <#
    .SYNOPSIS
        Get-ScriptPath returns the path of the current script.
    .OUTPUTS
        System.String
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
        ElseIf ($MyInvocation.MyCommand.Name) { $MyInvocation.MyCommand.Name } # Windows PowerShell
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
        System.String
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
        If ( [boolean](Get-Module -ListAvailable | Where-Object { $_.Name -eq $Module }) )

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
            $PSGetVersion = [version](Find-PackageProvider -Name PowerShellGet).Version
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
                EXIT 1
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

$appVendor = "Microsoft"
$appName = "Configuration Manager Client"
$appProcesses = @("CcmExec", "CmRcService", "SCClient", "ScNotification.exe")


#-----------------------------------------------------------[Execution]------------------------------------------------------------

# Prevent Configuration Manager Client software installation
# https://infrastructureland.wordpress.com/2015/02/04/how-to-prevent-the-configuration-manager-client-software-from-being-installed-on-specific-computers

# If Configuration Manager Client, uninstall it
If (Test-Path -Path "$envWinDir\ccmsetup\ccmsetup.exe")
{
    Write-Log -Message "$appVendor $appName is currently installed!" -Severity 2 -LogType CMTrace -WriteHost $True

    # Stop required processes
    Get-Process -Name $appProcesses | Stop-Process -Force

    Execute-Process -Path "$envWinDir\ccmsetup\ccmsetup.exe" -Parameters "/uninstall"

    # Delete the folder of the SCCM Client installation: "C:\Windows\CCM"
    Remove-Item -Path "$envWinDir\CCM" -Force -Recurse -Confirm:$false -Verbose

    # Delete the folder of the SCCM Client Cache of all the packages and Applications that were downloaded and installed on the Computer: "C:\Windows\ccmcache"
    Remove-Item -Path "$envWinDir\CCMSetup" -Force -Recurse -Confirm:$false -Verbose

    # Delete the folder of the SCCM Client Setup files that were used to install the client: "C:\Windows\ccmsetup"
    Remove-Item -Path "$envWinDir\CCMCache" -Force -Recurse -Confirm:$false -Verbose

    # Delete the file with the certificate GUID and SMS GUID that current Client was registered with
    Remove-Item -Path "$envWinDir\smscfg.ini" -Force -Confirm:$false -Verbose

    # Delete the certificate itself
    Remove-Item -Path 'HKLM:\Software\Microsoft\SystemCertificates\SMS\Certificates\*' -Force -Confirm:$false -Verbose

    # Remove all the registry keys associated with the SCCM Client that might not be removed by ccmsetup.exe
    Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\CCM' -Force -Recurse -Verbose
    Remove-Item -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\CCM' -Force -Recurse -Confirm:$false -Verbose
    Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\SMS' -Force -Recurse -Confirm:$false -Verbose
    Remove-Item -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\SMS' -Force -Recurse -Confirm:$false -Verbose
    Remove-Item -Path 'HKLM:\Software\Microsoft\CCMSetup' -Force -Recurse -Confirm:$false -Verbose
    Remove-Item -Path 'HKLM:\Software\Wow6432Node\Microsoft\CCMSetup' -Force -Confirm:$false -Recurse -Verbose

    # Remove the service from "Services"
    Remove-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\CcmExec' -Force -Recurse -Confirm:$false -Verbose
    Remove-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\ccmsetup' -Force -Recurse -Confirm:$false -Verbose

    # Remove the Namespaces from the WMI repository
    Get-CimInstance -Query "Select * From __Namespace Where Name='CCM'" -Namespace "root" | Remove-CimInstance -Verbose -Confirm:$false
    Get-CimInstance -Query "Select * From __Namespace Where Name='CCMVDI'" -Namespace "root" | Remove-CimInstance -Verbose -Confirm:$false
    Get-CimInstance -Query "Select * From __Namespace Where Name='SmsDm'" -Namespace "root" | Remove-CimInstance -Verbose -Confirm:$false
    Get-CimInstance -Query "Select * From __Namespace Where Name='sms'" -Namespace "root\cimv2" | Remove-CimInstance -Verbose -Confirm:$false

    # Alternative command for WMI Removal in case of something goes wrong with the above.
    # Get-WmiObject -query "Select * From __Namespace Where Name='CCM'" -Namespace "root" | Remove-WmiObject -Verbose | Out-Host
    # Get-WmiObject -query "Select * From __Namespace Where Name='CCMVDI'" -Namespace "root" | Remove-WmiObject -Verbose | Out-Host
    # Get-WmiObject -query "Select * From __Namespace Where Name='SmsDm'" -Namespace "root" | Remove-WmiObject -Verbose | Out-Host
    # Get-WmiObject -query "Select * From __Namespace Where Name='sms'" -Namespace "root\cimv2" | Remove-WmiObject -Verbose | Out-Host

    Write-Log -Message "$appVendor $appName was uninstalled successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
}

# Create fake ccmsetup & ccm files to prevent automatic installation
New-Item -Path $envWinDir -Name "ccmsetup" -Force -ItemType File
New-Item -Path $envWinDir -Name "ccm" -Force -ItemType File

Write-Log -Message "$appVendor $appName installation are now blocked!" -Severity 1 -LogType CMTrace -WriteHost $True