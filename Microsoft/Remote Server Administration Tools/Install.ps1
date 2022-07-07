# Standalone application install script for VDI environment - (C)2022 Jonathan Pitre, inspired by xenappblog.com

#Requires -Version 5.1
#Requires -RunAsAdministrator

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"
# Set the script execution policy for this process
Try { Set-ExecutionPolicy -ExecutionPolicy 'ByPass' -Scope 'Process' -Force } Catch {}
$env:SEE_MASK_NOZONECHECKS = 1
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
$Modules = @("PSADT") # Modules list

Function Get-ScriptDirectory
{
    Remove-Variable appScriptDirectory
    Try
    {
        If ($psEditor) { Split-Path $psEditor.GetEditorContext().CurrentFile.Path } # Visual Studio Code Host
        ElseIf ($psISE) { Split-Path $psISE.CurrentFile.FullPath } # Windows PowerShell ISE Host
        ElseIf ($PSScriptRoot) { $PSScriptRoot } # Windows PowerShell 3.0-5.1
        Else
        {
            Write-Host -Object "Cannot resolve script file's path" -ForegroundColor Red
            Exit 1
        }
    }
    Catch
    {
        Write-Host -Object "Caught Exception: $($Error[0].Exception.Message)" -ForegroundColor Red
        Exit 2
    }
}

Function Initialize-Module
{
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
        If (Get-Module -ListAvailable | Where-Object { $_.Name -eq $Module })
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

# Get the current script directory
$appScriptDirectory = Get-ScriptDirectory

# Install and import modules list
Foreach ($Module in $Modules)
{
    Initialize-Module -Module $Module
}

#-----------------------------------------------------------[Functions]------------------------------------------------------------

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$appVendor = "Microsoft"
$appName = "Remote Server Administration Tools (RSAT)"

#-----------------------------------------------------------[Execution]------------------------------------------------------------

If ($envOSName -like "*Windows 10*")
{
    # Install RSAT Tools
    # http://woshub.com/install-rsat-feature-windows-10-powershell

    # Active Directory Tools
    Add-WindowsCapability –Online –Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
    # DNS Tools
    Add-WindowsCapability –Online –Name Rsat.Dns.Tools~~~~0.0.1.0
    # Group Policy Management
    Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0

    # Remote Desktop Service Tools
    #Add-WindowsCapability -Online -Name Rsat.RemoteDesktop.Services.Tools~~~~0.0.1.0

    #Add-WindowsCapability -Online -Name Rsat.FileServices.Tools~~~~0.0.1.0
    #Add-WindowsCapability -Online -Name Rsat.IPAM.Client.Tools~~~~0.0.1.0
    #Add-WindowsCapability -Online -Name Rsat.LLDP.Tools~~~~0.0.1.0
    #Add-WindowsCapability -Online -Name Rsat.NetworkController.Tools~~~~0.0.1.0
    #Add-WindowsCapability -Online -Name Rsat.NetworkLoadBalancing.Tools~~~~0.0.1.0
    #Add-WindowsCapability -Online -Name Rsat.BitLocker.Recovery.Tools~~~~0.0.1.0
    #Add-WindowsCapability -Online -Name Rsat.CertificateServices.Tools~~~~0.0.1.0
    #Add-WindowsCapability -Online -Name Rsat.DHCP.Tools~~~~0.0.1.0
    #Add-WindowsCapability -Online -Name Rsat.FailoverCluster.Management.Tools~~~~0.0.1.0
    #Add-WindowsCapability -Online -Name Rsat.RemoteAccess.Management.Tools~~~~0.0.1.0
    #Add-WindowsCapability -Online -Name Rsat.ServerManager.Tools~~~~0.0.1.0
    #Add-WindowsCapability -Online -Name Rsat.Shielded.VM.Tools~~~~0.0.1.0
    #Add-WindowsCapability -Online -Name Rsat.StorageMigrationService.Management.Tools~~~~0.0.1.0
    #Add-WindowsCapability -Online -Name Rsat.StorageReplica.Tools~~~~0.0.1.0
    #Add-WindowsCapability -Online -Name Rsat.SystemInsights.Management.Tools~~~~0.0.1.0
    #Add-WindowsCapability -Online -Name Rsat.VolumeActivation.Tools~~~~0.0.1.0
    #Add-WindowsCapability -Online -Name Rsat.WSUS.Tools~~~~0.0.1.0
}

If ($envOSName -like "*Windows Server*")
{
    If (Get-WindowsFeature -Name GPMC | Where-Object -Property { $_.InstallState -eq "Available" })
    {
        # Group Policy Management
        Install-WindowsFeature -Name GPMC
    }
    If (Get-WindowsFeature -Name RSAT-AD-Tools | Where-Object -Property { $_.InstallState -eq "Available" })
    {
        # Active Directory Tools
        Install-WindowsFeature -Name RSAT-AD-Tools
    }
    If (Get-WindowsFeature -Name RSAT-DNS-Server | Where-Object -Property { $_.InstallState -eq "Available" })
    {
        # DNS tools
        Install-WindowsFeature -Name RSAT-DNS-Server
    }
    # Install-WindowsFeature -Name RSAT-DHCP
}

Write-Log -Message "$appVendor $appName were installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True