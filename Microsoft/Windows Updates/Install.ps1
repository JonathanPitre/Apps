# Standalone application install script for VDI environment - (C)2022 Jonathan Pitre, inspired by xenappblog.com

#Requires -Version 5.1
#Requires -RunAsAdministrator

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

$ProgressPreference = "Continue"
$ErrorActionPreference = "SilentlyContinue"
# Set the script execution policy for this process
Try { Set-ExecutionPolicy -ExecutionPolicy 'ByPass' -Scope 'Process' -Force } Catch {}
$env:SEE_MASK_NOZONECHECKS = 1
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
$Modules = @("PSADT", "PSWindowsUpdate") # Modules list

Function Get-ScriptDirectory
{
    Remove-Variable appScriptDirectory
    Try
    {
        If ($psEditor) { Split-Path $psEditor.GetEditorContext().CurrentFile.Path } # Visual Studio Code Host
        ElseIf ($psISE) { Split-Path $psISE.CurrentFile.FullPath } # Windows PowerShell ISE Host
        ElseIf ([bool]$MyInvocation) { $MyInvocation.MyCommand.Path } # Windows PowerShell 3.0-5.1
        Else
        {
            Write-Host -Object "Cannot resolve script file's path!" -ForegroundColor Red
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
    Write-Host -Object  "Importing $Module module..." -ForegroundColor Green

    # If module is imported say that and do nothing
    If (Get-Module | Where-Object {$_.Name -eq $Module})
    {
        Write-Host -Object  "Module $Module is already imported." -ForegroundColor Green
    }
    Else
    {
        # If module is not imported, but available on disk then import
        If (Get-Module -ListAvailable | Where-Object {$_.Name -eq $Module})
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
            If (Find-Module -Name $Module | Where-Object {$_.Name -eq $Module})
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
$appName = "Updates"
$appService = "wuauserv"
$appLog = "$env:ProgramData\Logs\Software\PSWindowsUpdate.log"

#-----------------------------------------------------------[Execution]------------------------------------------------------------

# Create folder to store log files
New-Folder -Path "$env:ProgramData\Logs\Software"

# Stop Windows Update service
Stop-ServiceAndDependencies -Name $appService

# Clear Windows Update policies
Remove-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Recurse -ContinueOnError $True

# Get updates for other Microsoft products
Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d -Confirm:$false

# Pause and give the service time to update
Start-Sleep 30

# Start Windows Update service
Set-ServiceStartMode -Name $appService -StartMode "Automatic"
Start-ServiceAndDependencies -Name $appService

Write-Log -Message "Gettings available $appVendor $appName..." -Severity 1 -LogType CMTrace -WriteHost $True
Get-WindowsUpdate -RootCategories "Critical Updates", "Definition Updates", "Feature Packs", "Security Updates", "Service Packs", "Tools", "Update Rollups", "Updates" -NotTitle "Preview" -MicrosoftUpdate | Out-File $appLog -Append

Write-Log -Message "Installing available $appVendor $appName..." -Severity 1 -LogType CMTrace -WriteHost $True
Get-WindowsUpdate -RootCategories "Upgrades" -NotTitle "Preview" -MicrosoftUpdate -Install -AcceptAll -UpdateType Software -IgnoreReboot -IgnoreUserInput | Out-File $appLog -Append

Get-WindowsUpdate -RootCategories "Critical Updates", "Definition Updates", "Feature Packs", "Security Updates", "Service Packs", "Tools", "Update Rollups", "Updates" -NotTitle "Preview" -MicrosoftUpdate -Install -AcceptAll -UpdateType Software -IgnoreReboot -IgnoreUserInput | Out-File $appLog -Append

# Windows 10 native way
#Start-Process -NoNewWindow "c:\windows\system32\UsoClient.exe" -argument "ScanInstallWait" -Wait
#Start-Process -NoNewWindow "c:\windows\system32\UsoClient.exe" -argument "StartInstall" -Wait

# Only reboot if needed
[bool]$WURebootStatus = Get-WURebootStatus -Silent
if ($WURebootStatus) {
    Write-Log -Message "$appVendor $appName were installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
    Show-InstallationRestartPrompt -Countdownseconds 30 -CountdownNoHideSeconds 30
}
$appScriptDirectory