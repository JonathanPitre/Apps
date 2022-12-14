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
$Modules = @("PSADT", "Evergreen") # Modules list

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
$appName = "Edge"
$appLongName = "for Business"
$appProcesses = @("msedge", "MicrosoftEdgeUpdate", "MicrosoftEdgeUpdateBroker", "MicrosoftEdgeUpdateCore", "msedgewebview2", "elevation_service")
$appServices = @("edgeupdate", "edgeupdatem", "MicrosoftEdgeElevationService")
$appInstallParameters = "/QB"
$appAddParameters = "DONOTCREATEDESKTOPSHORTCUT=TRUE DONOTCREATETASKBARSHORTCUT=TRUE"
$appChannel = "Stable"
$appRelease = "Enterprise"
$appArchitecture = "x64"
$Evergreen = Get-EvergreenApp -Name MicrosoftEdge | Where-Object { $_.Channel -eq $appChannel -and $_.Release -eq $appRelease -and $_.Architecture -eq $appArchitecture }
$appVersion = $Evergreen.Version
$appURL = $Evergreen.URI
$appSetup = Split-Path -Path $appURL -Leaf
$appConfigURL = "https://raw.githubusercontent.com/JonathanPitre/Apps/master/Microsoft/Edge%20for%20Business/master_preferences"
$appConfig = Split-Path -Path $appConfigURL -Leaf
$appDestination = "${env:ProgramFiles(x86)}\$appVendor\$appName\Application"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName" -Exact)
$appInstalledVersion = (Get-InstalledApplication -Name "$appVendor $appName" -Exact).DisplayVersion | Select-Object -First 1

#-----------------------------------------------------------[Execution]------------------------------------------------------------

If ([version]$appVersion -gt [version]$appInstalledVersion)
{
    Set-Location -Path $appScriptDirectory
    If (-Not(Test-Path -Path $appVersion)) { New-Folder -Path $appVersion }
    Set-Location -Path $appVersion

    # Delete machine policies to prevent issue during installation
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Recurse -ContinueOnError $True
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate" -Recurse -ContinueOnError $True
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Edge" -Recurse -ContinueOnError $True
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\EdgeUpdate" -Recurse -ContinueOnError $True

    # Uninstall previous versions
    Get-Process -Name $appProcesses | Stop-Process -Force
    If ($IsAppInstalled)
    {
        Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
        Remove-MSIApplications -Name "$appVendor $appName" -Parameters $appInstallParameters
    }

    # Uninstall Microsoft Edge Update
    If (Test-Path -Path "$envLocalAppData\$appVendor\$($appName)Update\$appVendor$($appName)Update.exe")
    {
        Write-Log -Message "Removing previous $appVendor $appName $appLongName folder to fix issues with new installation." -Severity 1 -LogType CMTrace -WriteHost $True
        Execute-Process -Path "$envLocalAppData\$appVendor\$($appName)Update\$appVendor$($appName)Update.exe" -Parameters "-uninstall" -IgnoreExitCodes 1606220281 -ContinueOnError $True
    }
    If (Test-Path -Path "$envProgramFilesX86\$appVendor\$($appName)Update\$appVendor$($appName)Update.exe")
    {
        Write-Log -Message "Removing previous $appVendor $appName $appLongName folder to fix issues with new installation." -Severity 1 -LogType CMTrace -WriteHost $True
        Execute-Process -Path "$envProgramFilesX86\$appVendor\$($appName)Update\$appVendor$($appName)Update.exe" -Parameters "-uninstall" -IgnoreExitCodes 1606220281 -ContinueOnError $True
    }

    # Remove previous install folders
    Remove-Folder -Path "$envLocalAppData\Microsoft\Edge" -ContinueOnError $True
    Remove-Folder -Path "$envLocalAppData\Microsoft\EdgeUpdate" -ContinueOnError $True
    Remove-Folder -Path "$envLocalAppData\Microsoft\Temp" -ContinueOnError $True
    Remove-Folder -Path "$envProgramFilesX86\Microsoft\$appName" -ContinueOnError $True
    Remove-Folder -Path "$envProgramFilesX86\Microsoft\EdgeCore" -ContinueOnError $True
    Remove-Folder -Path "$envProgramFilesX86\Microsoft\EdgeUpdate" -ContinueOnError $True
    Remove-Folder -Path "$envProgramFilesX86\Microsoft\Temp" -ContinueOnError $True

    # Remove previous registry entries
    Remove-RegistryKey -Key "HKCU:\Software\Microsoft\Edge" -Recurse -ContinueOnError $True
    Remove-RegistryKey -Key "HKCU:\Software\Microsoft\EdgeUpdate" -Recurse -ContinueOnError $True
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{ 9459C573-B17A-45AE-9F64-1857B5D58CEE}" -Recurse -ContinueOnError $True
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Edge" -Recurse -ContinueOnError $True
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate" -Recurse -ContinueOnError $True
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge Update" -Recurse -ContinueOnError $True
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge" -Recurse -ContinueOnError $True


    # Download latest setup file(s)
    If (-Not(Test-Path -Path $appScriptDirectory\$appVersion\$appSetup))
    {
        Write-Log -Message "Downloading $appVendor $appName $appLongName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURL -OutFile $appSetup
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Download required config file
    If (-Not(Test-Path -Path $appScriptDirectory\$appConfig))
    {
        Write-Log -Message "Downloading $appVendor $appName Config.." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appConfigURL -OutFile $appScriptDirectory\$appConfig
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Install latest version
    Write-Log -Message "Installing $appVendor $appName $appLongName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    Execute-MSI -Action Install -Path $appSetup -Parameters $appInstallParameters #-AddParameters $appAddParameters

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

    # Copy preferences file
    Copy-File -Path "$appScriptDirectory\master_preferences" -Destination $appDestination

    # Stop and disable unneeded scheduled tasks
    Get-ScheduledTask -TaskName "$appVendor$appName*" | Stop-ScheduledTask
    Get-ScheduledTask -TaskName "$appVendor$appName*" | Disable-ScheduledTask

    # Stop and disable unneeded services
    Stop-ServiceAndDependencies -Name $appServices[0]
    Stop-ServiceAndDependencies -Name $appServices[1]
    Stop-ServiceAndDependencies -Name $appServices[2]
    Set-ServiceStartMode -Name $appServices[0] -StartMode "Disabled"
    Set-ServiceStartMode -Name $appServices[1] -StartMode "Disabled"
    Set-ServiceStartMode -Name $appServices[2] -StartMode "Disabled"

    # Remove Active Setup - https://virtualwarlock.net/microsoft-edge-in-citrix
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{9459C573-B17A-45AE-9F64-1857B5D58CEE}" -Name "StubPath"

    # Execute the Microsoft Edge browser replacement task to make sure that the legacy Microsoft Edge browser is tucked away
    # This is only needed on Windows 10 versions where Microsoft Edge is not included in the OS.
    Execute-Process -Path "$envProgramFilesX86\$appVendor\$($appName)Update\MicrosoftEdgeUpdate.exe" -Parameters "/browserreplacement"

    # Creates a pinned taskbar icons for all users
    New-Shortcut -Path "$envSystemDrive\Users\Default\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\Taskbar\$appVendor $appName.lnk" -TargetPath "$appDestination\$($appProcesses[0]).exe" -IconLocation "$appDestination\$($appProcesses[0]).exe" -Description "$appVendor $appName" -WorkingDirectory "$appDestination"

    # Configure application shortcut
    #Remove-File -Path "$envCommonDesktop\$appVendor $appName.lnk" -ContinueOnError $True

    # Disable Citrix API hook - https://discussions.citrix.com/topic/406494-microsoft-new-edge-ready-for-citrix-terminal-serves
    # https://blog.vermeerschconsulting.be/index.php/2020/04/23edge-chromium-in-citrix-virtual-apps-server-2016-or-2019-with-a-working-smart-card-reader
    $regKey = "HKLM:\SOFTWARE\Citrix\CtxHook\AppInit_Dlls\SfrHook"
    $regKeyProcess = "$($appProcesses[0]).exe"
    If ((Test-Path -Path $regKey) -and (-Not(Test-Path -Path $regKey\$regKeyProcess)))
    {
        Write-Log -Message "Fixing Citrix API Hook..." -Severity 1 -LogType CMTrace -WriteHost $True
        # Add the msedge.exe key
        Set-RegistryKey -Key $regKey\$regKeyProcess -Value "(Default)"
    }

    # Disable autoupdate
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate" -Name "Update{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}" -Value "0" -Type DWord
    # Disable per-user installation
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate" -Name "Install{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}" -Value "4" -Type DWord

    # Go back to the parent folder
    Set-Location ..

    Write-Log -Message "$appVendor $appName $appLongName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
}
Else
{
    Write-Log -Message "$appVendor $appName $appLongName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}