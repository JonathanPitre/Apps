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
$Modules = @("PSADT", "Evergreen") # Modules list

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

#region Declarations

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

#endregion

#-----------------------------------------------------------[Execution]------------------------------------------------------------

#region Execution

If ([version]$appVersion -gt [version]$appInstalledVersion)
{
    Set-Location -Path $appScriptPath
    If (-Not(Test-Path -Path $appVersion)) { New-Folder -Path $appVersion }
    Set-Location -Path $appVersion

    # Delete machine policies to prevent issue during installation
    If ([boolean](Get-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Microsoft\Edge")) { Remove-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Recurse -ContinueOnError $True }
    If ([boolean](Get-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate")) { Remove-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate" -Recurse -ContinueOnError $True }
    If ([boolean](Get-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Edge")) { Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Edge" -Recurse -ContinueOnError $True }
    If ([boolean](Get-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\EdgeUpdate")) { Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\EdgeUpdate" -Recurse -ContinueOnError $True }

    # Uninstall previous versions
    # Edge cannot be uninstall anymore - https://answers.microsoft.com/en-us/microsoftedge/forum/all/getting-there-is-a-problem-with-this-windows/c5fb02db-6b40-4cd7-b74a-88470c71d730
    Get-Process -Name $appProcesses | Stop-Process -Force
    [string]$appUninstaller = (Get-ChildItem -Path $appDestination -Directory | Where-Object { $_.Name -match "^\d+?" } | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Select-Object -ExpandProperty FullName) + "\Installer\setup.exe"
    If (Test-Path -Path $appUninstaller)
    {
        Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
        Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -like "*$appName*" } | Remove-AppxProvisionedPackage -Online
        Get-AppxPackage -Name "*$appName*" -AllUsers | Remove-AppxPackage -AllUsers
        Get-AppxPackage -Name "*$appName*" | Remove-AppxPackage
        Execute-Process -Path $appUninstaller -Parameters "–-uninstall –-system-level -–force-uninstall" -IgnoreExitCodes * -ContinueOnError $True
        #Set-Location -Path $appUninstallerDestination
        #cmd.exe /c ".\setup.exe -–uninstall –-system-level -–force-uninstall"
        Get-Process -Name $appProcesses | Stop-Process -Force
    }

    # Remove previous install folders
    Remove-Folder -Path "$envLocalAppData\Microsoft\Edge" -ContinueOnError $True
    Remove-Folder -Path "$envLocalAppData\Microsoft\EdgeUpdate" -ContinueOnError $True
    Remove-Folder -Path "$envLocalAppData\Microsoft\Temp" -ContinueOnError $True
    #Remove-Folder -Path "$envProgramFilesX86\Microsoft\$appName" -ContinueOnError $True
    #Remove-Folder -Path "$envProgramFilesX86\Microsoft\EdgeCore" -ContinueOnError $True
    #Remove-Folder -Path "$envProgramFilesX86\Microsoft\EdgeUpdate" -ContinueOnError $True
    Remove-Folder -Path "$envProgramFilesX86\Microsoft\Temp" -ContinueOnError $True

    # Remove previous registry entries
    If ([boolean](Get-RegistryKey -Key "HKCU:\Software\Microsoft\Edge")) { Remove-RegistryKey -Key "HKCU:\Software\Microsoft\Edge" -Recurse -ContinueOnError $True }
    If ([boolean](Get-RegistryKey -Key "HKCU:\Software\Microsoft\EdgeUpdate")) { Remove-RegistryKey -Key "HKCU:\Software\Microsoft\EdgeUpdate" -Recurse -ContinueOnError $True }
    If ([boolean](Get-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{9459C573-B17A-45AE-9F64-1857B5D58CEE}")) { Remove-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{9459C573-B17A-45AE-9F64-1857B5D58CEE}" -Recurse -ContinueOnError $True }
    #Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Edge" -Recurse -ContinueOnError $True
    #Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate" -Recurse -ContinueOnError $True
    #Remove-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\EdgeUpdate" -Recurse -ContinueOnError $True
    #Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge Update" -Recurse -ContinueOnError $True
    #Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge" -Recurse -ContinueOnError $True

    # Download latest setup file(s)
    If (-Not(Test-Path -Path $appScriptPath\$appVersion\$appSetup))
    {
        Write-Log -Message "Downloading $appVendor $appName $appLongName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURL -OutFile $appSetup
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Download required config file
    If (-Not(Test-Path -Path $appScriptPath\$appConfig))
    {
        Write-Log -Message "Downloading $appVendor $appName Config.." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appConfigURL -OutFile $appScriptPath\$appConfig
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
    Copy-File -Path "$appScriptPath\master_preferences" -Destination $appDestination

    # Stop and disable unneeded scheduled tasks
    Get-ScheduledTask -TaskName "$appVendor$appName*" | Stop-ScheduledTask
    Get-ScheduledTask -TaskName "$appVendor$appName*" | Disable-ScheduledTask

    # Stop and disable unneeded services
    Stop-ServiceAndDependencies -Name $appServices[0]
    #Stop-ServiceAndDependencies -Name $appServices[1]
    #Stop-ServiceAndDependencies -Name $appServices[2]
    Set-ServiceStartMode -Name $appServices[0] -StartMode "Manual"
    #Set-ServiceStartMode -Name $appServices[1] -StartMode "Disabled"
    #Set-ServiceStartMode -Name $appServices[2] -StartMode "Disabled"

    # Remove Active Setup - https://virtualwarlock.net/microsoft-edge-in-citrix
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{9459C573-B17A-45AE-9F64-1857B5D58CEE}" -Name "StubPath"
    # Disable autoupdate
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\EdgeUpdate" -Name "Update{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}" -Value "0" -Type DWord
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\EdgeUpdate" -Name "UpdateDefault" -Value "0" -Type DWord
    # Disable per-user installation
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\EdgeUpdate" -Name "Install{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}" -Value "0" -Type DWord
    # Do not allow delivery of Microsoft Edge through Automatic Updates
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\EdgeUpdate" -Name "DoNotUpdateToEdgeWithChromium" -Value "1" -Type DWord

    # Execute the Microsoft Edge browser replacement task to make sure that the legacy Microsoft Edge browser is tucked away.
    # Only needed on Windows 10 versions where Microsoft Edge is not included in the OS.
    #Delete Browser replacement scheduled task!
    If ($envOSName -like "*Windows 10*" )
    {
        Execute-Process -Path "$envProgramFilesX86\$appVendor\$($appName)Update\MicrosoftEdgeUpdate.exe" -Parameters "/browserreplacement"
    }

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

    # Go back to the parent folder
    Set-Location ..

    Write-Log -Message "$appVendor $appName $appLongName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
}
Else
{
    Write-Log -Message "$appVendor $appName $appLongName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}

#endregion