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
$Modules = @("PSADT", "Nevergreen") # Modules list

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

$appShortName = "Zoom"
$appName = "Zoom Client for VDI"
$appProcesses = @("Zoom", "Zoom_launcher", "ZoomOutlookIMPlugin")
$appServices = @("ZoomCptService")
$appInstallParameters = "/QB"
# https://support.zoom.us/hc/en-us/articles/201362163-Mass-Installation-and-Configuration-for-Windows
$appAddParameters = "zNoDesktopShortCut=1"
$appArchitecture = "x64"
$Evergreen = Get-NevergreenApp -Name Zoom | Where-Object { $_.Name -eq "Zoom VDI Client" -and $_.Architecture -eq $appArchitecture -and $_.Type -eq "msi" }
$appVersion = $Evergreen.Version
$appURL = $Evergreen.URI
$appSetup = ((Split-Path -Path $appURL -Leaf).Trim("?archType=$appArchitecture"))
$appDestination = "$env:ProgramFiles\ZoomVDI\bin"
$appUninstallerURL = "https://assets.zoom.us/docs/msi-templates/CleanZoom.zip"
$appUninstallerZip = Split-Path -Path $appUninstallerURL -Leaf
$appUninstallerSetup = "CleanZoom.exe"
[boolean]$isAppInstalled = [boolean](Get-InstalledApplication -Name "$appName")
$appInstalledVersion = If ($isAppInstalled) { Get-FileVersion -File "$appDestination\Installer.exe" }
$appInstalledVersion = $appInstalledVersion.Replace(",", ".")

#endregion

#-----------------------------------------------------------[Execution]------------------------------------------------------------

#region Execution

If ([version]$appVersion -gt [version]$appInstalledVersion)
{
    Set-Location -Path $appScriptPath
    If (-Not(Test-Path -Path $appVersion)) { New-Folder -Path $appVersion }
    Set-Location -Path $appVersion

    # Download required cleanup tool
    If (-Not(Test-Path -Path $appScriptPath\$appUninstallerSetup))
    {
        Write-Log -Message "Downloading $appShortName Cleanup Tool..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appUninstallerURL -OutFile $appScriptPath\$appUninstallerZip
        Expand-Archive -Path $appScriptPath\$appUninstallerZip -DestinationPath $appScriptPath
        Remove-File -Path $appScriptPath\$appUninstallerZip
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Uninstall previous versions
    Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
    Get-Process -Name $appProcesses | Stop-Process -Force
    Execute-Process -Path $appScriptPath\$appUninstallerSetup -Parameters '/silent'

    # Remove user install
    $ZoomUsers = Get-ChildItem -Path "$($env:SystemDrive)\Users"
    $ZoomUsers | ForEach-Object {
        Try
        {
            If (Test-Path "$($env:SystemDrive)\Users\$($_.Name)\AppData\Roaming\$appShortName\bin\$appShortName.exe")
            {
                Remove-Item -Path "$($env:SystemDrive)\Users\$($_.Name)\AppData\Roaming\$appShortName" -Force -Recurse
                Remove-Item -Path "$($env:SystemDrive)\Users\$($_.Name)\AppData\Roaming\$($appShortName)VDI" -Force -Recurse
                Remove-Item -Path "$($env:SystemDrive)\Users\$($_.Name)\AppData\Roaming\Windows\Start Menu\Programs\$appShortName" -Force -Recurse
                Remove-Item -Path "$($env:SystemDrive)\Users\$($_.Name)\AppData\Roaming\Windows\Start Menu\Programs\$appShortName VDI" -Force -Recurse
            }
        }
        Catch
        {
            Out-Null
        }
    }

    # Remove registry entries from current profile
    Remove-RegistryKey -Key "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Zoom" -Recurse -ContinueOnError $True
    Remove-RegistryKey -Key "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\ZoomUMX" -Recurse -ContinueOnError $True
    Remove-RegistryKey -Key "HKCU:\Software\Zoom" -Recurse -ContinueOnError $True
    Remove-RegistryKey -Key "HKCU:\Software\ZoomUMX" -Recurse -ContinueOnError $True
    Remove-RegistryKey -Key "HKCU:\Software\Policies\Zoom\Zoom Meetings\VDI" -Recurse -ContinueOnError $True


    # Download latest setup file(s)
    If (-Not(Test-Path -Path $appScriptPath\$appVersion\$appSetup))
    {
        Write-Host -Object "Downloading $appName $appVersion..." -ForegroundColor Green -Debug
        Invoke-WebRequest -UseBasicParsing -Uri $appURL -OutFile $appScriptPath\$appVersion\$appSetup

    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Install latest version
    Write-Log -Message "Installing $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    Execute-MSI -Action Install -Path $appSetup -Parameters $appInstallParameters -AddParameters $appAddParameters

    # Stop and disable unneeded services
    Stop-Service -Name $appServices[0] -Force
    Set-Service -Name $appServices[0] -StartupType Manual

    # Configure application shortcut
    Remove-File -Path "$env:PUBLIC\Desktop\$appShortName VDI.lnk"
    Move-Item -Path "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\$appShortName VDI\$appShortName VDI.lnk" -Destination "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\$appShortName VDI.lnk" -Force
    Remove-Folder -Path "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\$appShortName VDI"

    # Go back to the parent folder
    Set-Location ..

    Write-Log -Message "$appName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
}
Else
{
    Write-Log -Message "$appName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}

#endregion