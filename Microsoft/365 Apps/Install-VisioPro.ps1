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
        [Parameter(Mandatory = $True)]
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

Function Get-MicrosoftOfficeUninstaller
{
    <#
    .SYNOPSIS
    Download Microsoft Office Uninstaller files

    .PARAMETER UninstallerURL
    Uninstaller URL repo

#>

    param(
        [string]$UninstallerURL = "https://raw.githubusercontent.com/OfficeDev/Office-IT-Pro-Deployment-Scripts/master/Office-ProPlus-Deployment/Remove-PreviousOfficeInstalls"
    )

    try
    {
        # Download
        If (-Not(Test-Path -Path $appUninstallerDir\Remove-PreviousOfficeInstalls.ps1))
        {
            Write-Log -Message "Downloading $appVendor $appName cleanup scripts..." -Severity 1 -LogType CMTrace -WriteHost $True
            New-Folder -Path $appUninstallerDir
            Invoke-WebRequest -Uri $UninstallerURL\OffScrub03.vbs -UseBasicParsing -OutFile $appUninstallerDir\OffScrub03.vbs
            Invoke-WebRequest -Uri $UninstallerURL\OffScrub07.vbs -UseBasicParsing -OutFile $appUninstallerDir\OffScrub07.vbs
            Invoke-WebRequest -Uri $UninstallerURL\OffScrub10.vbs -UseBasicParsing -OutFile $appUninstallerDir\OffScrub10.vbs
            Invoke-WebRequest -Uri $UninstallerURL\OffScrub_O15msi.vbs -UseBasicParsing -OutFile $appUninstallerDir\OffScrub_O15msi.vbs
            Invoke-WebRequest -Uri $UninstallerURL\OffScrub_O16msi.vbs -UseBasicParsing -OutFile $appUninstallerDir\OffScrub_O16msi.vbs
            Invoke-WebRequest -Uri $UninstallerURL\OffScrubc2r.vbs -UseBasicParsing -OutFile $appUninstallerDir\OffScrubc2r.vbs
            Invoke-WebRequest -Uri $UninstallerURL\Office2013Setup.exe -UseBasicParsing -OutFile $appUninstallerDir\Office2013Setup.exe
            Invoke-WebRequest -Uri $UninstallerURL\Office2016Setup.exe -UseBasicParsing -OutFile $appUninstallerDir\Office2016Setup.exe
            Invoke-WebRequest -Uri $UninstallerURL\Remove-PreviousOfficeInstalls.ps1 -UseBasicParsing -OutFile $appUninstallerDir\Remove-PreviousOfficeInstalls.ps1
        }
        Else
        {
            Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
        }

    }
    catch
    {
        Throw $_
    }
}

Function Get-MicrosoftOfficeConfig
{
    <#
    .SYNOPSIS
    Download Microsoft Office Configuration files

    .PARAMETER URL
    Configuration file URL
    #>

    param(
        [string]$ConfigURL = ""
    )

    try
    {
        # Download required config file
        If (-Not(Test-Path -Path $appScriptPath\$appConfig))
        {
            Write-Log -Message "Downloading $appVendor $appName Config.." -Severity 1 -LogType CMTrace -WriteHost $True
            Invoke-WebRequest -UseBasicParsing -Uri $appConfigURL -OutFile "$appScriptPath\$appConfig"
        }
        Else
        {
            Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
        }
    }
    catch
    {
        Throw $_
    }
}

#endregion

#----------------------------------------------------------[Declarations]----------------------------------------------------------

#region Declarations

$appVendor = "Microsoft"
$appName = "Visio"
$appConfigURL = "https://raw.githubusercontent.com/JonathanPitre/Apps/master/Microsoft/365%20Apps/VisioPro-VDI.xml"
$appConfig = Split-Path -Path $appConfigURL -Leaf # Download required config file
Get-MicrosoftOfficeConfig -ConfigURL $appConfigURL
$appSetup = "setup.exe"
$appProcesses = @("VISIO", "OfficeC2RClient", "OfficeClickToRun")
$appServices = @("ClickToRunSvc")
$appBitness = ([xml](Get-Content -Path $appScriptPath\$appConfig)).SelectNodes("//Add/@OfficeClientEdition").Value
$appChannel = ([xml](Get-Content -Path $appScriptPath\$appConfig)).SelectNodes("//@Channel").Value
$appDownloadParameters = "/download .\$appConfig"
$appInstallParameters = "/configure .\$appConfig"
$appUpdateParameters = "/update user displaylevel=true forceappshutdown=true"
$Evergreen = Get-EvergreenApp -Name Microsoft365Apps | Where-Object { $_.Channel -eq $appChannel }
$appVersion = $Evergreen.Version
$appURL = $Evergreen.URI
$appUninstallerDir = "$appScriptPath\Remove-PreviousOfficeInstalls"
If ($appBitness -eq "64")
{
    $appUpdateTool = "$env:CommonProgramFiles\microsoft shared\ClickToRun\OfficeC2RClient.exe"
    $appDestination = "$env:ProgramFiles\Microsoft Office\root\Office16"
    $appDownloadPath = "$env:ProgramFiles\Microsoft Office\Updates\Download"
}
ElseIf ($appBitness -eq "86")
{
    $appUpdateTool = "${env:CommonProgramFiles(x86)}\microsoft shared\ClickToRun\OfficeC2RClient.exe"
    $appDestination = "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16"
    $appDownloadPath = "${env:ProgramFiles(x86)}\Microsoft Office\Updates\Download"
}
[boolean]$isAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName .+" -RegEx)
$appInstalledVersion = (Get-InstalledApplication -Name "$appVendor $appName .*" -RegEx).DisplayVersion | Sort-Object -Descending | Select-Object -First 1

#endregion

#-----------------------------------------------------------[Execution]------------------------------------------------------------

#region Execution

Set-Location -Path $appScriptPath

If ([version]$appInstalledVersion -eq $null)
{
    # Download latest setup file(s)
    Write-Log -Message "Downloading the latest version of $appVendor Office Deployment Tool (ODT)..." -Severity 1 -LogType CMTrace -WriteHost $True
    Invoke-WebRequest -UseBasicParsing -Uri $appURL -OutFile "$appScriptPath\$appSetup"
    $appSetupVersion = (Get-Command .\$appSetup).FileVersionInfo.FileVersion

    # Uninstall previous version(s)
    Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
    Get-Process -Name $appProcesses | Stop-Process -Force

    # Download cleanup script
    Get-MicrosoftOfficeUninstaller
    & $appUninstallerDir\Remove-PreviousOfficeInstalls.ps1 -RemoveClickToRunVersions $True -Force $True -Remove2016Installs $True -NoReboot $True -ProductsToRemove $appName

    # Download latest version
    If (-Not(Test-Path -Path .\$appVersion)) { New-Folder -Path $appVersion }
    Copy-File $appConfig, $appSetup -Destination "$appScriptPath\$appVersion" -ContinueFileCopyOnError $True
    Set-Location -Path .\$appVersion

    If (-Not(Test-Path -Path .\Office\Data\v$appBitness.cab))
    {
        Write-Log -Message "Downloading $appVendor $appName x$appBitness $appChannel..." -Severity 1 -LogType CMTrace -WriteHost $True
        Execute-Process -Path .\$appSetup -Parameters $appDownloadParameters -PassThru
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Install latest version
    Write-Log -Message "Installing $appVendor $appName x$appBitness $appChannel..." -Severity 1 -LogType CMTrace -WriteHost $True
    Execute-Process -Path .\$appSetup -Parameters $appInstallParameters -PassThru
    Get-Process -Name OfficeC2RClient | Stop-Process -Force

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

    # Configure settings
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\common\OfficeUpdate" -Name "UpdateBranch"
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\common\OfficeUpdate" -Name "PreventTeamsInstall" -Value "1" -Type DWord
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\common\OfficeUpdate" -Name "PreventBingInstall" -Value "1" -Type DWord
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\common\OfficeUpdate" -Name "HideEnableDisableUpdates" -Value "1" -Type DWord
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\common\OfficeUpdate" -Name "HideUpdateNotifications" -Value "1" -Type DWord

    # Disable updates
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\common\OfficeUpdate" -Name "EnableAutomaticUpdates" -Value "0" -Type DWord
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Microsoft\Office\ClickToRun\Configuration" -Name "UpdatesEnabled" -Value "False" -Type String

    # Configure application shortcut
    Rename-Item -Path "$envCommonStartMenuPrograms\OneNote 2016.lnk" -NewName "$envCommonStartMenuPrograms\OneNote.lnk"

    # Stop and disable unneeded scheduled tasks
    Get-ScheduledTask -TaskName "Office*" | Stop-ScheduledTask
    Get-ScheduledTask -TaskName "Office*" | Disable-ScheduledTask

    # Go back to the parent folder
    Set-Location ..

    Write-Log -Message "$appVendor $appName x$appBitness $appChannel was successfully installed!" -Severity 1 -LogType CMTrace -WriteHost $True
}
ElseIf (([version]$appVersion -gt [version]$appInstalledVersion) -and (Test-Path -Path $appUpdateTool))
{
    # Uninstall previous version(s)
    Write-Log -Message "Stop problematic processes..." -Severity 1 -LogType CMTrace -WriteHost $True
    Get-Process -Name $appProcesses | Stop-Process -Force

    # Configure settings
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\common\OfficeUpdate" -Name "UpdateBranch"
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\common\OfficeUpdate" -Name "PreventTeamsInstall" -Value "1" -Type DWord
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\common\OfficeUpdate" -Name "PreventBingInstall" -Value "1" -Type DWord
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\common\OfficeUpdate" -Name "HideEnableDisableUpdates" -Value "1" -Type DWord
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\common\OfficeUpdate" -Name "HideUpdateNotifications" -Value "1" -Type DWord

    # Enable updates
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\common\OfficeUpdate" -Name "EnableAutomaticUpdates" -Value "1" -Type DWord
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Microsoft\Office\ClickToRun\Configuration" -Name "UpdatesEnabled" -Value "True" -Type String

    # Enable and start require services
    Set-ServiceStartMode -Name $appServices[0] -StartMode "Automatic" -ContinueOnError $True
    Start-ServiceAndDependencies -Name $appServices[0] -SkipServiceExistsTest -ContinueOnError $True

    # Install latest version
    Write-Log -Message "Installing $appVendor $appName x$appBitness $appChannel..." -Severity 1 -LogType CMTrace -WriteHost $True
    Execute-Process -Path $appUpdateTool -Parameters $appUpdateParameters

    # Close "You're up to date!" notification window
    Wait-Process -Name OfficeClickToRun
    Send-Keys -WindowTitle "Updates were installed" -Keys "{ENTER}" -WaitSeconds 2
    Get-Process -Name OfficeC2RClient, OfficeClickToRun | Stop-Process -Force

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

    # Disable updates
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\common\OfficeUpdate" -Name "EnableAutomaticUpdates" -Value "0" -Type DWord
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Microsoft\Office\ClickToRun\Configuration" -Name "UpdatesEnabled" -Value "False" -Type String

    # Configure application shortcut
    Rename-Item -Path "$envCommonStartMenuPrograms\OneNote 2016.lnk" -NewName "$envCommonStartMenuPrograms\OneNote.lnk"

    # Stop and disable unneeded scheduled tasks
    Get-ScheduledTask -TaskName "Office*" | Stop-ScheduledTask
    Get-ScheduledTask -TaskName "Office*" | Disable-ScheduledTask

    # Remove temp download
    Remove-File "$appDownloadPath\*" -Recurse

    # Go back to the parent folder
    Set-Location ..

    Write-Log -Message "$appVendor $appName x$appBitness $appChannel was successfully installed!" -Severity 1 -LogType CMTrace -WriteHost $True
}
Else
{
    Write-Log -Message "$appVendor $appName x$appBitness $appChannel is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}

#endregion