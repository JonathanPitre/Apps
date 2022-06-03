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

Function Get-MicrosoftOfficeUninstaller
{
    <#
    .SYNOPSIS
    Process Office Admx files

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

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$appVendor = "Microsoft"
$appName = "Project"
$appSetup = "setup.exe"
$appProcesses = @("WINPROJ")
$appConfigURL = "https://raw.githubusercontent.com/JonathanPitre/Apps/master/Microsoft/Office%20365/Project365-x64-VDI.xml"
$appConfig = Split-Path -Path $appConfigURL -Leaf
$appBitness = ([xml](Get-Content -Path $appScriptDirectory\$appConfig)).SelectNodes("//Add/@OfficeClientEdition").Value
$appChannel = ([xml](Get-Content -Path $appScriptDirectory\$appConfig)).SelectNodes("//@Channel").Value
$appDownloadParameters = "/download .\$appConfig"
$appInstallParameters = "/configure .\$appConfig"
$Evergreen = Get-EvergreenApp -Name Microsoft365Apps | Where-Object {$_.Channel -eq $appChannel}
$EvergreenADMX = Get-MicrosoftOfficeAdmxOnline | Where-Object { $_.Architecture -match $appBitness }
$appADMXURL = $EvergreenADMX.URI
$appADMX = Split-Path -Path $appADMXURL -Leaf
$appVersion = $Evergreen.Version
$appURL = $Evergreen.URI
$appUninstallerDir = "$appScriptDirectory\Remove-PreviousOfficeInstalls"
If ($appBitness -eq "64") {$appDestination = "$env:ProgramFiles\Microsoft Office\root\Office16"}
If ($appBitness -eq "86") {$appDestination = "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16"}
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName .+ " -RegEx)
$appInstalledVersion = (Get-InstalledApplication -Name "$appVendor $appName .* " -RegEx).DisplayVersion | Sort-Object -Descending | Select-Object -First 1

#-----------------------------------------------------------[Execution]------------------------------------------------------------

If ([version]$appVersion -gt [version]$appInstalledVersion)
{
    Set-Location -Path $appScriptDirectory

    # Download latest setup file(s)
    Write-Log -Message "Downloading the latest version of $appVendor Office Deployment Tool (ODT)..." -Severity 1 -LogType CMTrace -WriteHost $True
    Invoke-WebRequest -UseBasicParsing -Uri $appURL -OutFile $appSetup
    $appSetupVersion = (Get-Command .\$appSetup).FileVersionInfo.FileVersion

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

    # Uninstall previous version(s)
    Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
    Get-Process -Name $appProcesses | Stop-Process -Force
    # Download cleanup script
    Get-MicrosoftOfficeUninstaller
    & $appUninstallerDir\-RemoveClickToRunVersions $true -Force $true -Remove2016Installs $true -NoReboot $true -ProductsToRemove $appName

    # Download latest version
    If (-Not(Test-Path -Path .\$appVersion)) {New-Folder -Path $appVersion}
    Copy-File $appConfig, $appSetup -Destination $appVersion -ContinueFileCopyOnError $True
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
    Execute-Process -Path .\$appSetup -Parameters $appInstallParameters -Passthru
    Get-Process -Name OfficeC2RClient | Stop-Process -Force

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True
    Get-ScheduledTask -TaskName "Office*" | Stop-ScheduledTask
    Get-ScheduledTask -TaskName "Office*" | Disable-ScheduledTask

    # Go back to the parent folder
    Set-Location ..

    Write-Log -Message "$appVendor $appName x$appBitness $appChannel was successfully installed!" -Severity 1 -LogType CMTrace -WriteHost $True
}
Else
{
    Write-Log -Message "$appVendor $appName x$appBitness $appChannel is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}