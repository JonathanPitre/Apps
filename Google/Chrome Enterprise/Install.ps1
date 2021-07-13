# Standalone application install script for VDI environment - (C)2021 Jonathan Pitre & Owen Reynolds, inspired by xenappblog.com

#Requires -Version 5.1
#Requires -RunAsAdministrator

# Custom package providers list
$PackageProviders = @("Nuget")

# Custom modules list
$Modules = @("PSADT", "Evergreen")

Write-Verbose -Message "Importing custom modules..." -Verbose

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials

# Install custom package providers list
Foreach ($PackageProvider in $PackageProviders) {
    If (-not(Get-PackageProvider -ListAvailable -Name $PackageProvider -ErrorAction SilentlyContinue)) { Install-PackageProvider -Name $PackageProvider -Force }
}

# Add the Powershell Gallery as trusted repository
Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted

# Update PowerShellGet
$InstalledPSGetVersion = (Get-PackageProvider -Name PowerShellGet).Version
$PSGetVersion = [version](Find-PackageProvider -Name PowerShellGet).Version
If ($PSGetVersion -gt $InstalledPSGetVersion) { Install-PackageProvider -Name PowerShellGet -Force }

# Install and import custom modules list
Foreach ($Module in $Modules) {
    If (-not(Get-Module -ListAvailable -Name $Module)) { Install-Module -Name $Module -AllowClobber -Force | Import-Module -Name $Module -Force }
    Else {
        $InstalledModuleVersion = (Get-InstalledModule -Name $Module).Version
        $ModuleVersion = (Find-Module -Name $Module).Version
        $ModulePath = (Get-InstalledModule -Name $Module).InstalledLocation
        $ModulePath = (Get-Item -Path $ModulePath).Parent.FullName
        If ([version]$ModuleVersion -gt [version]$InstalledModuleVersion) {
            Update-Module -Name $Module -Force
            Remove-Item -Path $ModulePath\$InstalledModuleVersion -Force -Recurse
        }
    }
}

Write-Verbose -Message "Custom modules were successfully imported!" -Verbose

# Get the current script directory
Function Get-ScriptDirectory {
    Remove-Variable appScriptDirectory
    Try {
        If ($psEditor) { Split-Path $psEditor.GetEditorContext().CurrentFile.Path } # Visual Studio Code Host
        ElseIf ($psISE) { Split-Path $psISE.CurrentFile.FullPath } # Windows PowerShell ISE Host
        ElseIf ($PSScriptRoot) { $PSScriptRoot } # Windows PowerShell 3.0-5.1
        Else {
            Write-Host -ForegroundColor Red "Cannot resolve script file's path"
            Exit 1
        }
    }
    Catch {
        Write-Host -ForegroundColor Red "Caught Exception: $($Error[0].Exception.Message)"
        Exit 2
    }
}

# Variables Declaration
# Generic
$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"
$env:SEE_MASK_NOZONECHECKS = 1
$appScriptDirectory = Get-ScriptDirectory

# Application related
##*===============================================
$appVendor = "Google"
$appName = "Chrome"
$appLongName = "Enterprise"
$appProcesses = @("chrome", "GoogleUpdate", "chrome_proxy", "elevation_service")
$appServices = @("gupdate", "gupdatem", "GoogleChromeElevationService")
$appInstallParameters = "/QB"
$Evergreen = Get-EvergreenApp -Name GoogleChrome | Where-Object {$_.Architecture -eq "x64"}
$appVersion = $Evergreen.Version
$appURL = $Evergreen.URI
$appSetup = Split-Path -Path $appURL -Leaf
$appURLADMX = "https://dl.google.com/dl/edgedl/chrome/policy/policy_templates.zip"
$appADMX = Split-Path -Path $appURLADMX -Leaf
$appURLADMX2 = "https://dl.google.com/dl/update2/enterprise/googleupdateadmx.zip"
$appADMX2 = Split-Path -Path $appURLADMX2 -Leaf
$appConfigURL = "https://raw.githubusercontent.com/JonathanPitre/Apps/master/Google/Chrome%20Enterprise/master_preferences"
$appConfig = Split-Path -Path $appConfigURL -Leaf
$appDestination = "$env:ProgramFiles\$appVendor\$appName\Application"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName" -Exact)
$appInstalledVersion = (Get-InstalledApplication -Name "$appVendor $appName" -Exact).DisplayVersion | Select-Object -First 1
##*===============================================

If ([version]$appVersion -gt [version]$appInstalledVersion) {
    Set-Location -Path $appScriptDirectory
    If (-Not(Test-Path -Path $appVersion)) { New-Folder -Path $appVersion }
    Set-Location -Path $appVersion

    # Delete machine policies to prevent issue during installation
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\Policies\$appVendor\Update" -Recurse -ContinueOnError $True
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\Policies\$appVendor\$appName" -Recurse -ContinueOnError $True
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Policies\$appVendor\Temp" -Recurse -ContinueOnError $True
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Policies\$appVendor\Update" -Recurse -ContinueOnError $True
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Policies\$appVendor\$appName" -Recurse -ContinueOnError $True

    # Uninstall previous versions
    Get-Process -Name $appProcesses | Stop-Process -Force
    If ($IsAppInstalled) {
        Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
        Remove-MSIApplications -Name "$appVendor $appName" -Parameters $appInstallParameters
        Remove-MSIApplications -Name $($appVendor)Update -Parameters $appInstallParameters
    }

    # Uninstall Google Update
    If (Test-Path -Path "$env%LocalAppData\$appVendor\Update\$($appVendor)Update.exe") {
        Write-Log -Message "Removing previous $appVendor $appName $appLongName folder to fix issues with new installation." -Severity 1 -LogType CMTrace -WriteHost $True
        Execute-Process -Path "$envLocalAppData\$appVendor\Update\$($appVendor)Update.exe" -Parameters "-uninstall" -IgnoreExitCodes 1606220281 -ContinueOnError $True
    }
    If (Test-Path -Path "$envProgramFilesX86\$appVendor\Update\$($appVendor)Update.exe") {
        Write-Log -Message "Removing previous $appVendor $appName $appLongName folder to fix issues with new installation." -Severity 1 -LogType CMTrace -WriteHost $True
        Execute-Process -Path "$envProgramFilesX86\$appVendor\Update\$($appVendor)Update.exe" -Parameters "-uninstall" -IgnoreExitCodes 1606220281 -ContinueOnError $True
    }

    # Remove previous install folders
    Remove-Folder -Path "$envLocalAppData\$appVendor\$appName" -ContinueOnError $True
    Remove-Folder -Path "$envLocalAppData\$appVendor\Update" -ContinueOnError $True
    Remove-Folder -Path "$envLocalAppData\$appVendor\Software Reporter Tool" -ContinueOnError $True
    Remove-Folder -Path "$envLocalAppData\$appVendor\Policies" -ContinueOnError $True
    Remove-Folder -Path "$envLocalAppData\$appVendor\Temp" -ContinueOnError $True
    Remove-Folder -Path "$envLocalAppData\$appVendor\CrashReports" -ContinueOnError $True
    Remove-Folder -Path "$envProgramFilesX86\$appVendor\$appName" -ContinueOnError $True
    Remove-Folder -Path "$envProgramFilesX86\$appVendor\Update" -ContinueOnError $True
    Remove-Folder -Path "$envProgramFilesX86\$appVendor\Policies" -ContinueOnError $True
    Remove-Folder -Path "$envProgramFilesX86\$appVendor\Temp" -ContinueOnError $True
    Remove-Folder -Path "$envProgramFilesX86\$appVendor\CrashReports" -ContinueOnError $True

    # Download latest setup file(s)
    If (-Not(Test-Path -Path $appScriptDirectory\$appVersion\$appSetup)) {
        Write-Log -Message "Downloading $appVendor $appName $appLongName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURL -OutFile $appSetup
    }
    Else {
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

    # Download latest policy definitions
    Write-Log -Message "Downloading $appVendor $appName $appLongName $appVersion ADMX templates..." -Severity 1 -LogType CMTrace -WriteHost $True
    Invoke-WebRequest -UseBasicParsing -Uri $appURLADMX -OutFile $appScriptDirectory\$appADMX
    Invoke-WebRequest -UseBasicParsing -Uri $appURLADMX2 -OutFile $appScriptDirectory\$appADMX2
    New-Folder -Path "$appScriptDirectory\PolicyDefinitions"
    If (Get-ChildItem -Path $appScriptDirectory -Filter *.zip) {
        Get-ChildItem -Path $appScriptDirectory -Filter *.zip | Expand-Archive -DestinationPath $appScriptDirectory\PolicyDefinitions -Force
        Remove-File -Path $appScriptDirectory\*.zip -ContinueOnError $True
    }
    Move-Item -Path $appScriptDirectory\PolicyDefinitions\GoogleUpdateAdmx\* -Destination $appScriptDirectory\PolicyDefinitions -Force
    Move-Item -Path $appScriptDirectory\PolicyDefinitions\windows\admx\* -Destination $appScriptDirectory\PolicyDefinitions -Force
    Remove-Item -Path $appScriptDirectory\PolicyDefinitions -Include "GoogleUpdateAdmx", "chromeos", "common", "windows", "VERSION" -Force -Recurse

    # Install latest version
    Write-Log -Message "Installing $appVendor $appName $appLongName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    Execute-MSI -Action Install -Path $appSetup -Parameters $appInstallParameters

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

    # Copy preferences file
    Copy-File -Path "$appScriptDirectory\master_preferences" -Destination $appDestination

    # Stop and disable unneeded scheduled tasks
    Get-ScheduledTask -TaskName "$appVendor*" | Stop-ScheduledTask
    Get-ScheduledTask -TaskName "$appVendor*" | Disable-ScheduledTask

    # Stop and disable unneeded services
    Stop-ServiceAndDependencies -Name $appServices[0]
    Stop-ServiceAndDependencies -Name $appServices[1]
    Stop-ServiceAndDependencies -Name $appServices[2]
    Set-ServiceStartMode -Name $appServices[0] -StartMode "Manual"
    Set-ServiceStartMode -Name $appServices[1] -StartMode "Disabled"
    Set-ServiceStartMode -Name $appServices[2] -StartMode "Disabled"

    # Remove Active Setup - https://dennisspan.com/google-chrome-on-citrix-deep-dive/#StubPath
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{8A69D345-D564-463c-AFF1-A69D9E530F96}" -Name "StubPath"

    # Creates a pinned taskbar icons for all users
    New-Shortcut -Path "$envSystemDrive\Users\Default\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\Taskbar\$appVendor $appName.lnk" -TargetPath "$appDestination\$($appProcesses[0]).exe" -IconLocation "$appDestination\$($appProcesses[0]).exe" -Description "$appVendor $appName" -WorkingDirectory "$appDestination"

    # Remove desktop shortcut for all users
    #Remove-File -Path "$envCommonDesktop\$appVendor $appName.lnk" -ContinueOnError $True

    Update-GroupPolicy

    # Go back to the parent folder
    Set-Location ..

    Write-Log -Message "$appVendor $appName $appLongName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True

}
Else {
    Write-Log -Message "$appVendor $appName $appLongName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}