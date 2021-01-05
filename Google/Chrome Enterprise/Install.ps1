# PowerShell Wrapper for MDT, Standalone and Chocolatey Installation - (C)2020 Jonathan Pitre, inspired by xenappblog.com
# Example 1 Install EXE:
# Execute-Process -Path .\appName.exe -Parameters "/silent"
# Example 2 Install MSI:
# Execute-MSI -Action Install -Path appName.msi -Parameters "/QB" -AddParameters "ALLUSERS=1"
# Example 3 Uninstall MSI:
# Remove-MSIApplications -Name "appName" -Parameters "/QB"

#Requires -Version 5.1

# Custom package providers list
$PackageProviders = @("Nuget")

# Custom modules list
$Modules = @("PSADT", "Evergreen")

Set-ExecutionPolicy -ExecutionPolicy Bypass -Force

# Checking for elevated permissions...
If (-not([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning -Message "Insufficient permissions to continue! PowerShell must be run with admin rights."
    Break
}
Else {
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
}

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
$appSetup = "GoogleChromeStandaloneEnterprise64.msi"
$appProcesses = @("chrome", "GoogleUpdate", "chrome_proxy", "elevation_service")
$appServices = @("gupdate", "gupdatem", "GoogleChromeElevationService")
$appInstallParameters = "/QB"
$Evergreen = Get-GoogleChrome | Where-Object {$_.Architecture -eq "x64"}
$appVersion = $Evergreen.Version
$appURL = $Evergreen.URI
$appURLADMX = "https://dl.google.com/dl/edgedl/chrome/policy/policy_templates.zip"
$appADMX = ($appURLADMX).Split("/")[7]
$appURLADMX2 = "https://dl.google.com/dl/update2/enterprise/googleupdateadmx.zip"
$appADMX2 = ($appURLADMX2).Split("/")[6]
$appSource = $appVersion
$appDestination = "$env:ProgramFiles\$appVendor\$appName\Application"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName" -Exact)
$appInstalledVersion = (Get-InstalledApplication -Name "$appVendor $appName" -Exact).DisplayVersion | Select-Object -First 1
##*===============================================

If ([version]$appVersion -gt [version]$appInstalledVersion) {
    Set-Location -Path $appScriptDirectory
    If (-Not(Test-Path -Path $appSource)) { New-Folder -Path $appSource }
    Set-Location -Path $appSource

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
    If (-Not(Test-Path -Path $appScriptDirectory\$appSource\$appSetup)) {
        Write-Log -Message "Downloading $appVendor $appName $appLongName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURL -OutFile $appSetup
    }
    Else {
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
    Set-ServiceStartMode -Name $appServices[0] -StartMode "Disabled"
    Set-ServiceStartMode -Name $appServices[1] -StartMode "Disabled"
    Set-ServiceStartMode -Name $appServices[2] -StartMode "Disabled"

    # Creates a pinned taskbar icons for all users
    New-Shortcut -Path "$envSystemDrive\Users\Default\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\Taskbar\$appVendor $appName.lnk" -TargetPath "$appDestination\$($appProcesses[0]).exe" -IconLocation "$appDestination\$($appProcesses[0]).exe" -Description "$appVendor $appName" -WorkingDirectory "$appDestination"

    # Remove Active Setup - https://dennisspan.com/google-chrome-on-citrix-deep-dive/#StubPath
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{8A69D345-D564-463c-AFF1-A69D9E530F96}" -Name "StubPath"

    # Remove desktop shortcut for all users
    #Remove-File "$envCommonDesktop\$appVendor $appName.lnk" -ContinueOnError $True

    Update-GroupPolicy

    Write-Log -Message "$appVendor $appName $appLongName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True

}
Else {
    Write-Log -Message "$appVendor $appName $appLongName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}

<#
Write-Verbose -Message "Uninstalling custom modules..." -Verbose
Foreach ($Module in $Modules) {
    If ((Get-Module -ListAvailable -Name $Module)) {Uninstall-Module -Name $Module -Force}
}
Write-Verbose -Message "Custom modules were succesfully uninstalled!" -Verbose
#>