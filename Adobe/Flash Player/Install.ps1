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
$appVendor = "Adobe"
$appName = "Flash Player"
$appProcesses = @("chrome", "iexplore", "firefox", "AdobeFlashPlayerUpdateSvc")
$appInstallParameters = "/QB"
$appVersion = "32.0.0.465" #Latest version
$appURLActiveX = "https://download.macromedia.com/pub/flashplayer/pdc/$appVersion/install_flash_player_32_active_x.msi"
$appURLPPAPI = "https://download.macromedia.com/pub/flashplayer/pdc/$appVersion/install_flash_player_32_ppapi.msi"
$appURLPlugin = "https://download.macromedia.com/get/flashplayer/pdc/$appVersion/install_flash_player_32_plugin.msi"
$appURLUninstaller = "https://fpdownload.macromedia.com/get/flashplayer/current/support/uninstall_flash_player.exe"
$appSetupActiveX = $appURLActiveX.split("/")[7]
$appSetupPPAPI = $appURLPPAPI.split("/")[7]
$appSetupPlugin = $appURLPlugin.split("/")[7]
$appSetupUninstaller = $appURLUninstaller.split("/")[7]
$appDestinationx86 = "$env:SystemRoot\System32\Macromed\Flash"
$appDestinationx64 = "$env:SystemRoot\SysWOW64\Macromed\Flash"
[boolean]$IsAppInstalled = (Get-InstalledApplication -Name "$appVendor $appName \d{2}" -RegEx)
$appInstalledVersion = (Get-InstalledApplication -Name "$appVendor $appName \d{2}" -RegEx).DisplayVersion | Select-Object -First 1
##*===============================================

If ([version]$appVersion -gt [version]$appInstalledVersion) {
    Set-Location -Path $appScriptDirectory
    If (-Not(Test-Path -Path $appVersion)) {New-Folder -Path $appVersion}
    Set-Location -Path $appVersion

    # Uninstall previous versions
    Get-Process -Name $appProcesses | Stop-Process -Force
    If ($IsAppInstalled) {
        Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
        Execute-Process -Path .\$appSetupUninstaller -Parameters "-uninstall"
    }

    # Download latest setup file(s)
    If (-Not(Test-Path -Path $appScriptDirectory\$appVersion\$appSetupUninstaller)) {
        Write-Log -Message "Downloading $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURLActiveX -OutFile $appSetupActiveX
        Invoke-WebRequest -UseBasicParsing -Uri $appURLPPAPI -OutFile $appSetupPPAPI
        Invoke-WebRequest -UseBasicParsing -Uri $appURLPlugin -OutFile $appSetupPlugin
        Invoke-WebRequest -UseBasicParsing -Uri $appURLUninstaller -OutFile $appSetupUninstaller
    }
    Else {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Install latest version
    Write-Log -Message "Installing $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    #Execute-MSI -Action Install -Path $appSetupActiveX -Parameters $appInstallParameters
    Execute-MSI -Action Install -Path $appSetupPlugin -Parameters $appInstallParameters
    Execute-MSI -Action Install -Path $appSetupPPAPI -Parameters $appInstallParameters

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True
    Copy-File -Path "$appScriptDirectory\mms.cfg" -Destination "$appDestinationx86"
    Copy-File -Path "$appScriptDirectory\mms.cfg" -Destination "$appDestinationx64"
    Get-ScheduledTask -TaskName "$appVendor $appName*" | Stop-ScheduledTask
    Get-ScheduledTask -TaskName "$appVendor $appName*" | Disable-ScheduledTask
    Stop-ServiceAndDependencies -Name "$($appVendor)FlashPlayerUpdateSvc"
    Set-ServiceStartMode -Name "$($appVendor)FlashPlayerUpdateSvc" -StartMode "Disabled"

    # Go back to the parent folder
    Set-Location ..

    Write-Log -Message "$appVendor $appName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
}
Else {
    Write-Log -Message "$appVendor $appName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}