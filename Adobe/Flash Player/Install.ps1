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
$appProcess = @("chrome", "iexplore", "firefox", "AdobeFlashPlayerUpdateSvc")
$appInstallParameters = "/QB"
$webResponse = Invoke-WebRequest -UseBasicParsing -Uri ("https://get.adobe.com/flashplayer/") -SessionVariable websession
$webVersion = $webResponse.RawContent | Select-String '(Version\s{1}\d{2}.\d.\d.\d{3})' -AllMatches | ForEach-Object { $_.Matches.Value } | Select-Object -Unique
$appVersion = $webVersion.Split(" ")[1]
$appURLActiveX = "https://download.macromedia.com/pub/flashplayer/pdc/$appVersion/install_flash_player_32_active_x.msi"
$appURLPPAPI = "https://download.macromedia.com/pub/flashplayer/pdc/$appVersion/install_flash_player_32_ppapi.msi"
$appURLPlugin = "https://download.macromedia.com/get/flashplayer/pdc/$appVersion/install_flash_player_32_plugin.msi"
$appURLUninstaller = "https://fpdownload.macromedia.com/get/flashplayer/current/support/uninstall_flash_player.exe"
$appSetupActiveX = $appURLActiveX.split("/")[7]
$appSetupPPAPI = $appURLPPAPI.split("/")[7]
$appSetupPlugin = $appURLPlugin.split("/")[7]
$appSetupUninstaller = $appURLUninstaller.split("/")[7]
$appSource = $appVersion
$appDestinationx86 = "$envSystem32Directory\Macromed\Flash"
$appDestinationx64 = "$envSystemRoot\SysWOW64\Macromed\Flash"
[boolean]$IsAppInstalled = (Get-InstalledApplication -Name "$appVendor $appName \d{2}" -RegEx)
$appInstalledVersion = (Get-InstalledApplication -Name "$appVendor $appName \d{2}" -RegEx).DisplayVersion | Select-Object -First 1
##*===============================================

If ([version]$appVersion -gt [version]$appInstalledVersion) {
    Set-Location -Path $appScriptDirectory
    If (-Not(Test-Path -Path $appSource)) {New-Folder -Path $appSource}
    Set-Location -Path $appSource

    Write-Log -Message "Downloading $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    If (-Not(Test-Path -Path $appScriptDirectory\$appSource\$appSetupUninstaller)) {
        Invoke-WebRequest -UseBasicParsing -Uri $appURLActiveX -OutFile $appSetupActiveX
        Invoke-WebRequest -UseBasicParsing -Uri $appURLPPAPI -OutFile $appSetupPPAPI
        Invoke-WebRequest -UseBasicParsing -Uri $appURLPlugin -OutFile $appSetupPlugin
        Invoke-WebRequest -UseBasicParsing -Uri $appURLUninstaller -OutFile $appSetupUninstaller
    }
    Else {
        Write-Log -Message "File already exists. Skipping Download" -Severity 1 -LogType CMTrace -WriteHost $True
    }

    Get-Process -Name $appProcess | Stop-Process -Force
    If ($IsAppInstalled) {
        Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
        Execute-Process -Path .\$appSetupUninstaller -Parameters "-uninstall"
    }

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

    Write-Log -Message "$appVendor $appName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True

}
Else {
    Write-Log -Message "$appVendor $appName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}

<#
Write-Verbose -Message "Uninstalling custom modules..." -Verbose
Foreach ($Module in $Modules) {
    If ((Get-Module -ListAvailable -Name $Module)) {Uninstall-Module -Name $Module -Force}
}

Write-Verbose -Message "Custom modules were succesfully uninstalled!" -Verbose
#>