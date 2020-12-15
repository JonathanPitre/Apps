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
$appVendor = "Adobe"
$appName = "Creative Cloud"
$appSetup = "setup.exe"
$appProcesses = @("ccxprocess", "Creative Cloud", "AdobeUpdateService", "AGMService", "AGSService", "AGCInvokerUtility")
$appInstallParameters = "--silent"
$appCleanerToolParameters = "--cleanupXML=$appScriptDirectory\cleanup.xml"
$appVersion = "5.1.0.407"
$appSource = $appVersion
$appDestination = "${env:ProgramFiles(x86)}\Adobe\Adobe Creative Cloud\Utils"
# https://helpx.adobe.com/ca/creative-cloud/kb/cc-cleaner-tool-installation-problems.html
$appURLUninstaller = "http://download.macromedia.com/SupportTools/Cleaner/win/AdobeCreativeCloudCleanerTool.exe"
$appSetupUninstaller = $appURLUninstaller.split("/")[6]
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName")
$appInstalledVersion = (Get-InstalledApplication -Name "$appVendor $appName").DisplayVersion
##*===============================================

If ([version]$appVersion -gt [version]$appInstalledVersion) {
    Set-Location -Path $appScriptDirectory

    If (-Not(Test-Path -Path $appScriptDirectory\$appSetupUninstaller)) {
        Write-Log -Message "Downloading $appVendor $appName Cleaner Tool..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURLUninstaller -OutFile $appSetupUninstaller
    }
    Else {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
    Get-Process -Name $appProcesses | Stop-Process -Force
    If ($IsAppInstalled) {
        #Execute-Process -Path .\$appSetupUninstaller -Parameters "$appCleanerToolParameters"
        Execute-Process -Path "$appDestination\Uninstaller.exe" -Parameters "-uninstall"
    }

    Write-Log -Message "Installing $appVendor $appName $appShortVersion $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    Execute-Process -Path .\$appSetup -Parameters $appInstallParameters

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True
    Get-ScheduledTask -TaskName "$($appVendor)GCInvoker-1.0" | Stop-ScheduledTask
    Get-ScheduledTask -TaskName "$($appVendor)GCInvoker-1.0" | Disable-ScheduledTask

    Stop-ServiceAndDependencies -Name "$($appVendor)UpdateService"
    Set-ServiceStartMode -Name "$($appVendor)UpdateService" -StartMode "Disabled"
    Stop-ServiceAndDependencies -Name "$($appVendor)AGMService"
    Set-ServiceStartMode -Name "$($appVendor)AGMService" -StartMode "Disabled"
    Stop-ServiceAndDependencies -Name "$($appVendor)AGSService"
    Set-ServiceStartMode -Name "$($appVendor)AGSService" -StartMode "Disabled"

    Remove-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Adobe Creative Cloud" -ContinueOnError $True
    Remove-File -Path "$envCommonDesktop\$appVendor $appName.lnk" -ContinueOnError $True

}
Else {
    Write-Log -Message "$appVendor $appName $appShortVersion $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}

<#
Write-Verbose -Message "Uninstalling custom modules..." -Verbose
Foreach ($Module in $Modules) {
    If ((Get-Module -ListAvailable -Name $Module)) {Uninstall-Module -Name $Module -Force}
}
Write-Verbose -Message "Custom modules were succesfully uninstalled!" -Verbose
#>