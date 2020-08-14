# PowerShell Wrapper for MDT, Standalone and Chocolatey Installation - (C)2020 Jonathan Pitre, inspired by xenappblog.com
# Example 1 Install EXE:
# Execute-Process -Path .\appName.exe -Parameters "/silent"
# Example 2 Install MSI:
# Execute-MSI -Action Install -Path appName.msi -Parameters "/QB" -AddParameters "ALLUSERS=1"
# Example 3 Uninstall MSI:
# Remove-MSIApplications -Name "appName" -Parameters "/QB"

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
        If (-not(Get-PackageProvider -ListAvailable -Name $PackageProvider -ErrorAction SilentlyContinue)) {Install-PackageProvider -Name $PackageProvider -Force}
    }

    # Add the Powershell Gallery as trusted repository
    Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted

    # Update PowerShellGet
    $InstalledPSGetVersion = (Get-PackageProvider -Name PowerShellGet).Version
    $PSGetVersion = [version](Find-PackageProvider -Name PowerShellGet).Version
    If ($PSGetVersion -gt $InstalledPSGetVersion) {Install-PackageProvider -Name PowerShellGet -Force}

    # Install and import custom modules list
    Foreach ($Module in $Modules) {
        If (-not(Get-Module -ListAvailable -Name $Module)) {Install-Module -Name $Module -AllowClobber -Force | Import-Module -Name $Module -Force}
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
    If ($psISE) {Split-Path $psISE.CurrentFile.FullPath}
    Else {$Global:PSScriptRoot}
}

# Variables Declaration
# Generic
$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"
$appScriptDirectory = Get-ScriptDirectory
$env:SEE_MASK_NOZONECHECKS = 1
# Application related
##*===============================================
$appVendor = "Adobe"
$appName = "Acrobat"
$appSetup = "AcroPro.msi"
$appProcess = @("Acrobat", "AcroBroker", "acrobat_sl", "AcroCEF", "acrodist", "acrotray", "AcroRd32", "Acrobat Elements", "AcroTextExtractor", "ADelRCP", "AdobeCollabSync", "arh", "FullTrustNotIfier", "LogTransport2", "wow_helper", "outlook", "chrome", "iexplore")
$appTransform = "AcroPro.mst"
$appInstallParameters = "/QB"
$appParameters = "--tool=VolumeSerialize --generate --serial=1016-1899-8440-6413-0576-7429 --leid=V7{}AcrobatCont-12-Win-GM --regsuppress=ss --eulasuppress --stream" #--provfile Optional; path of the folder where prov.xml is created. If this parameter is not specified, prov.xml is created in the folder in which APTEE resides.
$appAddParameters = "IGNOREVCRT64=1 EULA_ACCEPT=YES UPDATE_MODE=0 DISABLE_ARM_SERVICE_INSTALL=1 ROAMIDENTITY=1 ROAMLICENSING=1"
$appVersion = ($appPatch).Substring(12, 10)
$appVersion = ("$appVersion").Insert(2, ".").Insert(6, ".")
$appShortVersion = "DC"
$appPatch = (Get-ChildItem $appScriptDirectory | Where-Object -Property Name -Match -Value "AcrobatDCUpd.*.msp$" | Sort-Object CreationTime -Descending | Select-Object -First 1 | Select-Object -ExpandProperty Name)
$appSource = $appVersion
$appDestination = "$envProgramFilesX86\$appVendor\$appName $appShortVersion\$appName"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName $appShortVersion")
$appInstalledVersion = (Get-InstalledApplication -Name "$appVendor $appName $appShortVersion").DisplayVersion
##*===============================================

If ([version]$appVersion -gt [version]$appInstalledVersion) {
    Set-Location -Path $appScriptDirectory

    Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
    Get-Process -Name $appProcess | Stop-Process -Force

    Write-Log -Message "Installing $appVendor $appName $appShortVersion $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    Execute-MSI -Action Install -Path $appSetup -Transform $appTransform -Parameters $appInstallParameters -AddParameters $appAddParameters -Patch $appPatch -SkipMSIAlreadyInstalledCheck

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True
    Get-ScheduledTask -TaskName "$appVendor Acrobat Update Task" | Stop-ScheduledTask
    Get-ScheduledTask -TaskName "$appVendor Acrobat Update Task" | Disable-ScheduledTask
    Stop-ServiceAndDependencies -Name "$($appVendor)UpdateService"
    Set-ServiceStartMode -Name "$($appVendor)UpdateService" -StartMode "Disabled"
    #Stop-ServiceAndDependencies -Name "$($appVendor)ARMService"
    #Set-ServiceStartMode -Name "$($appVendor)ARMService" -StartMode "Disabled"
    Stop-ServiceAndDependencies -Name "$($appVendor)GCInvoker-1.0"
    Set-ServiceStartMode -Name "$($appVendor)GCInvoker-1.0" -StartMode "Disabled"
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "AdobeAAMUpdater-1.0" -ContinueOnError $True
    #Remove-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "AdobeGCInvoker-1.0" -ContinueOnError $True
    <# Needed for serial number install only
    Execute-Process -Path ".\adobe_prtk.exe" -Parameters $appParameters #logs located in %temp%\AdobeSerialization.log, and %temp%\oobelib.log
    Execute-Process -Path "$appDestination\Acrobat.exe" -WindowStyle Minimized -NoWait
    Start-Sleep -s 70
    Get-Process -Name $appProcess | Stop-Process -Force
    Write-Verbose -Message "$appVendor $appName $appVersion was successfully installed!" -Verbose
    Write-Log -Message "$appName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
    #>
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