# PowerShell Wrapper for MDT, Standalone and Chocolatey Installation - (C)2020 Jonathan Pitre, inspired by xenappblog.com
# Example 1 Install EXE:
# Execute-Process -Path .\appName.exe -Parameters "/silent"
# Example 2 Install MSI:
# Execute-MSI -Action Install -Path appName.msi -Parameters "/QB" -AddParameters "ALLUSERS=1"
# Example 3 Uninstall MSI:
# Remove-MSIApplications -Name "appName" -Parameters "/QB"
# Custom package providers list
$PackageProviders = @("PowerShellGet","Nuget")
# Custom modules list
$Modules = @("PSADT","Evergreen")

# Checking for elevated permissions...
If (-not([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
	Write-Warning -Message "Insufficient permissions to continue! PowerShell must be run with admin rights."
	Break
}
Else {
	Write-Verbose -Message "Importing custom modules..." -Verbose

	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    [System.Net.WebRequest]::DefaultWebProxy.Credentials =  [System.Net.CredentialCache]::DefaultCredentials
	Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted

	# Install custom package providers list
	Foreach ($PackageProvider in $PackageProviders) {
		If (-not(Get-PackageProvider -Name $PackageProvider)) {Find-PackageProvider -Name $PackageProvider -ForceBootstrap -IncludeDependencies | Install-PackageProvider -Force -Confirm:$False}
    }

	# Install and import custom modules list
	Foreach ($Module in $Modules) {
		If (-not(Get-Module -ListAvailable -Name $Module)) {Install-Module -Name $Module -AllowClobber -Force | Import-Module -Name $Module}
        Else {Update-Module -Name $Module -Force}
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
$appVendor = "Microsoft"
$appName = "Edge"
$appLongName = "Edge Enterprise"
$appSetup = "MicrosoftEdgeEnterpriseX64.msi"
$appProcess = @("msedge", "MicrosoftEdgeUpdate")
$appInstallParameters = "/QB"
$Evergreen = Get-MicrosoftEdge | Where-Object { $_.Architecture -eq "x64" -and $_.Channel -eq "Stable" -and $_.Platform -eq "Windows" }
$appVersion = $Evergreen.Version
$appURL = $Evergreen.uri
$appSource = $appVersion
$appDestination = "$envProgramFilesX86\$appVendor\$appName\Application"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName" -Exact)
$appInstalledVersion = (Get-InstalledApplication -Name "$appVendor $appName" -Exact).DisplayVersion | Select-Object -First 1
##*===============================================

If ([version]$appVersion -gt [version]$appInstalledVersion) {
    Set-Location -Path $appScriptDirectory
    If (-Not(Test-Path -Path $appSource)) {New-Folder -Path $appSource}
    Set-Location -Path $appSource

    Write-Log -Message "Downloading $appVendor $appLongName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    If (-Not(Test-Path -Path $appScriptDirectory\$appSource\$appSetup)) {
        Invoke-WebRequest -UseBasicParsing -Uri $appURL -OutFile $appSetup
    }
    Else {
        Write-Log -Message "File already exists. Skipping Download" -Severity 1 -LogType CMTrace -WriteHost $True
    }

    Get-Process -Name $appProcess | Stop-Process -Force
    # Delete machine policies to prevent issue during installation
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\Policies\$appVendor\Update" -Recurse -ContinueOnError $True
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\Policies\$appVendor\$appName" -Recurse -ContinueOnError $True
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Policies\$appVendor\Temp" -Recurse -ContinueOnError $True
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Policies\$appVendor\Update" -Recurse -ContinueOnError $True
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Policies\$appVendor\$appName" -Recurse -ContinueOnError $True

    If ($IsAppInstalled) {
        Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
        Remove-MSIApplications -Name $appName -Parameters $appInstallParameters
        Remove-MSIApplications -Name $($appName)Update -Parameters $appInstallParameters
    }
    If (Test-Path -Path "$envProgramFilesX86\$($appName)Update") {
        Write-Log -Message "Removing previous $appVendor $appLongName folder to fix issues with new installation." -Severity 1 -LogType CMTrace -WriteHost $True
        Set-Location -Path "$envProgramFilesX86\$appVendor\$($appName)Update"
        Execute-Process -Path ".\$appVendor$($appName)Update.exe" -Parameters "-uninstall" -IgnoreExitCodes 1606220281 -ContinueOnError $True
    }

    Remove-Folder -Path "$envProgramFilesX86\$appVendor\$appName" -ContinueOnError $True
    Remove-Folder -Path "$envProgramFilesX86\$appVendor\$($appName)Update" -ContinueOnError $True
    Remove-Folder -Path "$envProgramFilesX86\$appVendor\Temp" -ContinueOnError $True

    Write-Log -Message "Installing $appVendor $appLongName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    Execute-MSI -Action Install -Path $appSetup -Parameters $appInstallParameters

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True
    Copy-File -Path "$appScriptDirectory\master_preferences" -Destination $appDestination
    Get-ScheduledTask -TaskName "$appVendor$appName*" | Stop-ScheduledTask
    Get-ScheduledTask -TaskName "$appVendor$appName*" | Disable-ScheduledTask
    Stop-ServiceAndDependencies -Name "$($appName)update"
    Set-ServiceStartMode -Name "$($appName)update" -StartMode "Disabled"
    Stop-ServiceAndDependencies -Name "$($appName)updatem"
    Set-ServiceStartMode -Name "$($appName)updatem" -StartMode "Disabled"
    # Creates a pinned taskbar icons for all users
    New-Shortcut -Path "$envSystemDrive\Users\Default\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\Taskbar\$appVendor $appName.lnk" -TargetPath "$appDestination\$($appProcess[0]).exe"  -IconLocation "$appDestination\$($appProcess[0]).exe" -Description "$appVendor $appName" -WorkingDirectory "$appDestination"
    # Remove Active Setup
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{9459C573-B17A-45AE-9F64-1857B5D58CEE}" -Name "StubPath"
    #Remove-File "$envCommonDesktop\$appVendor $appName.lnk" -ContinueOnError $True
    Update-GroupPolicy

    Write-Log -Message "$appVendor $appLongName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True

}
Else {
    Write-Log -Message "$appVendor $appLongName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}

<#
Write-Verbose -Message "Uninstalling custom modules..." -Verbose
Foreach ($Module in $Modules) {
    If ((Get-Module -ListAvailable -Name $Module)) {Uninstall-Module -Name $Module -Force}
}
Write-Verbose -Message "Custom modules were succesfully uninstalled!" -Verbose
#>