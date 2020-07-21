# PowerShell Wrapper for MDT, Standalone and Chocolatey Installation - (C)2020 Jonathan Pitre, inspired by xenappblog.com 
# Example 1 Install EXE:
# Execute-Process -Path .\appName.exe -Parameters "/silent"
# Example 2 Install MSI:
# Execute-MSI -Action Install -Path appName.msi -Parameters "/QB" -AddParameters "ALLUSERS=1"
# Example 3 Uninstall MSI:
# Remove-MSIApplications -Name "appName" -Parameters "/QB"

Clear-Host
Set-ExecutionPolicy -ExecutionPolicy Bypass -Force -Scope Process

# Custom package providers list
$PackageProviders = @("PowerShellGet","Nuget")
# Custom modules list
$Modules = @("Evergreen","InstallModuleFromGitHub")

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
		If (-not(Get-Module -ListAvailable -Name $Module)) {Install-Module -Name $Module -Force | Import-Module -Name $Module}
        Else {Update-Module -Name $Module -Force}
    }

    # Install custom PSAppDeployToolkit module from a GitHub repo
	$GitHubUser = "JonathanPitre"
	$GitHubRepo = "PSAppDeployToolkit"
	If (-not(Test-Path -Path $env:ProgramFiles\WindowsPowerShell\Modules\$GitHubRepo)) {Install-ModuleFromGitHub -GitHubRepo $GitHubUser/$GitHubRepo | Import-Module -Name $GitHubRepo}
	Else {Import-Module -Name $env:ProgramFiles\WindowsPowerShell\Modules\$GitHubRepo}
    
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
$appVendor = "Druide"
$appName = "Antidote"
$appShortVersion = "10"
$appVersion = Get-ChildItem $appScriptDirectory | Where-Object { $_.PSIsContainer } | Sort-Object CreationTime -Descending | Select-Object -First 1 | Select-Object -ExpandProperty Name
$appSource = $appVersion
$appSetup = "Antidote10.msi"
$appSetup2 = "Antidote10-Module-francais.msi"
$appSetup3 = "Antidote10-English-module.msi"
$appSetup4 = "Antidote-Connectix10.msi"
$appTransform = "ReseauAntidote.mst"
$appTransform2 = "ReseauConnectix.mst"
$appPatch = "Diff_Antidote_10_C_10.4.msp"
$appPatch2 = "Diff_Antidote_10_Module_F_10.4.msp"
$appPatch3 = "Diff_Antidote_10_Module_E_10.4.msp"
$appPatch4 = "Diff_Connectix_10_C_10.4.msp"
$appInstallParameters = "/QB"
$appProcess = @("Antidote", "AgentAntidote", "Connectix", "AgentConnectix", "OUTLOOK", "WINWORD", "EXCEL", "POWERPNT")
$appDestination = "$envProgramFilesX86\$appVendor\$appName $appShortVersion\Application\Bin64"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appName \d{2}" -RegEx) | Select-Object -First 1
$appInstalledVersion = (Get-InstalledApplication -Name "$appName \d{2}" -RegEx).DisplayVersion | Select-Object -First 1
##*===============================================

If ([version]$appVersion -gt [version]$appInstalledVersion) {

    Set-Location -Path $appScriptDirectory

    If (-Not(Test-Path -Path $appScriptDirectory\$appSource\$appSetup)) {
        Write-Log -Message "Setup files are missing.Please download and try again." -Severity 1 -LogType CMTrace -WriteHost $True
        Break
    }
    Else {
	    Write-Log -Message "File already exists. Skipping Download" -Severity 1 -LogType CMTrace -WriteHost $True
        Set-Location -Path $appSource
    }

    Get-Process -Name $appProcess | Stop-Process -Force
    If ($IsAppInstalled) {
        Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
        Remove-MSIApplications -Name $appName -Parameters $appInstallParameters
    }

    Write-Log -Message "Installing $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    Execute-MSI -Action Install -Path $appSetup -Parameters $appInstallParameters -Transform $appTransform -SkipMSIAlreadyInstalledCheck #-Patch $appPatch 
    Execute-MSI -Action Install -Path $appSetup2 -Parameters $appInstallParameters -SkipMSIAlreadyInstalledCheck #-Patch $appPatch2
    If (Test-Path -Path $appSetup3) {Execute-MSI -Action Install -Path $appSetup3 -Parameters $appInstallParameters -SkipMSIAlreadyInstalledCheck} #-Patch $appPatch3 
    Execute-MSI -Action Install -Path $appSetup4 -Parameters $appInstallParameters -Transform $appTransform2 -SkipMSIAlreadyInstalledCheck #-Patch $appPatch4 

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

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

If ((Test-Path -Path $env:ProgramFiles\WindowsPowerShell\Modules\$GitHubRepo)) {
Remove-Module -Name $GitHubRepo -Force
#Remove-Item -Path $env:ProgramFiles\WindowsPowerShell\Modules\$GitHubRepo -Recurse -Force
}

Write-Verbose -Message "Custom modules were succesfully uninstalled!" -Verbose
#>