# Standalone application install script for VDI environment - (C)2021 Jonathan Pitre & Owen Reynolds, inspired by xenappblog.com

#Requires -Version 5.1
#Requires -RunAsAdministrator

# Custom package providers list
$PackageProviders = @("Nuget")

# Custom modules list
$Modules = @("PSADT")

Write-Verbose -Message "Importing custom modules..." -Verbose

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials

# Install custom package providers list
Foreach ($PackageProvider in $PackageProviders)
{
	If (-not(Get-PackageProvider -ListAvailable -Name $PackageProvider -ErrorAction SilentlyContinue)) { Install-PackageProvider -Name $PackageProvider -Force }
}

# Add the Powershell Gallery as trusted repository
Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted

# Update PowerShellGet
$InstalledPSGetVersion = (Get-PackageProvider -Name PowerShellGet).Version
$PSGetVersion = [version](Find-PackageProvider -Name PowerShellGet).Version
If ($PSGetVersion -gt $InstalledPSGetVersion) { Install-PackageProvider -Name PowerShellGet -Force }

# Install and import custom modules list
Foreach ($Module in $Modules)
{
	If (-not(Get-Module -ListAvailable -Name $Module)) { Install-Module -Name $Module -AllowClobber -Force | Import-Module -Name $Module -Force }
	Else
 {
		$InstalledModuleVersion = (Get-InstalledModule -Name $Module).Version
		$ModuleVersion = (Find-Module -Name $Module).Version
		$ModulePath = (Get-InstalledModule -Name $Module).InstalledLocation
		$ModulePath = (Get-Item -Path $ModulePath).Parent.FullName
		If ([version]$ModuleVersion -gt [version]$InstalledModuleVersion)
		{
			Update-Module -Name $Module -Force
			Remove-Item -Path $ModulePath\$InstalledModuleVersion -Force -Recurse
		}
	}
}

Write-Verbose -Message "Custom modules were successfully imported!" -Verbose

# Get the current script directory
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
			Write-Host -ForegroundColor Red "Cannot resolve script file's path"
			Exit 1
		}
	}
	Catch
 {
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
$appVendor = "Citrix"
$appName2 = "XenApp and XenDesktop"
$appName = "Remote PowerShell SDK"
$appInstallParameters = "/q"
$appURL = "https://download.apps.cloud.com/CitrixPoshSdk.exe"
$appSetup = Split-Path -Path $appURL -Leaf
$appDestination = "$env:ProgramFiles\Citrix\Sdkproxy\Snapin\v1"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appName2 $appName")
$appInstalledVersion = ((Get-InstalledApplication -Name "$appName2 $appName").DisplayVersion)
##*===============================================

Set-Location -Path $appScriptDirectory

# Download latest setup file(s)
Write-Log -Message "Downloading latest $appVendor $appName2 $appName..." -Severity 1 -LogType CMTrace -WriteHost $True
Invoke-WebRequest -UseBasicParsing -Uri $appURL -OutFile $appSetup

$appVersion = (Get-FileVersion $appScriptDirectory\$appSetup)

If (-Not(Test-Path -Path $appVersion))
{
	New-Folder -Path $appVersion
	Move-Item -Path $appSetup -Destination $appScriptDirectory\$appVersion -Force
}
Set-Location -Path $appVersion

If ([version]$appVersion -gt [version]$appInstalledVersion)
{
    # Install latest version
    Write-Log -Message "Installing $appVendor $appName2 $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    Execute-Process -Path ".\$appSetup" -Parameters $appInstallParameters

	Write-Log -Message "$appVendor $appName2 $appName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True

	# Go back to the parent folder
	Set-Location ..
}
Else
{
	Write-Log -Message "$appVendor $appName2 $appName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}