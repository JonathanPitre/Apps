# Standalone application install script for VDI environment - (C)2021 Jonathan Pitre & Owen Reynolds, inspired by xenappblog.com

#Requires -Version 5.1
#Requires -RunAsAdministrator

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"
$env:SEE_MASK_NOZONECHECKS = 1
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

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$appName = "ShareX"
$appProcesses = @("$appName")
$appInstallParameters = "/VERYSILENT /NORESTART /NORUN /MERGETASKS=!createdesktopicon"
#Tasks=createsendtoicon,createstartupicon
$appConfigURL = "https://raw.githubusercontent.com/JonathanPitre/Apps/master/$appName/ApplicationConfig.json"
$appConfigHotkeysURL = "https://raw.githubusercontent.com/JonathanPitre/Apps/master/$appName/HotkeysConfig.json"
$appConfig = Split-Path -Path $appConfigURL -Leaf
$appConfigHotkeys = Split-Path -Path $appConfigHotkeysURL -Leaf
$Evergreen = Get-EvergreenApp -Name $appName | Where-Object { $_.Type -eq "exe" }
$appVersion = $Evergreen.Version
$appURL = $Evergreen.URI
$appSetup = Split-Path -Path $appURL -Leaf
$appDestination = "$env:ProgramFiles\$appName"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appName")
$appInstalledVersion = (Get-InstalledApplication -Name "$appName").DisplayVersion

#-----------------------------------------------------------[Execution]------------------------------------------------------------


If ([version]$appVersion -gt [version]$appInstalledVersion)
{
	Set-Location -Path $appScriptDirectory
	If (-Not(Test-Path -Path $appVersion)) {New-Folder -Path $appVersion}
	Set-Location -Path $appVersion

	# Download latest setup file(s)
	If (-Not(Test-Path -Path $appScriptDirectory\$appVersion\$appSetup))
 {
		Write-Log -Message "Downloading $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
		Invoke-WebRequest -UseBasicParsing -Uri $appURL -OutFile $appSetup
	}
	Else
 {
		Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
	}

	# Uninstall previous versions
	Get-Process -Name $appProcesses | Stop-Process -Force
	If ($IsAppInstalled)
 {
		Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
		Execute-Process -Path "$appDestination\unins000.exe" -Parameters "/VERYSILENT /NORESTART"
	}

	# Download required config file
	If (-Not(Test-Path -Path $appScriptDirectory\$appConfig))
 {
		Write-Log -Message "Downloading $appName config file..." -Severity 1 -LogType CMTrace -WriteHost $True
		Invoke-WebRequest -UseBasicParsing -Uri $appConfigURL -OutFile $appScriptDirectory\$appConfig
	}
	Else
 {
		Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
	}
	If (-Not(Test-Path -Path $appScriptDirectory\$appConfigHotkeys))
 {
		Write-Log -Message "Downloading $appName config file..." -Severity 1 -LogType CMTrace -WriteHost $True
		Invoke-WebRequest -UseBasicParsing -Uri $appConfigHotkeysURL -OutFile $appScriptDirectory\$appConfigHotkeys
	}
	Else
 {
		Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
	}

	# Install latest version
	Write-Log -Message "Installing $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
	Execute-Process -Path .\$appSetup -Parameters $appInstallParameters

	Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

	Write-Log -Message "Applying $appName settings to the Default User profile." -Severity 1 -LogType CMTrace -WriteHost $True
	# Copy config file to the default profile
	New-Item -Path "$appDestination" -Name "PersonalPath.cfg" -ItemType File -Value "%ApplicationData%\$appName" -Force
	New-Folder -Path "$envSystemDrive\Users\Default\AppData\Roaming\$appName"
	New-Folder -Path "$envSystemDrive\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
	New-Shortcut -Path "$envSystemDrive\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\$appName.lnk" -TargetPath "$appDestination\$appName.exe" -Arguments "-silent" -WorkingDirectory "$appDestination"
	Copy-File -Path "$appScriptDirectory\$appConfig" -Destination "$envSystemDrive\Users\Default\AppData\Roaming\$appName" -ContinueOnError $True
	Copy-File -Path "$appScriptDirectory\$appConfigHotkeys" -Destination "$envSystemDrive\Users\Default\AppData\Roaming\$appName" -ContinueOnError $True

	# Disable automatic updates check - https://getsharex.com/changelog
	Set-RegistryKey -Key "HKLM:\SOFTWARE\$appName" -Name "DisableUpdateCheck" -Type "DWord" -Value "1"
	# Disable automatic upload - https://getsharex.com/changelog
	Set-RegistryKey -Key "HKLM:\SOFTWARE\$appName" -Name "DisableUpload" -Type "DWord" -Value "1"

	# Set ShareX screenshots path to OneDrive if OneDrive is installed
	#If (Test-Path -Path "$envProgramFiles\Microsoft OneDrive\OneDrive.exe") {
	#    Set-RegistryKey -Key "HKLM:\SOFTWARE\$appName" -Name "PersonalPath" -Type "String" -Value "%OneDriveCommercial%\Documents\ShareX"
	#}

	# Configure application shortcut
	Copy-File -Path $envCommonStartMenuPrograms\$appName\$appName.lnk -Destination $envCommonStartMenuPrograms -ContinueOnError $True
	Remove-Folder -Path $envCommonStartMenuPrograms\$appName -ContinueOnError $True

	# Go back to the parent folder
	Set-Location ..

	Write-Log -Message "$appName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
}
Else
{
	Write-Log -Message "$appName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}