# Standalone application install script for VDI environment - (C)2021 Jonathan Pitre & Owen Reynolds, inspired by xenappblog.com

#Requires -Version 5.1
#Requires -RunAsAdministrator

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"
$env:SEE_MASK_NOZONECHECKS = 1
$Modules = @("PSADT") # Modules list

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

Function Install-WinGet
{
	[CmdletBinding()]
	# Install latest WinGet
	$MSDesktopAppInstaller = Get-AppPackage -Name 'Microsoft.DesktopAppInstaller'
	If (-Not $MSDesktopAppInstaller -or [version]$MSDesktopAppInstaller.Version -lt [version]"1.1.12653")
 {
		Write-Host -Object "Installing WinGet Dependencies..." -ForegroundColor Green
		Add-AppxPackage -Path 'https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx'
		$releases_url = 'https://api.github.com/repos/microsoft/winget-cli/releases/latest'
		$releases = Invoke-RestMethod -uri $releases_url
		$latestRelease = $releases.assets | Where-Object { $_.browser_download_url.EndsWith('msixbundle') } | Select-Object -First 1
		Write-Host -Object "Installing WinGet from $($latestRelease.browser_download_url)..." -ForegroundColor Green
		Add-AppxPackage -Path $latestRelease.browser_download_url
	}
	Else
 {
		Write-Host -Object "WinGet is already installed!" -ForegroundColor Green
	}

	# Configure WinGet

	# WinGet config path from: https://github.com/microsoft/winget-cli/blob/master/doc/Settings.md#file-location
	$settingsPath = "$env:LOCALAPPDATA\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalState\settings.json";
	$settingsJson =
@"
// For documentation on these settings, see: https://aka.ms/winget-settings
{
	"visual": {
		"progressBar": "rainbow"
	},
	"experimentalFeatures": {
		"experimentalMSStore": true,
		"list": true,
		"upgrade": true,
		"uninstall": true
	}
}
"@;
	$settingsJson | Out-File $settingsPath -Encoding utf8

    # Removing MSStore from WinGet due to EULA
    #winget source reset msstore
    winget source remove msstore
    winget source add --name winget --arg https://winget.azureedge.net/cache --type Microsoft.PreIndexed.Package
    Write-Host -Object "WinGet was configured!" -ForegroundColor Green
}

#----------------------------------------------------------[Declarations]----------------------------------------------------------

Install-WinGet
$appVendor = "Google"
$appName = "Earth Pro"
$appProcesses = @("googleearthpro")
$appInstallParameters = "OMAHA=1"
$WinGet = winget show Google.EarthPro
$appVersion = ($WinGet | Select-String -Pattern "Version: ((?:\d+\.)+\d+)").Matches.Groups[1].Value
$appURL = ($WinGet | Select-String -Pattern "Download Url: ((http|https)://.+)").Matches.Groups[1].Value
$appSetup = Split-Path -Path $appURL -Leaf
$appDestination = "$env:ProgramFiles\Google Earth Pro"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName")
$appInstalledVersion = (Get-InstalledApplication -Name "$appVendor $appName").DisplayVersion

#-----------------------------------------------------------[Execution]------------------------------------------------------------

If ([version]$appVersion -gt [version]$appInstalledVersion)
{
	Set-Location -Path $appScriptDirectory
	If (-Not(Test-Path -Path $appVersion)) { New-Folder -Path $appVersion }
	Set-Location -Path $appVersion

    # Download latest setup file(s)
	<#If (-Not(Test-Path -Path $appScriptDirectory\$appVersion\$appSetup))
    {
		Write-Log -Message "Downloading $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
		Invoke-WebRequest -UseBasicParsing -Uri $appURL -OutFile $appSetup
	}
	Else
    {
		Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
	}
    #>

    # Uninstall previous versions
	Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
	Get-Process -Name $appProcesses | Stop-Process -Force
    If ($IsAppInstalled)
    {
        Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
        Remove-MSIApplications -Name $appVendor $appName -Parameters "/QB"
    }

    # Install latest version
	Write-Log -Message "Installing $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
	#Execute-Process -Path ".\$appSetup" -Parameters $appInstallParameters
    winget install Google.EarthPro

	Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

    # Load the Default User registry hive
    Execute-Process -Path "$envWinDir\System32\reg.exe" -Parameters "LOAD HKLM\DefaultUser $envSystemDrive\Users\Default\NTUSER.DAT" -WindowStyle Hidden

    # Removes software notificationg
    Set-RegistryKey -Key "HKLM:\DefaultUser\Software\$appVendor\$appVendor $appName" -Name "enableTips" -Value "false" -Type String
    Set-RegistryKey -Key "HKLM:\DefaultUser\Software\$appVendor\$appVendor $appName" -Name "tooltips" -Value "false" -Type String


    # Unload the Default User registry hive
    Start-Sleep -Seconds 3
    Execute-Process -Path "$envWinDir\System32\reg.exe" -Parameters "UNLOAD HKLM\DefaultUser" -WindowStyle Hidden

    # Cleanup temp files
    Remove-Item -Path "$envSystemDrive\Users\Default\*.LOG1" -Force
    Remove-Item -Path "$envSystemDrive\Users\Default\*.LOG2" -Force
    Remove-Item -Path "$envSystemDrive\Users\Default\*.blf" -Force
    Remove-Item -Path "$envSystemDrive\Users\Default\*.regtrans-ms" -Force

    # Configure application shortcut
    Remove-File -Path "$envCommonDesktop\$appVendor $appName.lnk" -ContinueOnError $True

	# Go back to the parent folder
	Set-Location ..

	Write-Log -Message "$appVendor $appName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
}
Else
{
	Write-Log -Message "$appVendor $appName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}