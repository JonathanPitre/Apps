# Standalone application install script for VDI environment - (C)2023 Jonathan Pitre

#Requires -Version 5.1
#Requires -RunAsAdministrator

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

#region Initialisations
$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"
# Set the script execution policy for this process
Try { Set-ExecutionPolicy -ExecutionPolicy 'ByPass' -Scope 'Process' -Force } Catch {}
# Unblock ps1 script
Get-ChildItem -Recurse *.ps*1 | Unblock-File
$env:SEE_MASK_NOZONECHECKS = 1
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
$Modules = @("PSADT", "VcRedist") # Modules list

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
$appScriptPath = Get-ScriptDirectory

# Install and import modules list
Foreach ($Module in $Modules)
{
	Initialize-Module -Module $Module
}

#-----------------------------------------------------------[Functions]------------------------------------------------------------

#region Functions
#endregion

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$appVendor = "Microsoft"
$appName = "Visual C++"
$appMajorVersion = ( Get-VcList | Select-Object -Last 1).Release
$VcList = Get-VcList
$VcListVersion = ($VcList | Where-Object {$_.Release -eq $appMajorVersion -and $_.Architecture -eq "x64" }).Version
$appVersion = $VcListVersion.Substring(0, $VcListVersion.Length - 2)
$appSetup = Split-Path -Path ($VcList).Download -Leaf
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName $appMajorVersion")
$appInstalledVersion = (Get-InstalledApplication -Name "$appVendor $appName $appMajorVersion").DisplayVersion | Select-Object -First 1

#-----------------------------------------------------------[Execution]------------------------------------------------------------

If ([version]$appVersion -gt [version]$appInstalledVersion)
{
	Set-Location -Path $appScriptPath

	# Uninstall previous versions
	Remove-MSIApplications -Name "$appVendor $appName" -ContinueOnError $True

	# Download latest setup file(s)
	If (-Not(Test-Path -Path $appScriptPath\$appMajorVersion\x64\RTM\$appSetup))
 {
		Write-Log -Message "Downloading $appVendor $appName Runtimes..." -Severity 1 -LogType CMTrace -WriteHost $True
		Save-VcRedist -VcList $VcList -Path $appScriptPath
	}
	Else
 {
		Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
	}

	# Install latest version
	Write-Log -Message "Installing $appVendor $appName Runtimes..." -Severity 1 -LogType CMTrace -WriteHost $True
	Install-VcRedist -Path $appScriptPath -VcList $VcList

	Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

	# Go back to the parent folder
	Set-Location ..

	Write-Log -Message "$appVendor $appName Runtimes were installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
}
Else
{
	Write-Log -Message "$appVendor $appName $appMajorVersion $appInstalledVersion Runtimes are already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}