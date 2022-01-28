# Standalone application install script for VDI environment - (C)2021 Jonathan Pitre & Owen Reynolds, inspired by xenappblog.com

#Requires -Version 5.1
#Requires -RunAsAdministrator

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"
$env:SEE_MASK_NOZONECHECKS = 1
$Modules = @("PSADT", "Nevergreen") # Modules list

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

$appVendor = "Adobe"
$appName = "Acrobat"
$appShortVersion = "DC"
$appArchitecture = "x64"
$appProcesses = @("Acrobat", "AdobeCollabSync", "AcroCEF", "acrobat_sl", "acrodist", "AcroServicesUpdater", "acrotray", "AGSService", "outlook", "chrome", "iexplore")
$appServices = @("AdobeUpdateService")
$appTransformURL = "https://github.com/JonathanPitre/Apps/raw/master/Adobe/Acrobat DC/AcroProx64.mst"
$appTransform = Split-Path -Path $appTransformURL -Leaf
$appInstallParameters = "/QB"
$appAddParameters = "IGNOREVCRT64=1 EULA_ACCEPT=YES UPDATE_MODE=0 DISABLE_ARM_SERVICE_INSTALL=1 ROAMIDENTITY=1 ROAMLICENSING=1"
$Nevergreen = Get-NevergreenApp -Name AdobeAcrobat | Where-Object {$_.Architecture -eq $appArchitecture}
$appVersion = $Nevergreen.Version
$appSetupURL = "https://trials.adobe.com/AdobeProducts/APRO/Acrobat_HelpX/win32/Acrobat_DC_Web_x64_WWMUI.zip"
$appSetup = Split-Path -Path $appSetupURL -Leaf
$appMsiSetup = "AcroPro.msi"
$appPatchURL = $Nevergreen.URI
$appPatch = Split-Path -Path $appPatchURL -Leaf
$appADMXurl = "https://ardownload2.adobe.com/pub/adobe/acrobat/win/AcrobatDC/misc/AcrobatADMTemplate.zip"
$appADMX = Split-Path -Path $appADMXurl -Leaf
$appCustWizURL = "https://ardownload2.adobe.com/pub/adobe/acrobat/win/AcrobatDC/misc/CustWiz2100720091_en_US_DC.exe"
$appCustWiz = Split-Path -Path $appCustWizURL -Leaf
$appCustWizVersion = $appCustWiz.Trim("CustWiz").Trim("_en_US_DC.exe")
$appDestination = "$env:ProgramFiles\$appVendor\$appName $appShortVersion\$appName"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName.* $appShortVersion .*" -RegEx)
$appInstalledVersion = (Get-InstalledApplication -Name "$appVendor $appName $appShortVersion (64-bit)" -Exact).DisplayVersion

#-----------------------------------------------------------[Execution]------------------------------------------------------------


If ([version]$appVersion -gt [version]$appInstalledVersion)
{
	Set-Location -Path $appScriptDirectory

	# Download latest setup file(s)
	If (-Not(Test-Path -Path $appScriptDirectory\$appMsiSetup))
 {
		Write-Log -Message "Downloading $appVendor $appName $appShortVersion $appArchitecture $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
		Invoke-WebRequest -UseBasicParsing -Uri $appSetupURL -OutFile $appSetup
		Write-Log -Message "Extracting $appVendor $appName $appShortVersion $appArchitecture $appVersion ZIP..." -Severity 1 -LogType CMTrace -WriteHost $True
		# Extract ZIP
		Expand-Archive -Path $appScriptDirectory\$appSetup -DestinationPath $appScriptDirectory -Force
		Copy-File -Path "$appScriptDirectory\$appVendor $appName\*" -Destination $appScriptDirectory -Recurse
		Remove-Folder -Path "$appScriptDirectory\$appVendor $appName"
		Remove-File -Path "$appScriptDirectory\$appSetup"
	}
	Else
 {
		Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
	}

	# Download latest patch
	If (-Not(Test-Path -Path $appScriptDirectory\$appPatch))
 {
		Write-Log -Message "Downloading $appVendor $appName $appShortVersion $appArchitecture $appVersion patch..." -Severity 1 -LogType CMTrace -WriteHost $True
		Invoke-WebRequest -UseBasicParsing -Uri $appPatchURL -OutFile $appPatch
		# Modify setup.ini according to latest patch
		If ((Test-Path -Path $appScriptDirectory\$appPatch) -and (Test-Path -Path $appScriptDirectory\$appPatch\setup.ini))
		{
			Set-IniValue -FilePath $appScriptDirectory\setup.ini -Section "Startup" -Key "CmdLine" -Value "/sPB /rs /msi $appAddParameters"
			Set-IniValue -FilePath $appScriptDirectory\setup.ini -Section "Product" -Key "CmdLine" -Value "TRANSFORMS=`"$appTransform`""
			Set-IniValue -FilePath $appScriptDirectory\setup.ini -Section "Product" -Key "PATCH" -Value $appPatch
		}
	}
	Else
 {
		Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
	}

	# Download latest policy definitions
	Write-Log -Message "Downloading $appVendor $appName $appShortVersion ADMX templates..." -Severity 1 -LogType CMTrace -WriteHost $True
	Invoke-WebRequest -UseBasicParsing -Uri $appADMXurl -OutFile $appADMX
	New-Folder -Path "$appScriptDirectory\PolicyDefinitions"
	Expand-Archive -Path $appADMX -DestinationPath "$appScriptDirectory\PolicyDefinitions" -Force
	Remove-File -Path $appADMX, $appScriptDirectory\PolicyDefinitions\*.adm

	# Download latest Adobe Acrobat Customization Wizard DC
	If (-Not(Test-Path -Path $appScriptDirectory\$appCustWiz))
 {
		Write-Log -Message "Downloading $appVendor $appName Custimization Wizard $appShortVersion $appCustWizVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
		Invoke-WebRequest -UseBasicParsing -Uri $appCustWizURL -OutFile $appCustWiz
	}
	Else
 {
		Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
	}


	# Uninstall previous versions
	Get-Process -Name $appProcesses | Stop-Process -Force
	If (($IsAppInstalled) -and (Test-Path -Path $appScriptDirectory\$appMsiSetup))
 {
		Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
		Remove-MSIApplications -Name "$appVendor $appName* $appShortVersion*" -WildCard -Exact
	}

	If ((Test-Path -Path "$appScriptDirectory\$appMsiSetup") -and (Test-Path -Path $appScriptDirectory\$appPatch))
 {
		# Download required transform file
		If (-Not(Test-Path -Path $appScriptDirectory\$appTransform))
		{
			Write-Log -Message "Downloading $appVendor $appName $appShortVersion $appArchitecture transform..." -Severity 1 -LogType CMTrace -WriteHost $True
			Invoke-WebRequest -UseBasicParsing -Uri $appTransformURL -OutFile $appScriptDirectory\$appTransform
		}
		Else
		{
			Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
		}

		# Install latest version
		Write-Log -Message "Installing $appVendor $appName $appShortVersion $appArchitecture $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
		Execute-MSI -Action Install -Path $appMsiSetup -Transform $appTransform -Parameters $appInstallParameters -AddParameters $appAddParameters -Patch $appPatch -SkipMSIAlreadyInstalledCheck
	}
	ElseIf (($IsAppInstalled) -and (Test-Path -Path $appScriptDirectory\$appPatch))
 {
		# Install latest patch
		Write-Log -Message "Setup file(s) are missing, MSP file(s) will be installed instead." -Severity 2 -LogType CMTrace -WriteHost $True
		Write-Log -Message "Installing $appVendor $appName $appShortVersion $appArchitecture $appVersion patch..." -Severity 1 -LogType CMTrace -WriteHost $True
		Execute-MSP -Path $appPatch
	}
	Else
 {
		Write-Log -Message "Setup file(s) are missing." -Severity 3 -LogType CMTrace -WriteHost $True
		Exit-Script
	}

	Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

	# Stop and disable unneeded scheduled tasks
	Get-ScheduledTask -TaskName "$appVendor $appName Update Task" | Stop-ScheduledTask
	Get-ScheduledTask -TaskName "$appVendor $appName Update Task" | Disable-ScheduledTask

	# Stop and disable unneeded services
	Stop-ServiceAndDependencies -Name $appServices[0] -SkipServiceExistsTest -ContinueOnError $True
	Set-ServiceStartMode -Name $appServices[0] -StartMode "Disabled" -ContinueOnError $True

	# Remove unneeded applications from running at start-up
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Acrobat Assistant 8.0" -ContinueOnError $True
	Remove-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "AdobeAAMUpdater-1.0" -ContinueOnError $True
	#Remove-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "AdobeGCInvoker-1.0" -ContinueOnError $True

	# Remove Active Setup
	Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components\{AC76BA86-0000-0000-7760-7E8A45000000}" -Name "StubPath"

	If (-Not(Get-InstalledApplication -Name "Adobe Creative Cloud"))
 {
		Write-Log -Message "Adobe Creative Cloud must be installed in order for $appVendor $appName $appShortVersion licensing to work!" -Severity 2 -LogType CMTrace -WriteHost $True
	}

	# Go back to the parent folder
	Set-Location ..

	Write-Log -Message "$appVendor $appName $appShortVersion $appArchitecture $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
}
Else
{
	Write-Log -Message "$appVendor $appName $appShortVersion $appArchitecture $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}