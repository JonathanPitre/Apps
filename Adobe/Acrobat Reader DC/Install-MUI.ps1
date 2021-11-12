# Standalone application install script for VDI environment - (C)2021 Jonathan Pitre & Owen Reynolds, inspired by xenappblog.com

#Requires -Version 5.1
#Requires -RunAsAdministrator

# Custom package providers list
$PackageProviders = @("Nuget")

# Custom modules list
$Modules = @("PSADT", "Nevergreen")

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
$appVendor = "Adobe"
$appName = "Acrobat Reader"
$appName2 = "Reader"
$appShortVersion = "DC"
$appLanguage = "Multi"
$appArchitecture ="x86"
$appProcesses = @("AcroRd32", "AdobeCollabSync", "ReaderCEF", "reader_sl")
$appTransformURL = "https://github.com/JonathanPitre/Apps/raw/master/Adobe/Acrobat%20Reader%20DC/AcroRead.mst"
$appTransform = Split-Path -Path $appTransformURL -Leaf
$appInstallParameters = "/QB"
$appAddParameters = "EULA_ACCEPT=YES DISABLE_CACHE=1 DISABLE_PDFMAKER=YES DISABLEDESKTOPSHORTCUT=0 UPDATE_MODE=0 DISABLE_ARM_SERVICE_INSTALL=1"
$appAddParameters2 = "ALLUSERS=1"
$Nevergreen = Get-NevergreenApp -Name AdobeAcrobatReader| Where-Object { $_.Language -eq $appLanguage -and $_.Architecture -eq $appArchitecture }
$appVersion = $Nevergreen.Version
$appSetupURL = "https://ardownload2.adobe.com/pub/adobe/reader/win/AcrobatDC/1500720033/AcroRdrDC1500720033_MUI.exe"
$appSetup = Split-Path -Path $appSetupURL -Leaf
$appMsiSetup = "AcroRead.msi"
$appPatchURL = $Nevergreen.URI
$appPatch = Split-Path -Path $appPatchURL -Leaf
$appFontURL = "https://ardownload2.adobe.com/pub/adobe/reader/win/AcrobatDC/misc/FontPack2100120135_XtdAlf_Lang_DC.msi"
$appFont = Split-Path -Path $appFontURL -Leaf
$appDicURL = "https://ardownload2.adobe.com/pub/adobe/reader/win/AcrobatDC/misc/AcroRdrSD1900820071_all_DC.msi"
$appDic = Split-Path -Path $appDicURL -Leaf
$appADMXurl = "https://ardownload2.adobe.com/pub/adobe/reader/win/AcrobatDC/misc/ReaderADMTemplate.zip"
$appADMX = Split-Path -Path $appADMXurl -Leaf
$appDestination = "${env:ProgramFiles(x86)}\$appVendor\$appName $appShortVersion\$appName2"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName.* $appShortVersion .*" -RegEx)
$appInstalledVersion = (Get-InstalledApplication -Name "$appVendor $appName $appShortVersion MUI" -Exact).DisplayVersion
##*===============================================

If ([version]$appVersion -gt [version]$appInstalledVersion)
{
    Set-Location -Path $appScriptDirectory

    # Download latest setup file(s)
    If (-Not(Test-Path -Path $appScriptDirectory\$appMsiSetup))
    {
        Write-Log -Message "Downloading $appVendor $appName $appShortVersion $appLanguage $appArchitecture $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appSetupURL -OutFile $appSetup
        Write-Log -Message "Extracting $appVendor $appName $appShortVersion $appLanguage $appArchitecture $appVersion MSI..." -Severity 1 -LogType CMTrace -WriteHost $True
        New-Folder -Path "$appScriptDirectory\MSI"
        # Extract MSI
        Execute-Process -Path .\$appSetup -Parameters "-sfx_o`"$appScriptDirectory\MSI`" -sfx_ne"
        Copy-File -Path "$appScriptDirectory\MSI\*" -Destination $appScriptDirectory -Recurse
        Remove-Folder -Path "$appScriptDirectory\MSI"
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
        Write-Log -Message "Installing $appVendor $appName $appShortVersion $appLanguage $appArchitecture $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
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

    # Install Extended Asian Language Font Pack
    If (-Not(Test-Path -Path $appScriptDirectory\$appFont))
    {
        Write-Log -Message "Downloading $appVendor $appName $appShortVersion Extended Asian Language Font Pack..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appFontURL -OutFile $appFont
        Write-Log -Message "Installing $appVendor $appName $appShortVersion Extended Asian Language Font Pack..." -Severity 1 -LogType CMTrace -WriteHost $True
        Execute-MSI -Action Install -Path $appFont -Parameters $appInstallParameters -AddParameters $appAddParameters2
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
        Write-Log -Message "Installing $appVendor $appName $appShortVersion Extended Asian Language Font Pack..." -Severity 1 -LogType CMTrace -WriteHost $True
        Execute-MSI -Action Install -Path $appFont -Parameters $appInstallParameters -AddParameters $appAddParameters2
    }

    # Install Spelling Dictionaries
    If (-Not(Test-Path -Path $appScriptDirectory\$appDIC))
    {
        Write-Log -Message "Downloading $appVendor $appName $appShortVersion Spelling Dictionaries..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appDicURL -OutFile $appDic
        Write-Log -Message "Installing $appVendor $appName $appShortVersion Spelling Dictionaries..." -Severity 1 -LogType CMTrace -WriteHost $True
        Execute-MSI -Action Install -Path $appDic -Parameters $appInstallParameters -AddParameters $appAddParameters2
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
        Write-Log -Message "Installing $appVendor $appName $appShortVersion Spelling Dictionaries..." -Severity 1 -LogType CMTrace -WriteHost $True
        Execute-MSI -Action Install -Path $appDic -Parameters $appInstallParameters -AddParameters $appAddParameters2
    }

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

    # Stop and disable unneeded scheduled tasks
    Get-ScheduledTask -TaskName "$appVendor Acrobat Update Task" | Stop-ScheduledTask
    Get-ScheduledTask -TaskName "$appVendor Acrobat Update Task" | Disable-ScheduledTask

    # Fix application Start Menu shorcut
    Copy-File -Path "$envCommonStartMenuPrograms\$appName $appShortVersion.lnk" -Destination "$envCommonStartMenuPrograms\$appVendor $appName $appShortVersion.lnk" -ContinueFileCopyOnError $True
    Remove-File -Path "$envCommonStartMenuPrograms\$appName $appShortVersion.lnk" -ContinueOnError

    # Remove Active Setup
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components\{A6EADE66-0000-0000-484E-7E8A45000000}" -Name "StubPath"

    # Go back to the parent folder
    Set-Location ..

    Write-Log -Message "$appVendor $appName $appShortVersion $appLanguage $appArchitecture $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
}
Else
{
    Write-Log -Message "$appVendor $appName $appShortVersion $appArchitecture $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}