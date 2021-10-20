# Standalone application install script for VDI environment - (C)2021 Jonathan Pitre & Owen Reynolds, inspired by xenappblog.com

#Requires -Version 5.1
#Requires -RunAsAdministrator

# Custom package providers list
$PackageProviders = @("Nuget")

# Custom modules list
$Modules = @("PSADT", "Evergreen", "Nevergreen")

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
$appName = "Acrobat"
$appShortVersion = "DC"
$appLanguage = "French"
$appArchitecture ="x64"
$appProcesses = @("Acrobat", "AdobeCollabSync", "AcroCEF", "acrobat_sl")
$appTransformURL = "https://github.com/JonathanPitre/Apps/raw/master/Adobe/Acrobat%20Reader%20DC/AcroProx64.mst"
$appTransform = Split-Path -Path $appTransformURL -Leaf
$appInstallParameters = "/QB"
$appAddParameters = "EULA_ACCEPT=YES DISABLE_CACHE=1 DISABLE_PDFMAKER=YES DISABLEDESKTOPSHORTCUT=0 UPDATE_MODE=0 DISABLE_ARM_SERVICE_INSTALL=1"
$Evergreen = Get-EvergreenApp -Name AdobeAcrobatReaderDC | Where-Object { $_.Language -eq $appLanguage -and $_.Architecture -eq $appArchitecture }
$appVersion = $Evergreen.Version
$appSetupURL = $Evergreen.URI
$appSetup = Split-Path -Path $appSetupURL -Leaf
$appMsiSetup = "AcroPro.msi"
$Nevergreen = Get-NevergreenApp -Name AdobeAcrobatReader| Where-Object { $_.Architecture -eq $appArchitecture }
$appPatchURL = $Nevergreen.Uri
$appPatchVersion = $Nevergreen.Version
$appPatch = Split-Path -Path $appPatchURL -Leaf
$appDestination = "$env:ProgramFiles\$appVendor\$appName $appShortVersion\$appName"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName.* $appShortVersion .*" -RegEx)
$appInstalledVersion = (Get-InstalledApplication -Name "$appVendor $appName $appShortVersion (64-bit)" -Exact).DisplayVersion
##*===============================================

If ([version]$appVersion -gt [version]$appInstalledVersion)
{
    Set-Location -Path $appScriptDirectory

    # Download latest setup file(s)
    If (-Not(Test-Path -Path $appScriptDirectory\$appMsiSetup))
    {
        Write-Log -Message "Downloading $appVendor $appName $appShortVersion $appArchitecture $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appSetupURL -OutFile $appSetup
        Write-Log -Message "Extracting $appVendor $appName $appShortVersion $appArchitecture $appVersion MSI..." -Severity 1 -LogType CMTrace -WriteHost $True
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
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Modify setup.ini according to latest patch
    If (Test-Path -Path $appScriptDirectory\setup.ini)
    {
        Set-IniValue -FilePath $appScriptDirectory\setup.ini -Section "Startup" -Key "CmdLine" -Value "/sPB /rs /msi $appAddParameters"
        Set-IniValue -FilePath $appScriptDirectory\setup.ini -Section "Product" -Key "CmdLine" -Value "TRANSFORMS=`"$appTransform`""
        Set-IniValue -FilePath $appScriptDirectory\setup.ini -Section "Product" -Key "PATCH" -Value $appPatch
    }

    # Uninstall previous versions
    Get-Process -Name $appProcesses | Stop-Process -Force
    If (($IsAppInstalled) -and (Test-Path -Path $appScriptDirectory\$appMsiSetup))
    {
        Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
        Remove-MSIApplications -Name "$appVendor $appName* $appShortVersion*" -WildCard
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
        Execute-MSI -Action Install -Path $appMsiSetup  -Transform $appTransform -Parameters $appInstallParameters -AddParameters $appAddParameters -Patch $appPatch -SkipMSIAlreadyInstalledCheck
    }
    ElseIf (($appInstalledVersion) -and (Test-Path -Path $appScriptDirectory\$appPatch))
    {
        # Install latest patch
        Write-Log -Message "Setup file(s) are missing, MSP file will be installed." -Severity 1 -LogType CMTrace -WriteHost $True
        Write-Log -Message "Installing $appVendor $appName $appShortVersion $appArchitecture $appPatchVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Execute-MSP -Path $appPatch -Parameters $appInstallParameters
    }
    Else
    {
        Write-Log -Message "Setup file(s) are missing" -Severity 2 -LogType CMTrace -WriteHost $True
        Exit-Script
    }

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

    # Stop and disable unneeded scheduled tasks
    Get-ScheduledTask -TaskName "$appVendor $appName Update Task" | Stop-ScheduledTask
    Get-ScheduledTask -TaskName "$appVendor $appName Update Task" | Disable-ScheduledTask

    # Go back to the parent folder
    Set-Location ..

    Write-Log -Message "$appVendor $appName $appShortVersion $appArchitecture $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
}
Else
{
    Write-Log -Message "$appVendor $appName $appShortVersion $appArchitecture $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}