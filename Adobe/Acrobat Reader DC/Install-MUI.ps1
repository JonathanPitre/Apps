# PowerShell Wrapper for MDT, Standalone and Chocolatey Installation - (C)2020 Jonathan Pitre, inspired by xenappblog.com
# Example 1 Install EXE:
# Execute-Process -Path .\appName.exe -Parameters "/silent"
# Example 2 Install MSI:
# Execute-MSI -Action Install -Path appName.msi -Parameters "/QB" -AddParameters "ALLUSERS=1"
# Example 3 Uninstall MSI:
# Remove-MSIApplications -Name "appName" -Parameters "/QB"

#Requires -Version 5.1

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
        If (-not(Get-PackageProvider -ListAvailable -Name $PackageProvider -ErrorAction SilentlyContinue)) { Install-PackageProvider -Name $PackageProvider -Force }
    }

    # Add the Powershell Gallery as trusted repository
    Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted

    # Update PowerShellGet
    $InstalledPSGetVersion = (Get-PackageProvider -Name PowerShellGet).Version
    $PSGetVersion = [version](Find-PackageProvider -Name PowerShellGet).Version
    If ($PSGetVersion -gt $InstalledPSGetVersion) { Install-PackageProvider -Name PowerShellGet -Force }

    # Install and import custom modules list
    Foreach ($Module in $Modules) {
        If (-not(Get-Module -ListAvailable -Name $Module)) { Install-Module -Name $Module -AllowClobber -Force | Import-Module -Name $Module -Force }
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

# Get the current script directory
Function Get-ScriptDirectory {
    Remove-Variable appScriptDirectory
    Try {
        If ($psEditor) { Split-Path $psEditor.GetEditorContext().CurrentFile.Path } # Visual Studio Code Host
        ElseIf ($psISE) { Split-Path $psISE.CurrentFile.FullPath } # Windows PowerShell ISE Host
        ElseIf ($PSScriptRoot) { $PSScriptRoot } # Windows PowerShell 3.0-5.1
        Else {
            Write-Host -ForegroundColor Red "Cannot resolve script file's path"
            Exit 1
        }
    }
    Catch {
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
$appShortVersion = "DC"
$appProcesses = @("AcroRd32", "AcroBroker", "AcroTextExtractor", "ADelRCP", "AdobeCollabSync", "arh", "Eula", "FullTrustNotIfier", "LogTransport2", "reader_sl", "wow_helper")
$appTransform = "AcroRead.mst"
$appSetup = "AcroRead.msi"
$appInstallParameters = "/QB"
$appAddParameters = "EULA_ACCEPT=YES DISABLE_CACHE=1 DISABLE_PDFMAKER=YES DISABLEDESKTOPSHORTCUT=0 UPDATE_MODE=0 DISABLE_ARM_SERVICE_INSTALL=1"
$appAddParameters2 = "ALLUSERS=1"
$Evergreen = Get-AdobeAcrobat| Where-Object {$_.Track -eq "DC"}
$appVersion = $Evergreen.Version
# Evergreen removed the native command to download Adobe Reader MUI patch
$appURLPatch = ($Evergreen.URI).Replace("acrobat", "reader").Replace("AcrobatDCUpd", "AcroRdrDCUpd").Replace(".msp", "_MUI.msp")
$appPatch = ($appURLPatch).Split("/")[9]
$appURLMUI = "ftp://ftp.adobe.com/pub/adobe/reader/win/AcrobatDC/1500720033/AcroRdrDC1500720033_MUI.exe"
$appMUI = ($appURLMUI).Split("/")[9]
$appURLFont = "ftp://ftp.adobe.com/pub/adobe/reader/win/AcrobatDC/misc/FontPack1902120058_XtdAlf_Lang_DC.msi"
$appFont = ($appURLFont).Split("/")[9]
$appURLDic = "ftp://ftp.adobe.com/pub/adobe/reader/win/AcrobatDC/misc/AcroRdrSD1900820071_all_DC.msi"
$appDic = ($appURLDic).Split("/")[9]
$appURLADMX = "ftp://ftp.adobe.com/pub/adobe/reader/win/AcrobatDC/misc/ReaderADMTemplate.zip"
$appADMX = ($appURLADMX).Split("/")[9]
$appSource = $appVersion
$appDestination = "${env:ProgramFiles(x86)}\$appVendor\$appName $appShortVersion\Reader"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName $appShortVersion MUI")
$appInstalledVersion = (Get-InstalledApplication -Name "$appVendor $appName $appShortVersion MUI").DisplayVersion
##*===============================================

If ([version]$appVersion -gt [version]$appInstalledVersion) {
    Set-Location -Path $appScriptDirectory

    # Uninstall previous versions
    Get-Process -Name $appProcesses | Stop-Process -Force

    # Download latest setup file(s)
    If (-Not(Test-Path -Path $appScriptDirectory\$appSetup)) {
        Write-Log -Message "Downloading $appVendor $appName $appShortVersion MUI..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURLMUI -OutFile $appMUI
        Write-Log -Message "Extracting $appVendor $appName $appShortVersion MSI..." -Severity 1 -LogType CMTrace -WriteHost $True
        New-Folder -Path "$appScriptDirectory\MSI"
        Execute-Process -Path .\$appMUI -Parameters "-sfx_o`"$appScriptDirectory\MSI`" -sfx_ne"
        Copy-File -Path "$appScriptDirectory\MSI\*" -Destination $appScriptDirectory -Recurse
        Remove-Folder -Path "$appScriptDirectory\MSI"
        Remove-File -Path "$appScriptDirectory\$appMUI"
    }
    Else {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    If (-Not(Test-Path -Path $appScriptDirectory\$appDIC)) {
        Write-Log -Message "Downloading $appVendor $appName $appShortVersion Spelling Dictionaries..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURLDic -OutFile $appDic
    }
    Else {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    If (-Not(Test-Path -Path $appScriptDirectory\$appFont)) {
        Write-Log -Message "Downloading $appVendor $appName $appShortVersion Extended Asian Language Font Pack..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURLFont -OutFile $appFont
    }
    Else {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Download latest policy definitions
    Write-Log -Message "Downloading $appVendor $appName $appShortVersion ADMX templates..." -Severity 1 -LogType CMTrace -WriteHost $True
    Invoke-WebRequest -UseBasicParsing -Uri $appURLADMX -OutFile $appADMX
    New-Folder -Path "$appScriptDirectory\PolicyDefinitions"
    Expand-Archive -Path $appADMX -DestinationPath "$appScriptDirectory\PolicyDefinitions" -Force
    Remove-File -Path $appADMX, $appScriptDirectory\PolicyDefinitions\*.adm

    # Download latest patch file
    If (-Not(Test-Path -Path $appScriptDirectory\$appPatch)) {
        Write-Log -Message "Downloading $appVendor $appName $appShortVersion $appVersion patch..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURLPatch -OutFile $appPatch
        If (Test-Path -Path $appScriptDirectory\$appPatch) {
            Set-IniValue -FilePath $appScriptDirectory\setup.ini -Section "Startup" -Key "CmdLine" -Value "/sPB /rs"
            Set-IniValue -FilePath $appScriptDirectory\setup.ini -Section "Product" -Key "CmdLine" -Value "TRANSFORMS=`"$appTransform`""
            Set-IniValue -FilePath $appScriptDirectory\setup.ini -Section "Product" -Key "PATCH" -Value $appPatch
        }
    }
    Else {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Install latest version
    If ((Test-Path -Path $appScriptDirectory\$appSetup) -and (Test-Path -Path $appScriptDirectory\$appTransform)) {
        Write-Log -Message "Installing $appVendor $appName $appShortVersion $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Execute-MSI -Action Install -Path $appSetup -Transform $appTransform -Parameters $appInstallParameters -AddParameters $appAddParameters -Patch $appPatch -SkipMSIAlreadyInstalledCheck
    }
    Else {
        Write-Log -Message "Setup file(s) are missing." -Severity 1 -LogType CMTrace -WriteHost $True
        Exit-Script
    }

    Write-Log -Message "Installing $appVendor $appName $appShortVersion Spelling Dictionaries..." -Severity 1 -LogType CMTrace -WriteHost $True
    Execute-MSI -Action Install -Path $appDic -Parameters $appInstallParameters -AddParameters $appAddParameters2

    Write-Log -Message "Installing $appVendor $appName $appShortVersion Extended Asian Language Font Pack..." -Severity 1 -LogType CMTrace -WriteHost $True
    Execute-MSI -Action Install -Path $appFont -Parameters $appInstallParameters -AddParameters $appAddParameters2

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

    # Stop and disable unneeded scheduled tasks
    Get-ScheduledTask -TaskName "$appVendor Acrobat Update Task" | Stop-ScheduledTask
    Get-ScheduledTask -TaskName "$appVendor Acrobat Update Task" | Disable-ScheduledTask

    # Fix application Start Menu shorcut
    Copy-File -Path "$envCommonStartMenuPrograms\$appName $appShortVersion.lnk" -Destination "$envCommonStartMenuPrograms\$appVendor $appName $appShortVersion.lnk" -ContinueFileCopyOnError $True
    Remove-File -Path "$envCommonStartMenuPrograms\$appName $appShortVersion.lnk" -ContinueOnError $True

    Write-Log -Message "$appVendor $appName $appShortVersion $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True

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