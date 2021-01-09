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
$appVendor = "Druide"
$appName = "Antidote"
$appProcesses = @("Antidote", "AgentAntidote", "Connectix", "AgentConnectix", "OUTLOOK", "WINWORD", "EXCEL", "POWERPNT")
$appTransform = "ReseauAntidote.mst"
$appTransform2 = "ReseauConnectix.mst"
$appURLVersion = "https://www.antidote.info/en/assistance/mises-a-jour/historique/antidote-10/windows"
$webRequest = Invoke-WebRequest -UseBasicParsing -Uri ($appURLVersion) -SessionVariable websession
$regexAppVersion = "Antidote \d\d v\d.+ Windows"
$webVersion = $webRequest.RawContent | Select-String -Pattern $regexAppVersion -AllMatches | ForEach-Object { $_.Matches.Value } | Select-Object -First 1
$appShortVersion = ($webVersion).Split(" ")[1]
$appPatchVersion = ($webVersion).Trim("Andidote $appShortVersion v").Trim(" Windows").Replace(" ", "")
$appVersion = "$appShortVersion.$appPatchVersion"
$appURLPatch = "https://telechargement12.druide.com/Win/antidote_$appShortVersion/Diff_Antidote_$($appShortVersion)_C_$($appShortVersion).$appPatchVersion.msp"
$appURLPatch2 = "https://telechargement12.druide.com/Win/antidote_$appShortVersion/Diff_Antidote_$($appShortVersion)_Module_F_$($appShortVersion).$appPatchVersion.msp"
$appURLPatch3 = "https://telechargement12.druide.com/Win/antidote_$appShortVersion/Diff_Antidote_$($appShortVersion)_Module_E_$($appShortVersion).$appPatchVersion.msp"
$appURLPatch4 = "https://telechargement12.druide.com/Win/antidote_$appShortVersion/Diff_Connectix_$($appShortVersion)_C_$($appShortVersion).$appPatchVersion.msp"
$appPatch = $appURLPatch.Split("/")[5]
$appPatch2 = $appURLPatch2.Split("/")[5]
$appPatch3 = $appURLPatch3.Split("/")[5]
$appPatch4 = $appURLPatch4.Split("/")[5]
$appSetup = "Antidote$appShortVersion.msi"
$appSetup2 = "Antidote$appShortVersion-Module-francais.msi"
$appSetup3 = "Antidote$appShortVersion-English-module.msi"
$appSetup4 = "Antidote-Connectix$appShortVersion.msi"
$appInstallParameters = "/QB"
$appSource = $appPatchVersion
$appDestination = "${env:ProgramFiles(x86)}\$appVendor\$appName $appShortVersion\Application\Bin64"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appName \d{2}" -RegEx) | Select-Object -First 1
$appInstalledVersion = (Get-InstalledApplication -Name "$appName \d{2}" -RegEx).DisplayVersion | Select-Object -First 1
##*===============================================

If ([version]$appVersion -gt [version]$appInstalledVersion) {
    Set-Location -Path $appScriptDirectory
    If (-Not(Test-Path -Path $appSource)) { New-Folder -Path $appSource }

    # Check if setup file exist
    If (-Not(Test-Path -Path $appScriptDirectory\$appSetup)) {
        Write-Log -Message "Setup files are missing. Please download and try again." -Severity 1 -LogType CMTrace -WriteHost $True
        Exit
    }

    # Uninstall previous versions
    Get-Process -Name $appProcesses | Stop-Process -Force
    If ($IsAppInstalled) {
        Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
        Remove-MSIApplications -Name $appName -Parameters $appInstallParameters
    }

    # Download latest setup file(s)
    If (-Not(Test-Path -Path $appScriptDirectory\$appSource\$appPatch)) {
        Write-Log -Message "Downloading $appVendor $appName $appShortVersion $appVersion Patch..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURLPatch -OutFile $appScriptDirectory\$appSource\$appPatch
    }
    Else {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    If (-Not(Test-Path -Path $appScriptDirectory\$appSource\$appPatch2)) {
        Write-Log -Message "Downloading $appVendor $appName $appShortVersion $appVersion Patch..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURLPatch2 -OutFile $appScriptDirectory\$appSource\$appPatch2
    }

    Else {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }
    If (-Not(Test-Path -Path $appScriptDirectory\$appSource\$appPatch3)) {
        Write-Log -Message "Downloading $appVendor $appName $appShortVersion $appVersion Patch..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURLPatch3 -OutFile $appScriptDirectory\$appSource\$appPatch3
    }
    Else {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    If (-Not(Test-Path -Path $appScriptDirectory\$appSource\$appPatch4)) {
        Write-Log -Message "Downloading $appVendor $appName $appShortVersion $appVersion Patch..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURLPatch4 -OutFile $appScriptDirectory\$appSource\$appPatch4
    }
    Else {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Install latest version
    Write-Log -Message "Installing $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    Execute-MSI -Action Install -Path $appSetup -Parameters $appInstallParameters -Transform $appTransform -SkipMSIAlreadyInstalledCheck -Patch $appScriptDirectory\$appSource\$appPatch
    Execute-MSI -Action Install -Path $appSetup2 -Parameters $appInstallParameters -SkipMSIAlreadyInstalledCheck -Patch $appScriptDirectory\$appSource\$appPatch2
    If (Test-Path -Path $appSetup3) {Execute-MSI -Action Install -Path $appSetup3 -Parameters $appInstallParameters -SkipMSIAlreadyInstalledCheck} -Patch $appScriptDirectory\$appSource\$appPatch3
    Execute-MSI -Action Install -Path $appSetup4 -Parameters $appInstallParameters -Transform $appTransform2 -SkipMSIAlreadyInstalledCheck -Patch $appScriptDirectory\$appSource\$appPatch4

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
Write-Verbose -Message "Custom modules were succesfully uninstalled!" -Verbose
#>