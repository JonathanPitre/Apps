# Standalone application install script for VDI environment - (C)2021 Jonathan Pitre & Owen Reynolds, inspired by xenappblog.com

#Requires -Version 5.1
#Requires -RunAsAdministrator

# Custom package providers list
$PackageProviders = @("Nuget")

# Custom modules list
$Modules = @("PSADT", "Evergreen")

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
$appVendor = "Citrix"
$appName = "Workspace"
$appName2 = "App"
$appProcesses = @("wfica32", "wfcrun32", "redirector", "CDViewer", "HdxBrowser", "HdxTeams", "HdxBrowserCef", "concentr", "cpviewer", "PseudoContainer2", "PseudoContainer", "CtxCFRUI", "ssonsvr", "WebHelper", "SelfServicePlugin", "SelfService", "Receiver", "Ceip", "AuthManSvr", "CWAUpdaterService")
# https://docs.citrix.com/en-us/citrix-workspace-app-for-windows/install.html
$appInstallParameters = "EnableCEIP=false EnableTracing=false /forceinstall /noreboot /silent /includeSSON /AutoUpdateCheck=disabled"
$Evergreen = Get-EvergreenApp -Name CitrixWorkspaceApp | Where-Object {$_.Title -contains "Citrix Workspace - Current Release"}
$appVersion = $Evergreen.Version
$appURL = $Evergreen.URI
$appSetup = Split-Path -Path $appURL -Leaf
$appDestination = "${env:ProgramFiles(x86)}\Citrix\ICA Client"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName \d{4}" -RegEx)
$appInstalledVersion = (Get-InstalledApplication -Name "$appVendor $appName \d{4}" -RegEx).DisplayVersion
##*===============================================

If ([version]$appVersion -gt [version]$appInstalledVersion) {
    Set-Location -Path $appScriptDirectory
    If (-Not(Test-Path -Path $appVersion)) {New-Folder -Path $appVersion}
    Set-Location -Path $appVersion

    If (-Not(Test-Path -Path $appScriptDirectory\$appVersion\$appSetup)) {
        Write-Log -Message "Downloading $appVendor $appName $appName2 $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURL -OutFile $appSetup
    }
    Else {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
    Get-Process -Name $appProcesses | Stop-Process -Force

    Write-Log -Message "Installing $appVendor $appName $appName2 $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    Execute-Process -Path .\$appSetup -Parameters $appInstallParameters -WaitForMsiExec

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

    # Disable automatic updates service
    If (Test-ServiceExists -Name CWAUpdaterService) {
        Stop-ServiceAndDependencies -Name CWAUpdaterService
        Set-ServiceStartMode -Name CWAUpdaterService -StartMode "Disabled"
    }
    Get-Process -Name $appProcesses | Stop-Process -Force

    # Add Windows Defender exclusion(s) - https://docs.citrix.com/en-us/tech-zone/build/tech-papers/antivirus-best-practices.html
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\ICA Client\AuthManager\AuthManSvr.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\ICA Client\CDViewer.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\ICA Client\HdxRtcEngine.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\ICA Client\SelfServicePlugin\SelfService.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\ICA Client\SelfServicePlugin\SelfServicePlugin.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\ICA Client\concentr.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\ICA Client\wfica32.exe" -Force

    # Add Windows Firewall rule(s) - https://docs.citrix.com/en-us/citrix-virtual-apps-desktops/multimedia/opt-ms-teams.html
    If (-Not(Get-NetFirewallRule -DisplayName "$appVendor $appName $appName2")) {
        New-NetFirewallRule -Displayname "$appVendor $appName" -Direction Inbound -Program "$appDestination\HdxRtcEngine.exe" -Profile 'Domain, Private, Public' -Protocol TCP
        New-NetFirewallRule -Displayname "$appVendor $appName" -Direction Inbound -Program "$appDestination\HdxRtcEngine.exe" -Profile 'Domain, Private, Public' -Protocol UDP
    }

    # Registry Optimizations
    # Fix AutoCAD slow mouse performance - https://support.citrix.com/article/CTX235943
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Wow6432Node\Citrix\ICA Client\Engine\Lockdown Profiles\All Regions\Lockdown\Virtual Channels\Mouse" -Name "MouseTimer" -Type "String" -Value "25"

    # Enable UDP Audio - https://www.mycugc.org/blogs/ray-davis1/2020/03/10/how-to-get-udp-audio-in-citrix-vad-working
    <#
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Citrix\ICA Client\Engine\Lockdown Profiles\All Regions\Lockdown\Virtual Channels\Audio" -Name "AudioBandwidthLimit" -Type "String" -Value "1-"
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Citrix\ICA Client\Engine\Lockdown Profiles\All Regions\Lockdown\Virtual Channels\Audio" -Name "ClientAudio" -Type "String" -Value "true,false"
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Citrix\ICA Client\Engine\Lockdown Profiles\All Regions\Lockdown\Virtual Channels\Audio" -Name "EnableRtpAudio" -Type "String" -Value "true,false"
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Citrix\ICA Client\Engine\Lockdown Profiles\All Regions\Lockdown\Virtual Channels\Audio" -Name "EnableUDPThroughGateway" -Type "String" -Value "true,false"
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Citrix\ICA Client\Engine\Lockdown Profiles\All Regions\Lockdown\Virtual Channels\Audio" -Name "RtpAudioHighestPort" -Type "String" -Value "16509"
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Citrix\ICA Client\Engine\Lockdown Profiles\All Regions\Lockdown\Virtual Channels\Audio" -Name "RtpAudioLowestPort" -Type "String" -Value "16500"
    #>

    # Go back to the parent folder
    Set-Location ..

    Write-Log -Message "$appVendor $appName $appName2 $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
}
Else {
    Write-Log -Message "$appVendor $appName $appName2 $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}