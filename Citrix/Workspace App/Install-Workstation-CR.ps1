# Standalone application install script for VDI environment - (C)2022 Jonathan Pitre & Owen Reynolds, inspired by xenappblog.com

#Requires -Version 5.1
#Requires -RunAsAdministrator

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"
$env:SEE_MASK_NOZONECHECKS = 1
$Modules = @("PSADT","Evergreen") # Modules list

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

$appVendor = "Citrix"
$appName = "Workspace"
$appName2 = "app"
$appProcesses = @("wfica32", "wfcrun32", "redirector", "CDViewer", "HdxBrowser", "HdxTeams", "HdxBrowserCef", "concentr", "cpviewer", "PseudoContainer2", "PseudoContainer", "CtxCFRUI", "ssonsvr", "WebHelper", "SelfServicePlugin", "SelfService", "Receiver", "Ceip", "AuthManSvr", "CWAUpdaterService")
# https://docs.citrix.com/en-us/citrix-workspace-app-for-windows/install.html
$appInstallParameters = "EnableCEIP=false EnableTracing=false /forceinstall /noreboot /silent /includeSSON"
$Evergreen = Get-EvergreenApp -Name CitrixWorkspaceApp | Where-Object { $_.Title -like "Citrix Workspace - Current Release" }
$appVersion = $Evergreen.Version
$appURL = $Evergreen.URI
$appSetup = Split-Path -Path $appURL -Leaf
$appDestination = "${env:ProgramFiles(x86)}\Citrix\ICA Client"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName \d+" -RegEx)
$appInstalled = Get-InstalledApplication -Name "$appVendor $appName \d+" -RegEx
$appInstalledVersion = ($appInstalled).DisplayVersion

#-----------------------------------------------------------[Execution]------------------------------------------------------------

If ($appVersion -gt $appInstalledVersion) {
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

    Get-Process -Name $appProcesses | Stop-Process -Force

    # Add Windows Defender exclusion(s) - https://docs.citrix.com/en-us/tech-zone/build/tech-papers/antivirus-best-practices.html
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\ICA Client\AuthManager\AuthManSvr.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\ICA Client\CDViewer.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\ICA Client\HdxRtcEngine.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\ICA Client\SelfServicePlugin\SelfService.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\ICA Client\SelfServicePlugin\SelfServicePlugin.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\ICA Client\concentr.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\ICA Client\wfica32.exe" -Force

    # Add Windows Firewall rules
    # HDX Teams rule - https://docs.citrix.com/en-us/citrix-virtual-apps-desktops/multimedia/opt-ms-teams.html
    If (-Not(Get-NetFirewallRule -DisplayName "$appVendor $appName $appName2 HDX Teams")) {
        New-NetFirewallRule -Displayname "$appVendor $appName $appName2 HDX Teams" -Direction Inbound -Profile 'Domain, Private, Public' -Program "$appDestination\HdxRtcEngine.exe" -Protocol TCP
        New-NetFirewallRule -Displayname "$appVendor $appName $appName2 HDX Teams" -Direction Inbound -Profile 'Domain, Private, Public' -Program "$appDestination\HdxRtcEngine.exe" -Protocol UDP
    }

    # HDX Audio Real-time Transport UDP rule required with VDA 2112
    If (-Not(Get-NetFirewallRule -DisplayName "$appVendor $appName $appName2 HDX Audio Real-time Transport")) {
        New-NetFirewallRule -DisplayName "$appVendor $appName $appName2 HDX Audio Real-time Transport" -Direction Inbound -Protocol UDP -LocalPort 16500-16501 -Profile 'Domain, Private, Public' -Program "$appDestination\wfica32.exe"
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

    # Copy policy definitions files to lacal computer
    Copy-File -Path $appDestination\Configuration\*.admx, $appDestination\Configuration\en-us -Destination $envWinDir\PolicyDefinitions -Recurse

    # Go back to the parent folder
    Set-Location ..

    Write-Log -Message "$appVendor $appName $appName2 $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
}
Else {
    Write-Log -Message "$appVendor $appName $appName2 $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}