# Standalone application install script for VDI environment - (C)2022 Jonathan Pitre, inspired by xenappblog.com

#Requires -Version 5.1
#Requires -RunAsAdministrator

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"
# Set the script execution policy for this process
Try { Set-ExecutionPolicy -ExecutionPolicy 'ByPass' -Scope 'Process' -Force } Catch {}
$env:SEE_MASK_NOZONECHECKS = 1
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
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

Function Get-CitrixDownload
{
    <#
.SYNOPSIS
  Downloads a Citrix VDA or ISO from Citrix.com utilizing authentication
.DESCRIPTION
  Downloads a Citrix VDA or ISO from Citrix.com utilizing authentication
  Ryan Butler 2/6/2020 https://github.com/ryancbutler/Citrix/tree/master/XenDesktop/AutoDownload
.PARAMETER dlNumber
  Number assigned to binary download
.PARAMETER dlEXE
  File to be downloaded
.PARAMETER dlPath
  Path to store downloaded file. Must contain following slash (C:\Temp\)
.PARAMETER CitrixUserName
  Citrix.com username
.PARAMETER CitrixPassword
  Citrix.com password
.EXAMPLE
  Get-CitrixDownload -dlNumber "16834" -dlEXE "Citrix_Virtual_Apps_and_Desktops_7_1912.iso" -CitrixUserName "MyCitrixUsername" -CitrixPassword "MyCitrixPassword" -dlPath "C:\Temp\"
#>
    Param(
        [Parameter(Mandatory = $true)]$dlNumber,
        [Parameter(Mandatory = $true)]$dlEXE,
        [Parameter(Mandatory = $true)]$dlPath,
        [Parameter(Mandatory = $true)]$CitrixUserName,
        [Parameter(Mandatory = $true)]$CitrixPassword
    )
    #Initialize Session
    Invoke-WebRequest "https://identity.citrix.com/Utility/STS/Sign-In?ReturnUrl=%2fUtility%2fSTS%2fsaml20%2fpost-binding-response" -SessionVariable websession -UseBasicParsing | Out-Null

    #Set Form
    $Form = @{
        "persistent" = "on"
        "userName"   = $CitrixUserName
        "password"   = $CitrixPassword
    }

    #Authenticate
    Try
    {
        Invoke-WebRequest -Uri ("https://identity.citrix.com/Utility/STS/Sign-In?ReturnUrl=%2fUtility%2fSTS%2fsaml20%2fpost-binding-response") -WebSession $websession -Method POST -Body $form -ContentType "application/x-www-form-urlencoded" -UseBasicParsing -ErrorAction Stop | Out-Null
    }
    Catch
    {
        If ($_.Exception.Response.StatusCode.Value__ -eq 500)
        {
            Write-Verbose "500 returned on auth. Ignoring"
            Write-Verbose $_.Exception.Response
            Write-Verbose $_.Exception.Message
        }
        Else
        {
            Throw $_
        }
    }

    $dlURL = "https://secureportal.citrix.com/Licensing/Downloads/UnrestrictedDL.aspx?DLID=${dlNumber}&URL=https://downloads.citrix.com/${dlNumber}/${dlEXE}"
    $Download = Invoke-WebRequest -Uri $dlURL -WebSession $WebSession -UseBasicParsing -Method GET
    $Webform = @{
        "chkAccept"            = "on"
        "clbAccept"            = "Accept"
        "__VIEWSTATEGENERATOR" = ($Download.InputFields | Where-Object { $_.id -eq "__VIEWSTATEGENERATOR" }).value
        "__VIEWSTATE"          = ($Download.InputFields | Where-Object { $_.id -eq "__VIEWSTATE" }).value
        "__EVENTVALIDATION"    = ($Download.InputFields | Where-Object { $_.id -eq "__EVENTVALIDATION" }).value
    }

    $OutFile = ($dlPath + $dlEXE)
    #Download
    Invoke-WebRequest -Uri $dlURL -WebSession $WebSession -Method POST -Body $Webform -ContentType "application/x-www-form-urlencoded" -UseBasicParsing -OutFile $OutFile
    return $OutFile
}

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$appVendor = "Citrix"
$appName = "Virtual Apps and Desktops"
$appName2 = "Virtual Delivery Agent"
$appProcesses = @("BrokerAgent", "picaSessionAgent")
$appServices = @("CitrixTelemetryService")
# https://docs.citrix.com/en-us/citrix-virtual-apps-desktops-service/install-configure/install-command.html
# https://docs.citrix.com/en-us/citrix-virtual-apps-desktops/install-configure/install-vdas-sccm.html
$appInstallParameters = '/components vda /disableexperiencemetrics /enable_hdx_ports /enable_hdx_udp_ports /enable_real_time_transport /enable_remote_assistance /enablerestore /enable_ss_ports /exclude "Machine Identity Service","Citrix Universal Print Client","Citrix Personalization for App-V - VDA","Citrix Supportability Tools","Citrix Files for Windows","Citrix Files for Outlook","User Personalization layer","Citrix WEM Agent","Citrix MCS IODriver" /includeadditional "Citrix Profile Management","Citrix Profile Management WMI Plugin","Citrix Telemetry Service","Citrix VDA Upgrade Agent","Citrix Rendezvous V2" /noreboot /noresume /quiet /remotepc /remove_appdisk_ack /remove_pvd_ack'
$Evergreen = Get-EvergreenApp -Name CitrixVirtualAppsDesktopsFeed | Where-Object {$_.Title -like "Citrix Virtual Apps and Desktops 7 22*, All Editions"} | Sort-Object Version -Descending | Select-Object -First 1
$appVersion = $Evergreen.Version
$appSetup = "VDAWorkstationSetup_$appVersion.exe"
$appDlNumber = "20117"
$appDestination = "$env:ProgramFiles\$appVendor\Virtual Delivery Agent"
$appHardwarePlatform = Get-HardwarePlatform
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor .*$appName2.*" -RegEx)
$appInstalledVersion = (((Get-InstalledApplication -Name "$appVendor .*$appName2.*" -RegEx).DisplayVersion)).Substring(0, 4)

#-----------------------------------------------------------[Execution]------------------------------------------------------------

If ($appVersion -gt $appInstalledVersion)
{
    Set-Location -Path $appScriptDirectory
    If (-Not(Test-Path -Path $appVersion)) {New-Folder -Path $appVersion}
    Set-Location -Path $appVersion

    # Install Windows Server Media Foundation feature if missing
    If ($envOSName -Like "*Windows Server *")
    {
        If (-Not(Get-WindowsFeature -Name Server-Media-Foundation)) {Install-WindowsFeature Server-Media-Foundation}
    }

    # Install Windows Media Player feature if missing
    If ($envOSName -Like "*Windows 10*")
    {
        If ((Get-WindowsOptionalFeature -FeatureName "WindowsMediaPlayer" -Online).State -ne "Enabled")
        {
            Enable-WindowsOptionalFeature -FeatureName "WindowsMediaPlayer" -All -Online
        }
    }

    # Fix VDA install error - https://www.thewindowsclub.com/computer-missing-media-features-icloud-windows-error
    If (Test-Path -Path "$envProgramFiles\Windows Media Player\wmplayer.exe")
    {
        $WindowsMediaPlayerVersion = (Get-FileVersion -File "$envProgramFiles\Windows Media Player\setup_wm.exe" -ProductVersion)
        If ((Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\WindowsFeatures\WindowsMediaVersion") -and (Get-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\WindowsFeatures\WindowsMediaVersion" -Value "(Default)") -eq "")
        {
            Write-Log -Message "Windows Media Player version is empty" -Severity 1 -LogType CMTrace -WriteHost $True
            Set-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\WindowsFeatures\WindowsMediaVersion" -Name "(Default)" -Value $WindowsMediaPlayerVersion -Type "DWord"
        }
    }

    If (-Not(Test-Path -Path $appScriptDirectory\$appVersion\$appSetup) -or (Get-ChildItem).Length -lt 1024kb)
    {
        Write-Log -Message "Citrix credentials for downloading the $appVendor $appName2" -Severity 1 -LogType CMTrace -WriteHost $True
        $CitrixUserName = Read-Host -Prompt "Please supply your Citrix.com username"
        $CitrixPassword1 = Read-Host -Prompt "Please supply your Citrix.com password" -AsSecureString
        $CitrixPassword2 = Read-Host -Prompt "Please supply your Citrix.com password once more" -AsSecureString
        $CitrixPassword1Temp = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($CitrixPassword1))
        $CitrixPassword2Temp = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($CitrixPassword2))

        If ($CitrixPassword1Temp -ne $CitrixPassword2Temp)
        {
            Write-Log -Message "The supplied Citrix passwords missmatch!" -Severity 3 -LogType CMTrace -WriteHost $True
            Exit-Script -ExitCode 1
        }

        Remove-Variable -Name CitrixPassword1Temp, CitrixPassword2Temp
        $CitrixCredentials = New-Object System.Management.Automation.PSCredential ($CitrixUserName, $CitrixPassword1)

        # Verify Citrix credentials
        $CitrixUserName = $CitrixCredentials.UserName
        $CitrixPassword = $CitrixCredentials.GetNetworkCredential().Password

        # Download latest version
        Write-Log -Message "Downloading $appVendor $appName2 $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Get-CitrixDownload -dlNumber $appDlNumber -dlEXE $appSetup -CitrixUserName $CitrixUserName -CitrixPassword $CitrixPassword -dlPath .\
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Copy $appSetup to $envTemp\Install to avoid install issue
    Copy-File -Path ".\$appSetup" -Destination "$envTemp\Install" -Recurse
    Set-Location -Path "$envTemp\Install"

    # Uninstall previous versions
    Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
    Get-Process -Name $appProcesses | Stop-Process -Force

    # Install latest version
    Write-Log -Message "Installing $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    Execute-Process -Path .\$appSetup -Parameters $appInstallParameters -WaitForMsiExec -IgnoreExitCodes "3"

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

    # Stop and disable unneeded services
    Stop-ServiceAndDependencies -Name $appServices[0] -SkipServiceExistsTest
    Set-ServiceStartMode -Name $appServices[0] -StartMode "Disabled" -ContinueOnError $True

    # Add Windows Defender exclusion(s) - https://docs.citrix.com/en-us/tech-zone/build/tech-papers/antivirus-best-practices.html
    Add-MpPreference -ExclusionProcess "%ProgramFiles%\Citrix\User Profile Manager\UserProfileManager.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles%\Citrix\Virtual Desktop Agent\BrokerAgent.exe" -Force
    Add-MpPreference -ExclusionProcess "%SystemRoot%\System32\spoolsv.exe" -Force
    Add-MpPreference -ExclusionProcess "%SystemRoot%\System32\winlogon.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles%\Citrix\ICAService\picaSvc2.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles%\Citrix\ICAService\CpSvc.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\HDX\bin\WebSocketService.exe" -Force
    Add-MpPreference -ExclusionPath "%SystemRoot%\System32\drivers\CtxUvi.sys" -Force

    # Setting powercfg over-rides to get around screen lock issues - https://forums.ivanti.com/s/article/Screensaver-doesn-t-become-active-on-a-Citrix-Virtual-Desktop-Agent
    Execute-Process -Path "$envSystem32Directory\powercfg.exe" -Parameters "/requestsoverride PROCESS picaSessionAgent.exe DISPLAY"
    Execute-Process -Path "$envSystem32Directory\powercfg.exe" -Parameters "/requestsoverride PROCESS GFXMGR.exe DISPLAY"

    # Registry optimizations
    # Enable EDT MTU Discovery on the VDA - https://docs.citrix.com/en-us/citrix-virtual-apps-desktops/technical-overview/hdx/adaptive-transport.html
    # Now enabled by default
    #Set-RegistryKey -Key "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\icawd" -Name "MtuDiscovery" -Type "DWord" -Value "1"

    # Disable Citrix Profile Management if detected
    If ((Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ctxProfile") -and (Get-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Citrix\UserProfileManager" -Value "PSEnabled") -ne "0")
    {
        Write-Log -Message "Disabling Citrix Profile Management..." -Severity 1 -LogType CMTrace -WriteHost $True
        Set-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Citrix\UserProfileManager" -Name "PSEnabled" -Value "0" -Type "DWord"
    }

    # https://www.carlstalhood.com/remote-pc/#deliverygroup
    # When a user connects to his physical VDA using Remote PC Access, the monitor layout order change - https://support.citrix.com/article/CTX256820
    # Set-RegistryKey -Key "HKLM:\SOFTWARE\Citrix\Graphics" -Name "UseSDCForLocalModes" -Type "DWord" -Value "1"

    # The virtual machine 'Unknown' cannot accept additional sessions - https://discussions.citrix.com/topic/403211-remote-pc-solution-issue-the-virtual-machine-unknown-cannot-accept-additional-sessions/?source=email#comment-2045356
    # Set-RegistryKey -Key "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type "DWord" -Value "0"

    # Session disconnects when you select Ctrl+Alt+Del on the machine that has session management notification enabled - https://docs.citrix.com/en-us/citrix-virtual-apps-desktops/install-configure/remote-pc-access.html
    If (($appHardwarePlatform -like "Virtual*") -or (Get-WindowsOptionalFeature -FeatureName "Microsoft-Hyper-V" -Online).State -eq "Enabled")
    {
        Set-RegistryKey -Key "HKLM:\SOFTWARE\Citrix\PortICA" -Name "ForceEnableRemotePC" -Type "DWord" -Value "1"
    }
    Else
    {
        # Disconnected sessions might remain open on a p ysical machine even after the time specified under "Disconnect session timer interval" has passed
        # https://discussions.citrix.com/topic/410389-sessions-to-physical-pcs-do-not-go-into-disconnected-state
        # https://docs.citrix.com/en-us/legacy-archive/downloads/xenapp-and-xendesktop-7.6-long-term-service-release-(ltsr).pdf
        #Set-RegistryKey -Key "HKLM:\SOFTWARE\Citrix\PortICA" -Name "ForceDisableRemotePC" -Type "DWord" -Value "1"
    }

    # Allow a Remote PC Access machine to go into a sleep state - https://docs.citrix.com/en-us/citrix-virtual-apps-desktops/install-configure/remote-pc-access.html
    # Set-RegistryKey -Key "HKLM:\SOFTWARE\Citrix\PortICA" -Name "DisableRemotePCSleepPreventer" -Type "DWord" -Value "1"

    # Prevent automatic disconnection to the local user session when a remote user session is initiated (by pressing CTRL+ATL+DEL) - https://docs.citrix.com/en-us/citrix-virtual-apps-desktops/install-configure/remote-pc-access.html
    # Set-RegistryKey -Key "HKLM:\SOFTWARE\Citrix\PortICA\RemotePC" -Name "SasNotification" -Type "DWord" -Value "1"

    # The local user has preference over the remote user when the connection message is not acknowledged within the timeout period - https://docs.citrix.com/en-us/citrix-virtual-apps-desktops/install-configure/remote-pc-access.html
    # Set-RegistryKey -Key "HKLM:\SOFTWARE\Citrix\PortICA\RemotePC" -Name "RpcaMode" -Type "DWord" -Value "1"

    # The timeout for enforcing the Remote PC Access mode is 30 seconds (decimal) by default - https://docs.citrix.com/en-us/citrix-virtual-apps-desktops/install-configure/remote-pc-access.html
    # Set-RegistryKey -Key "HKLM:\SOFTWARE\Citrix\PortICA\RemotePC" -Name "RpcaTimeout" -Type "DWord" -Value "45"

    # Enable WOL
    # https://www.cyberdrain.com/monitoring-with-powershell-monitor-and-enabling-wol-for-hp-lenovo-dell

    # Enable Rendezvous - https://docs.citrix.com/en-us/citrix-daas/hdx/rendezvous-protocol/rendezvous-v2.html
    If ((Get-RegistryKey -Key "HKLM:\SOFTWARE\Citrix\XenDesktopSetup" -Value "Rendezvous V2 Component") -eq "1")
    {
        Set-RegistryKey -Key "HKLM:\SOFTWARE\Citrix\VirtualDesktopAgent" -Name "GctRegistration" -Type "DWord" -Value "1"
    }

    # Go back to the parent folder
    Set-Location ..
    Remove-Folder -Path "$envTemp\Install"

    Write-Log -Message "$appVendor $appName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True

    Write-Log -Message "$appVendor $appName2" -Text "A reboot required after $appVendor $appName2 $appVersion installation. The computer $envComputerName will reboot in 30 seconds!" -Severity 2 -LogType CMTrace -WriteHost $True
    Show-InstallationRestartPrompt -Countdownseconds 30 -CountdownNoHideSeconds 30
}
Else
{
    Write-Log -Message "$appVendor $appName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}