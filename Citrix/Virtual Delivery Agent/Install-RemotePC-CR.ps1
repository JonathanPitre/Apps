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
$appVendor = "Citrix"
$appName = "Virtual Apps and Desktops"
$appName2 = "Virtual Delivery Agent"
$appProcesses = @("BrokerAgent", "picaSessionAgent")
$appServices = @("CitrixTelemetryService")
# https://docs.citrix.com/en-us/citrix-virtual-apps-desktops-service/install-configure/install-command.html
# https://docs.citrix.com/en-us/citrix-virtual-apps-desktops/install-configure/install-vdas-sccm.html
$appInstallParameters = '/noreboot /quiet /enable_remote_assistance /disableexperiencemetrics /noresume /enable_real_time_transport /enable_hdx_ports /enable_hdx_udp_ports'
$Evergreen = Get-CitrixVirtualAppsDesktopsFeed | Where-Object {$_.Title -like "Citrix Virtual Apps and Desktops 7 *, All Editions"} | Select-Object -First 1
$appVersion = $Evergreen.Version
$appSetup = "VDAWorkstationCoreSetup_$appVersion.exe"
$appURL = "https://secureportal.citrix.com/Licensing/Downloads/UnrestrictedDL.aspx?DLID=19146&URL=https://downloads.citrix.com/19146/$appSetup"
$appSource = $appVersion
$appDestination = "$env:ProgramFiles\$appVendor\Virtual Delivery Agent"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor .*$appName2.*" -RegEx)
$appInstalledVersion = (((Get-InstalledApplication -Name "$appVendor .*$appName2.*" -RegEx).DisplayVersion)).Substring(0, 4)
##*===============================================

If ($appVersion -gt $appInstalledVersion) {
    Set-Location -Path $appScriptDirectory
    If (-Not(Test-Path -Path $appSource)) {New-Folder -Path $appSource}
    Set-Location -Path $appSource

    # Install Windows Server Media Foundation feature if missing
    If ($envOSName -Like "*Windows Server *") {
        If (!(Get-WindowsFeature -Name Server-Media-Foundation)) {Install-WindowsFeature Server-Media-Foundation}
    }

    # Install Windows Media Player feature if missing
    If ($envOSName -Like "*Windows 10*") {
        If ((Get-WindowsOptionalFeature –FeatureName "WindowsMediaPlayer" -Online).State -ne "Enabled") {
            Enable-WindowsOptionalFeature –FeatureName "WindowsMediaPlayer" -All -Online
        }
    }

    # Fix VDA install error - https://www.thewindowsclub.com/computer-missing-media-features-icloud-windows-error
    If (Test-Path -Path "$envProgramFiles\Windows Media Player\wmplayer.exe") {
        $WindowsMediaPlayerVersion = (Get-FileVersion -File "$envProgramFiles\Windows Media Player\setup_wm.exe" -ProductVersion)
        If ((Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\WindowsFeatures\WindowsMediaVersion") -and (Get-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\WindowsFeatures\WindowsMediaVersion" -Value "(Default)") -eq "") {
            Write-Log -Message "Windows Media Player version is empty" -Severity 1 -LogType CMTrace -WriteHost $True
            Set-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\WindowsFeatures\WindowsMediaVersion" -Name "(Default)" -Value $WindowsMediaPlayerVersion -Type "DWord"
        }
    }

    If (-Not(Test-Path -Path $appScriptDirectory\$appSource\$appSetup)) {

        Write-Log -Message "MyCitrix credentials (for downloading the VDA)" -Severity 1 -LogType CMTrace -WriteHost $True
        $MyCitrixUserName = Read-Host -Prompt "Please supply your MyCitrix username"
        $MyCitrixPassword1 = Read-Host -Prompt "Please supply your MyCitrix password" -AsSecureString
        $MyCitrixPassword2 = Read-Host -Prompt "Please supply your MyCitrix password once more" -AsSecureString
        $MyCitrixPassword1Temp = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($MyCitrixPassword1))
        $MyCitrixPassword2Temp = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($MyCitrixPassword2))

        If ($MyCitrixPassword1Temp -ne $MyCitrixPassword2Temp) {
            Write-Log -Message "The supplied MyCitrix passwords are not the same" -Severity 3 -LogType CMTrace -WriteHost $True
            Return
        }

        Remove-Variable -Name MyCitrixPassword1Temp,MyCitrixPassword2Temp
        $CitrixCredentials = New-Object System.Management.Automation.PSCredential ($MyCitrixUserName, $MyCitrixPassword1)

        # Verify Citrix credentials
        # Ryan Butler TechDrabble.com @ryan_c_butler 07/19/2019
        $CitrixUserName = $CitrixCredentials.UserName
        $CitrixPassword = $CitrixCredentials.GetNetworkCredential().Password

        Write-Log -Message "Downloading $appVendor $appName2 $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        # Ryan Butler TechDrabble.com @ryan_c_butler 07/19/2019
        $CitrixUserName = $CitrixCredentials.UserName
        $CitrixPassword = $CitrixCredentials.GetNetworkCredential().Password

        # Initialize Session
        Invoke-WebRequest "https://identity.citrix.com/Utility/STS/Sign-In?ReturnUrl=%2fUtility%2fSTS%2fsaml20%2fpost-binding-response" -SessionVariable CTXWebSession -UseBasicParsing

        # Authenticate
        $WebFormAuth = @{
            "persistent" = "on"
            "userName"   = $CitrixUserName
            "password"   = $CitrixPassword
        }

        Invoke-WebRequest -Uri ("https://identity.citrix.com/Utility/STS/Sign-In?ReturnUrl=%2fUtility%2fSTS%2fsaml20%2fpost-binding-response") -WebSession $CTXWebSession -Method POST -Body $WebFormAuth -ContentType "application/x-www-form-urlencoded" -UseBasicParsing

        $DownloadVDA = Invoke-WebRequest -Uri $appURL -WebSession $CTXWebSession -UseBasicParsing -Verbose -Method GET

        $WebFormDownload = @{
            "chkAccept"         = "on"
            "__EVENTTARGET"     = "clbAccept_0"
            "__EVENTARGUMENT"   = "clbAccept_0_Click"
            "__VIEWSTATE"       = ($DownloadVDA.InputFields | Where-Object { $_.id -eq "__VIEWSTATE" }).value
            "__EVENTVALIDATION" = ($DownloadVDA.InputFields | Where-Object { $_.id -eq "__EVENTVALIDATION" }).value
        }

        # Download latest version
        Invoke-WebRequest -Uri $appURL -WebSession $CTXWebSession -Method POST -Body $WebFormDownload -ContentType "application/x-www-form-urlencoded" -UseBasicParsing -OutFile $appSetup -Verbose

    }
    Else {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    Copy-File -Path ".\*" -Destination "$env:SystemDrive\Installs\VDA" -Recurse

    # Uninstall previous versions
    Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
    Get-Process -Name $appProcesses | Stop-Process -Force

    # Install latest version
    Write-Log -Message "Installing $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    Execute-Process -Path .\$appSetup -Parameters $appInstallParameters -WaitForMsiExec -IgnoreExitCodes "3"

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

    # Stop and disable unneeded services
    Stop-ServiceAndDependencies -Name $appServices[0]
    Set-ServiceStartMode -Name $appServices[0] -StartMode "Disabled"

    # Add Windows Defender exclusion(s) - https://docs.citrix.com/en-us/tech-zone/build/tech-papers/antivirus-best-practices.html
    Add-MpPreference -ExclusionProcess "%ProgramFiles%\Citrix\User Profile Manager\UserProfileManager.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles%\Citrix\Virtual Desktop Agent\BrokerAgent.exe" -Force
    Add-MpPreference -ExclusionProcess "%SystemRoot%\System32\spoolsv.exe" -Force
    Add-MpPreference -ExclusionProcess "%SystemRoot%\System32\winlogon.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles%\Citrix\ICAService\picaSvc2.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles%\Citrix\ICAService\CpSvc.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\HDX\bin\WebSocketService.exe" -Force
    #Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\HDX\bin\WebSocketAgent.exe" -Force

    # Setting powercfg over-rides to get around screen lock issues - https://forums.ivanti.com/s/article/Screensaver-doesn-t-become-active-on-a-Citrix-Virtual-Desktop-Agent
    Execute-Process -Path "$envSystem32Directory\powercfg.exe" -Parameters "/requestsoverride PROCESS picaSessionAgent.exe DISPLAY"
    Execute-Process -Path "$envSystem32Directory\powercfg.exe" -Parameters "/requestsoverride PROCESS GFXMGR.exe DISPLAY"

    # Registry optimizations
    # https://www.carlstalhood.com/remote-pc/#deliverygroup
    # When a user connects to his physical VDA using Remote PC Access, the monitor layout order change - https://support.citrix.com/article/CTX256820
    # Set-RegistryKey -Key "HKLM:\SOFTWARE\Citrix\Graphics" -Name "UseSDCForLocalModes" -Type "DWord" -Value "1"

    # The virtual machine 'Unknown' cannot accept additional sessions - https://discussions.citrix.com/topic/403211-remote-pc-solution-issue-the-virtual-machine-unknown-cannot-accept-additional-sessions/?source=email#comment-2045356
    # Set-RegistryKey -Key "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type "DWord" -Value "0"

    # Session disconnects when you select Ctrl+Alt+Del on the machine that has session management notification enabled - https://docs.citrix.com/en-us/citrix-virtual-apps-desktops/install-configure/remote-pc-access.html
    # Set-RegistryKey -Key "HKLM:\SOFTWARE\Citrix\PortICA" -Name "ForceEnableRemotePC" -Type "DWord" -Value "1"

    # Allow a Remote PC Access machine to go into a sleep state - https://docs.citrix.com/en-us/citrix-virtual-apps-desktops/install-configure/remote-pc-access.html
    # Set-RegistryKey -Key "HKLM:\SOFTWARE\Citrix\PortICA" -Name "DisableRemotePCSleepPreventer" -Type "DWord" -Value "1"

    # Prevent automatic disconnection to the local user session when a remote user session is initiated (by pressing CTRL+ATL+DEL) - https://docs.citrix.com/en-us/citrix-virtual-apps-desktops/install-configure/remote-pc-access.html
    # Set-RegistryKey -Key "HKLM:\SOFTWARE\Citrix\PortICA\RemotePC" -Name "SasNotification" -Type "DWord" -Value "1"

    # The local user has preference over the remote user when the connection message is not acknowledged within the timeout period - https://docs.citrix.com/en-us/citrix-virtual-apps-desktops/install-configure/remote-pc-access.html
    # Set-RegistryKey -Key "HKLM:\SOFTWARE\Citrix\PortICA\RemotePC" -Name "RpcaMode" -Type "DWord" -Value "1"

    # The timeout for enforcing the Remote PC Access mode is 30 seconds (decimal) by default - https://docs.citrix.com/en-us/citrix-virtual-apps-desktops/install-configure/remote-pc-access.html
    # Set-RegistryKey -Key "HKLM:\SOFTWARE\Citrix\PortICA\RemotePC" -Name "RpcaTimeout" -Type "DWord" -Value "45"

    Set-Location -Path $appScriptDirectory
    Remove-Folder -Path "$env:SystemDrive\Installs"

    Write-Log -Message "$appVendor $appName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True

    Write-Log -Message "$appVendor $appName2" -Text "A reboot required after $appVendor $appName2 $appVersion installation. The computer $envComputerName will reboot in 30 seconds!" -Severity 2 -LogType CMTrace -WriteHost $True
    Show-DialogBox -Title "$appVendor $appName2" -Text "A reboot required after $appVendor $appName2 $appVersion installation. The computer $envComputerName will reboot in 30 seconds!" -Timeout "10" -Icon "Exclamation"
    Show-InstallationRestartPrompt -Countdownseconds 30 -CountdownNoHideSeconds 30

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