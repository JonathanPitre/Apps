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
[array]$Modules = @("PSADT", "Autologon", "BetterCredentials") # Modules list

Function Get-ScriptPath
{
    <#
    .SYNOPSIS
        Get-ScriptPath returns the path of the current script.
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param()

    Begin
    {
        Remove-Variable appScriptPath
    }
    Process
    {
        If ($psEditor) { Split-Path -Path $psEditor.GetEditorContext().CurrentFile.Path } # Visual Studio Code
        ElseIf ($MyInvocation.MyCommand.CommandType -eq "ExternalScript") { Split-Path -Path $My$MyInvocation.MyCommand.Source } # PS1 converted to EXE
        ElseIf ($null -ne $HostInvocation) { $HostInvocation.MyCommand.Path } # SAPIEN PowerShell Studio
        ElseIf ($psISE) { Split-Path -Path $psISE.CurrentFile.FullPath } # Windows PowerShell ISE
        ElseIf ($MyInvocation.PSScriptRoot) { $MyInvocation.PSScriptRoot } # Windows PowerShell 3.0+
        ElseIf ($MyInvocation.MyCommand.Path) { Split-Path -Path $MyInvocation.MyCommand.Path -Parent } # Windows PowerShell
        Else
        {
            Write-Host -Object "Unable to resolve script's file path!" -ForegroundColor Red
            Exit 1
        }
    }
}

Function Get-ScriptName
{
    <#
    .SYNOPSIS
        Get-ScriptName returns the name of the current script.
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param()
    Begin
    {
        Remove-Variable appScriptName
    }
    Process
    {
        If ($psEditor) { Split-Path -Path $psEditor.GetEditorContext().CurrentFile.Path -Leaf } # Visual Studio Code Host
        ElseIf ($psEXE) { [System.Diagnotics.Process]::GetCurrentProcess.Name } # PS1 converted to EXE
        ElseIf ($null -ne $HostInvocation) { $HostInvocation.MyCommand.Name } # SAPIEN PowerShell Studio
        ElseIf ($psISE) { $psISE.CurrentFile.DisplayName.Trim("*") } # Windows PowerShell ISE
        ElseIf ($MyInvocation.MyCommand.Name) { $MyInvocation.MyCommand.Name } # Windows PowerShell
        Else
        {
            Write-Host -Object "Uanble to resolve script's file name!" -ForegroundColor Red
            Exit 1
        }
    }
}

Function Initialize-Module
{
    <#
    .SYNOPSIS
        Initialize-Module install and import modules from PowerShell Galllery.
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Module
    )
    Write-Host -Object "Importing $Module module..." -ForegroundColor Green

    # If module is imported say that and do nothing
    If (Get-Module | Where-Object { $_.Name -eq $Module })
    {
        Write-Host -Object "Module $Module is already imported." -ForegroundColor Green
    }
    Else
    {
        # If module is not imported, but available on disk then import
        If ( [bool](Get-Module -ListAvailable | Where-Object { $_.Name -eq $Module }) )

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
            If (Find-Module -Name $Module | Where-Object { $_.Name -eq $Module })
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
                Exit 1
            }
        }
    }
}

[string]$appScriptPath = Get-ScriptPath # Get the current script path
[string]$appScriptName = Get-ScriptName # Get the current script name

# Install and import modules list
Foreach ($Module in $Modules)
{
    Initialize-Module -Module $Module
}

#endregion

#-----------------------------------------------------------[Functions]------------------------------------------------------------

#region Functions

Function Get-CitrixVDA
{
    [OutputType([System.Management.Automation.PSObject])]
    [CmdletBinding()]
    Param ()
    $DownloadURL = "https://docs.citrix.com/en-us/citrix-virtual-apps-desktops/whats-new.html"

    Try
    {
        $DownloadText = (Invoke-WebRequest -Uri $DownloadURL -DisableKeepAlive -UseBasicParsing).RawContent
    }
    Catch
    {
        Throw "Failed to connect to URL: $DownloadURL with error $_."
        Break
    }
    Finally
    {
        $RegEx = "(Citrix Virtual Apps and Desktops.+) (\d{4})"
        $Version = ($DownloadText | Select-String -Pattern $RegEx).Matches.Groups[2].Value

        if ($Version)
        {
            [PSCustomObject]
            @{
                Name    = 'Citrix Virtual Delivery Agent'
                Version = $Version
            }
        }
    }

}

Function Get-SessionName
{
    [OutputType([System.Management.Automation.PSObject])]
    [CmdletBinding()]
    Param ()
    $SessionInfo = qwinsta $env:USERNAME
    If ($SessionInfo)
    {
        ForEach ($line in $SessionInfo[1..$SessionInfo.Count])
        {
            $tmp = $line.split(" ") | Where-Object { $_.Length -gt 0 }
            $SessionName = $tmp[0].Trim(">")
            Return $SessionName
        }
    }
}

#endregion

#----------------------------------------------------------[Declarations]----------------------------------------------------------

#region Declarations

[string]$appVendor = "Citrix"
[string]$appName = "Virtual Delivery Agent"
# Installation parameters available here - https://docs.citrix.com/en-us/citrix-virtual-apps-desktops-service/install-configure/install-command.html
# https://docs.citrix.com/en-us/citrix-virtual-apps-desktops/install-configure/install-vdas-sccm.html
[int]$appVersion = (Get-CitrixVDA).Version
[string]$appInstall = "VDAWorkstationSetup_$appVersion.exe"
[string]$appInstallParameters = '/components vda /disableexperiencemetrics /enable_hdx_ports /enable_hdx_udp_ports /enable_real_time_transport /enable_remote_assistance /enable_ss_ports /exclude "Citrix Personalization for App-V - VDA","Citrix VDA Upgrade Agent" /includeadditional "Citrix Profile Management","Citrix Profile Management WMI Plug-in","Citrix MCS IODriver","Citrix Rendezvous V2","Citrix Web Socket VDA Registration Tool" /mastermcsimage /noreboot /noresume /quiet /remove_appdisk_ack /remove_pvd_ack'
[array]$appProcesses = @("BrokerAgent", "picaSessionAgent")
[array]$appServices = @("CitrixTelemetryService")
[string]$appDestination = "$env:ProgramFiles\$appVendor\Virtual Delivery Agent"
[string]$sessionName = Get-SessionName
[bool]$isAppInstalled = [bool](Get-InstalledApplication -Name "$appVendor .*$appName.*" -RegEx)
[int]$appInstalledVersion = ((Get-InstalledApplication -Name "$appVendor .*$appName.*" -RegEx).DisplayVersion).Substring(0, 4)
[string]$appCleanupTool = "VDACleanupUtility.exe"
[string]$appCleanupToolParameters = "/unattended /noreboot"
[string]$appUninstallString = (Get-InstalledApplication -Name "$appVendor .*$appName.*" -RegEx).UninstallString
[string]$appUninstall = ($appUninstallString).Split("/")[0].Trim().Trim("""")
[string]$appUninstallParameters = "/removeall /quiet /noreboot"

#endregion

#-----------------------------------------------------------[Execution]------------------------------------------------------------

#region Execution

# Get current account credentials
[bool]$isLocalCredentialStored = [bool](Find-Credential -Filter "*$envUserName")
If ($isLocalCredentialStored)
{
    Write-Host -Object "Stored credentials found for current account." -ForegroundColor Green
    $localCredentials = (BetterCredentials\Get-Credential -UserName $env:USERNAME -Store)
    $localCredentialsPassword = $localCredentials.Password
}
Else
{
    Write-Host -Object "Please enter your current account credentials." -ForegroundColor Green
    $null = BetterCredentials\Get-Credential -UserName $env:USERNAME -Store
    $localCredentials = (BetterCredentials\Get-Credential -UserName $env:USERNAME -Store)
    $localCredentialsPassword = $localCredentials.Password
}

# Detect if running from a Citrix session
If ($sessionName -like "*ica*")
{
    Write-Log -Message "$appVendor $appName CANNOT BE INSTALLED from a Citrix session, please run the installation from a CONSOLE SESSION!" -Severity 3 -LogType CMTrace -WriteHost $True
    Exit-Script
}

Set-Location -Path $appScriptPath
If (-Not(Test-Path -Path $appVersion)) { New-Folder -Path $appVersion }
Set-Location -Path $appVersion

If (($isAppInstalled -eq $false) -and (Test-Path -Path "$appScriptPath\$appVersion\$appInstall") -and (Test-Path -Path "$appScriptPath\$appCleanupTool"))
{
    # Install prerequisites
    If (-Not($envOSName -like "*Windows Server*"))
    {
        # Enable Microsoft Remote Assistance
        Write-Log -Message "Enabling Microsoft Remote Assistance..." -Severity 1 -LogType CMTrace -WriteHost $True
        Set-RegistryKey -Key "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value "1" -Type DWord

        # Install Windows Media Player
        If ((Get-WindowsOptionalFeature -FeatureName "WindowsMediaPlayer" -Online).State -ne "Enabled")
        {
            Write-Log -Message "Installing Microsoft Windows Media Player..." -Severity 1 -LogType CMTrace -WriteHost $True
            Enable-WindowsOptionalFeature -FeatureName "WindowsMediaPlayer" -All -Online
        }
    }
    Else
    {
        Write-Log -Message "$appVendor $appName CANNOT be installed on Windows Server!" -Severity 3 -LogType CMTrace -WriteHost $True
        Exit-Script
    }

    # Prevent installation error - https://www.thewindowsclub.com/computer-missing-media-features-icloud-windows-error
    If (Test-Path -Path "$envProgramFiles\Windows Media Player\wmplayer.exe")
    {
        $WindowsMediaPlayerVersion = (Get-FileVersion -File "$envProgramFiles\Windows Media Player\setup_wm.exe" -ProductVersion)
        If ((Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\WindowsFeatures\WindowsMediaVersion") -and (Get-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\WindowsFeatures\WindowsMediaVersion" -Value "(Default)") -eq "")
        {
            Write-Log -Message "Windows Media Player version is empty" -Severity 1 -LogType CMTrace -WriteHost $True
            Set-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\WindowsFeatures\WindowsMediaVersion" -Name "(Default)" -Value $WindowsMediaPlayerVersion -Type "DWord"
        }
    }

    # Fix an issue with Citrix Connection Quality Indicator
    If (Test-Path -Path "${env:ProgramFiles(x86)}\Citrix\HDX\bin\Connection Quality Indicator\Citrix.CQI.exe")
    {
        Write-Log -Message "Citrix Connection Quality Indicator must be uninstalled before the Virtual Delivery Agent installation, don't forget to REINSTALL it!" -Severity 2 -LogType CMTrace -WriteHost $True
        Get-Process -Name "CQISvc", "Citrix.CQI" | Stop-Process -Force
        Write-Log -Message "Uninstalling Citrix Connection Quality Indicator..." -Severity 1 -LogType CMTrace -WriteHost $True
        Remove-MSIApplications -Name "Citrix Connection Quality Indicator" -Exact
    }

    # Run Citrix VDA CleanUp Utility
    Write-Log -Message "Running $appVendor VDA Cleanup Utility..." -Severity 1 -LogType CMTrace -WriteHost $True
    Execute-Process -Path "$appScriptPath\$appCleanupTool" -Parameters "$appCleanupToolParameters" -IgnoreExitCodes 1

    # Copy $appInstall to $envTemp\Install to avoid install issue
    Copy-File -Path ".\$appInstall" -Destination "$envTemp\Install" -Recurse
    Set-Location -Path "$envTemp\Install"

    # Uninstall previous versions
    Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
    Get-Process -Name $appProcesses | Stop-Process -Force

    # Install latest version
    Write-Log -Message "Installing $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    Execute-Process -Path .\$appInstall -Parameters $appInstallParameters -WaitForMsiExec -IgnoreExitCodes "3"

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

    # Stop and disable unneeded services
    Get-Service -Name $appServices[0] | Stop-ServiceAndDependencies -Name $appServices[0] -SkipServiceExistsTest
    Get-Service -Name $appServices[0] | Set-ServiceStartMode -Name $appServices[0] -StartMode "Disabled" -ContinueOnError $True

    # Add Windows Defender exclusion(s) - https://docs.citrix.com/en-us/tech-zone/build/tech-papers/antivirus-best-practices.html
    Add-MpPreference -ExclusionPath "%SystemRoot%\System32\drivers\CtxUvi.sys" -Force
    Add-MpPreference -ExclusionPath "%ProgramFiles%\Citrix\HDX\bin\CitrixLogonCsp.dll" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles%\Citrix\User Profile Manager\UserProfileManager.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles%\Citrix\Virtual Desktop Agent\BrokerAgent.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles%\Citrix\HDX\bin\CtxSvcHost.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles%\Citrix\HDX\bin\ctxgfx.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles%\Citrix\HDX\bin\picaSvc2.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles%\Citrix\HDX\bin\CpSvc.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\HDX\bin\WebSocketService.exe" -Force
    # Custom additions for Citrix Machine Creation Services
    Add-MpPreference -ExclusionPath "mcsdif.vhdx" -Force
    Add-MpPreference -ExclusionPath "%SystemRoot%\System32\drivers\CVhdFilter.sys" -Force

    # Set powercfg over-rides to get around screen lock issues - https://forums.ivanti.com/s/article/Screensaver-doesn-t-become-active-on-a-Citrix-Virtual-Desktop-Agent
    Execute-Process -Path "$envSystem32Directory\powercfg.exe" -Parameters "/requestsoverride PROCESS picaSessionAgent.exe DISPLAY"
    Execute-Process -Path "$envSystem32Directory\powercfg.exe" -Parameters "/requestsoverride PROCESS GFXMGR.exe DISPLAY"

    # Fix Screensaver not working - https://support.citrix.com/article/CTX205214/screensaver-not-working-in-xendesktop
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Citrix\Graphics" -Name "SetDisplayRequiredMode" -Value "0" -Type "DWord"

    # Registry optimizations

    # Enable Rendezvous v2 - https://docs.citrix.com/en-us/citrix-daas/hdx/rendezvous-protocol/rendezvous-v2.html
    If ((Get-RegistryKey -Key "HKLM:\SOFTWARE\Citrix\XenDesktopSetup" -Value "Rendezvous V2 Component") -eq "1")
    {
        Set-RegistryKey -Key "HKLM:\SOFTWARE\Citrix\VirtualDesktopAgent" -Name "GctRegistration" -Value "1" -Type "DWord"
    }

    # Reduce HDX bandwidth usage by up to 15% -https://www.citrix.com/blogs/2023/04/06/reduce-your-hdx-bandwidth-usage
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Citrix\GroupPolicy\Defaults\WDSettings" -Name "ReducerOverrideMask" -Value "23" -Type "DWord"

    # Enable new EDT congestion control - https://www.citrix.com/blogs/2023/04/25/turbo-charging-edt-for-unparalleled-experience-in-a-hybrid-world
    Set-RegistryKey -Key "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\icawd\Tds\udp\UDPStackParameters" -Name "edtBBR" -Value "1" -Type "DWord"

    # CVAD 2303 Users stuck on welcome screen when reconnecting to a disconnected session - https://support.citrix.com/article/CTX547782/cvad-2303-users-stuck-on-welcome-screen-when-reconnecting-to-a-disconnected-session
    #Set-RegistryKey -Key "HKLM:\SOFTWARE\Citrix\Graphics" -Name "PermitRunAsLocalSystem" -Value "1" -Type "DWord"

    # Go back to the parent folder
    Set-Location ..
    Remove-Folder -Path "$envTemp\Install"

    # Reboot and relaunch script
    Enable-AutoLogon -Password $localCredentialsPassword -LogonCount "1" -AsynchronousRunOnce -Command "$($PSHome)\powershell.exe -NoLogo -NoExit -NoProfile -WindowStyle Maximized -File `"$appScriptPath\$appScriptName`" -ExecutionPolicy ByPass"

    Write-Log -Message "$appVendor $appName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
    Write-Log -Message "A reboot is required after $appVendor $appName $appVersion installation!" -Severity 2 -LogType CMTrace -WriteHost $True
    Show-InstallationRestartPrompt -CountdownSeconds 30 -CountdownNoHideSeconds 30
}
ElseIf (($appVersion -gt $appInstalledVersion) -and (Test-Path -Path "$appScriptPath\$appCleanupTool"))
{
    # Fix an issue with Citrix Connection Quality Indicator
    If (Test-Path -Path "${env:ProgramFiles(x86)}\Citrix\HDX\bin\Connection Quality Indicator\Citrix.CQI.exe")
    {
        Write-Log -Message "Citrix Connection Quality Indicator must be uninstalled before the Virtual Delivery Agent installation, don't forget to REINSTALL it!" -Severity 2 -LogType CMTrace -WriteHost $True
        Get-Process -Name "CQISvc", "Citrix.CQI" | Stop-Process -Force
        Write-Log -Message "Uninstalling Citrix Connection Quality Indicator..." -Severity 1 -LogType CMTrace -WriteHost $True
        Remove-MSIApplications -Name "Citrix Connection Quality Indicator" -Exact
    }

    # Copy $appInstall to $envTemp\Install to avoid install issue
    Copy-File -Path ".\$appInstall" -Destination "$envTemp\Install" -Recurse
    Set-Location -Path "$envTemp\Install"

    # Uninstall previous versions
    Write-Log -Message "$appVendor $appName $appInstalledVersion must be uninstalled first." -Severity 2 -LogType CMTrace -WriteHost $True
    Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
    Get-Process -Name $appProcesses | Stop-Process -Force
    Execute-Process -Path $appUninstall -Parameters $appUninstallParameters -WaitForMsiExec -IgnoreExitCodes "3"

    # Run Citrix VDA CleanUp Utility
    Write-Log -Message "Running $appVendor VDA Cleanup Utility..." -Severity 1 -LogType CMTrace -WriteHost $True
    Execute-Process -Path "$appScriptPath\$appCleanupTool" -Parameters "$appCleanupToolParameters" -IgnoreExitCodes 1
    Write-Log -Message "$appVendor $appName $appVersion was uninstalled successfully!" -Severity 1 -LogType CMTrace -WriteHost $True

    # Reboot and relaunch script
    Enable-AutoLogon -Password $localCredentialsPassword -LogonCount "1" -AsynchronousRunOnce -Command "$($PSHome)\powershell.exe -NoLogo -NoExit -NoProfile -WindowStyle Maximized -File `"$appScriptPath\$appScriptName`" -ExecutionPolicy ByPass"
    Write-Log -Message "A reboot is required after $appVendor $appName $appVersion installation!" -Severity 2 -LogType CMTrace -WriteHost $True
    Show-InstallationRestartPrompt -CountdownSeconds 30 -CountdownNoHideSeconds 30
}
ElseIf ($appVersion -eq $appInstalledVersion)
{
    # Disable autologon
    Disable-AutoLogon
    Write-Log -Message "$appVendor $appName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}
Else
{
    Write-Log -Message "$appVendor $appName $appVersion EXE file and $appCleanupTool MUST BE DOWNLOADED MANUALLY FIRST!" -Severity 3 -LogType CMTrace -WriteHost $True
    Start-Process -FilePath "https://www.citrix.com/downloads/citrix-virtual-apps-and-desktops"
    Start-Sleep -Seconds 2
    Start-Process -FilePath "https://support.citrix.com/article/CTX209255/vda-cleanup-utility"

    # Disable autologon
    Disable-AutoLogon
    Exit-Script
}

#endregion