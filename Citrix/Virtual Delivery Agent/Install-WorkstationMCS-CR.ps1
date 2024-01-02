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
        ElseIf ($MyInvocation.PSCommandPath) { Split-Path -Path $MyInvocation.PSCommandPath -Leaf } # Windows PowerShell
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
[int]$appVersion = (Get-CitrixVDA).Version
[string]$appInstall = "VDAWorkstationSetup_$appVersion.exe"
# Installation parameters available here - https://docs.citrix.com/en-us/citrix-virtual-apps-desktops/install-configure/install-command.html
# https://docs.citrix.com/en-us/citrix-virtual-apps-desktops/install-configure/install-vdas-sccm.html
[string]$appInstallParameters = '/components vda /disableexperiencemetrics /enable_hdx_ports /enable_hdx_udp_ports /enable_real_time_transport /enable_remote_assistance /enable_ss_ports /exclude "Citrix Personalization for App-V - VDA","Citrix VDA Upgrade Agent" /includeadditional "Citrix Profile Management","Citrix Profile Management WMI Plug-in","Citrix MCS IODriver","Citrix Rendezvous V2","Citrix Web Socket VDA Registration Tool" /mastermcsimage /noreboot /noresume /quiet /remove_appdisk_ack /remove_pvd_ack /xendesktopcloud'
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
[bool]$enableCitrixUviProcessesExclusions = $true
[array]$citrixUviProcessesToAdd = @("sppsvc.exe", "RAserver.exe", "SelfService.exe", "CtxWebBrowser.exe", "Receiver.exe", "msedge.exe", "msedgewebview2.exe", "AcroCef.exe", "RdrCEF.exe", "QtWebEngineProcess.exe")
[bool]$enableCitrixVirtualSmartCard = $false # Set to $true if you need Smart Card support

#endregion

#-----------------------------------------------------------[Execution]------------------------------------------------------------

#region Execution

# Disable automatic logon at next reboot to avoid powershell from automatically launching after the VDA installation
$regRunOnceValue = Get-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Value "(default)"
If ((-Not [string]::IsNullOrEmpty($regRunOnceValue)))
{
    Disable-AutoLogon
}

# Get current account credentials
[bool]$isLocalCredentialStored = [bool](Find-Credential -Filter "*$envUserName")
If ($isLocalCredentialStored)
{
    Write-Host -Object "Stored credentials found for current account." -ForegroundColor Green
    $localCredentials = (BetterCredentials\Get-Credential -UserName $env:USERNAME -Store)
    $localCredentialsUserName = $localCredentials.UserName
    $localCredentialsPassword = $localCredentials.Password
}
Else
{
    Write-Host -Object "Please enter your current account credentials." -ForegroundColor Green
    $null = BetterCredentials\Get-Credential -UserName $env:USERNAME -Store
    $localCredentials = (BetterCredentials\Get-Credential -UserName $env:USERNAME -Store)
    $localCredentialsUserName = $localCredentials.UserName
    $localCredentialsPassword = $localCredentials.Password
}

Set-Location -Path $appScriptPath
If (-Not(Test-Path -Path $appVersion)) { New-Folder -Path $appVersion }
Set-Location -Path $appVersion

# VDA new installation
If (($isAppInstalled -eq $false) -and (Test-Path -Path "$appScriptPath\$appVersion\$appInstall") -and (Test-Path -Path "$appScriptPath\$appCleanupTool"))
{
    # Detect if running from a Citrix session
    If ($sessionName -like "*ica*")
    {
        Write-Log -Message "$appVendor $appName CANNOT BE INSTALLED from a Citrix session, please run the installation from a CONSOLE SESSION!" -Severity 3 -LogType CMTrace -WriteHost $True
        Exit-Script
    }

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
    #Write-Log -Message "Running $appVendor VDA Cleanup Utility..." -Severity 1 -LogType CMTrace -WriteHost $True
    # Delete previous logs
    #Remove-Folder -Path "$env:Temp\Citrix\VdaCleanup" -Recurse
    #Execute-Process -Path "$appScriptPath\$appCleanupTool" -Parameters "$appCleanupToolParameters" -IgnoreExitCodes 1
    #Write-Log -Message "$appVendor $appName $appVersion was uninstalled successfully!" -Severity 1 -LogType CMTrace -WriteHost $True

    # Copy $appInstall to $envTemp\Install to avoid install issue
    Copy-File -Path ".\$appInstall" -Destination "$envTemp\Install" -Recurse
    Set-Location -Path "$envTemp\Install"

    # Install latest version
    Write-Log -Message "Installing $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    # Delete previous logs
    Remove-Folder -Path "$env:Temp\Citrix\XenDesktop Installer" -Recurse
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

    # Reduce HDX bandwidth usage by up to 15% - https://www.citrix.com/blogs/2023/04/06/reduce-your-hdx-bandwidth-usage
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Citrix\GroupPolicy\Defaults\WDSettings" -Name "ReducerOverrideMask" -Value "23" -Type "DWord"

    # Enable new EDT congestion control - https://www.citrix.com/blogs/2023/04/25/turbo-charging-edt-for-unparalleled-experience-in-a-hybrid-world
    Set-RegistryKey -Key "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\icawd\Tds\udp\UDPStackParameters" -Name "edtBBR" -Value "1" -Type "DWord"

    # Enable support for EDT Lossy protocol - https://docs.citrix.com/en-us/citrix-workspace-app-for-windows/ear.html
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Citrix\Audio" -Name "EdtUnreliableAllowed" -Value "1" -Type "DWord"
    # Citrix  utilises Kernel APC Hooking as a replacement of AppInit_DLLs.
    # The KAPC Hooking DLL Injection Driver (CtxUvi) verifies that the hook DLLs configuration in the
    # registry is not changed at runtime (i.e. HKLM\SOFTWARE\Citrix\CtxHook\AppInit_DLLs\<hook name>).
    # If a change to the configuration is detected, the CtxUvi driver disables itself until the next
    # reboot, resulting in none of the Citrix Hooks being properly loaded. So it is recommended NOT to
    # use Group Policies to control these registry keys and placing them in the master PVS/MCS image.

    # References:
    # - https://support.citrix.com/article/CTX220418
    # - https://support.citrix.com/article/CTX226605
    # - https://support.citrix.com/article/CTX223973

    If ($enableCitrixUviProcessesExclusions)
    {
        # Prevent the CtxUvi Driver disabling
        Set-RegistryKey -Key "HKLM:\SYSTEM\CurrentControlSet\Services\CtxUvi" -Name "UviStatusDisabled" -Value "0" -Type DWord
        Set-RegistryKey -Key "HKLM:\SYSTEM\CurrentControlSet\Services\CtxUvi" -Name "UviEnabled" -Value "1" -Type DWord

        # Add a list of processes to the UviProcesExcludes registry value under the HKLM:\System\CurrentControlSet\Services\CtxUvi
        # Add the full process here, but the code will only add the first 14 characters to the UviProcesExcludes registry value
        try
        {
            If ($null -ne (Get-RegistryKey -Key "HKLM:\SYSTEM\CurrentControlSet\Services\CtxUvi" -Value "UviProcessExcludes"))
            {
                $UviProcessExcludes = (Get-RegistryKey -Key "HKLM:\SYSTEM\CurrentControlSet\Services\CtxUvi" -Value "UviProcessExcludes")
            }
        }
        catch
        {
            #
        }
        [bool]$AddUviProcessExcludes = $false
        Write-Verbose "Checking the UviProcessExcludes value..." -Verbose
        If (-Not([string]::IsNullOrEmpty($UviProcessExcludes)))
        {
            Write-Verbose "- The current values are: `"$UviProcessExcludes`"" -Verbose
            ForEach ($citrixUviProcessToAdd in $citrixUviProcessesToAdd)
            {
                If ($citrixUviProcessToAdd.Length -gt 14)
                {
                    $citrixUviProcessToAdd = $citrixUviProcessToAdd.SubString(0, 14)
                }
                If ($UviProcessExcludes -like "*$citrixUviProcessToAdd*")
                {
                    Write-Verbose "- The $citrixUviProcessToAdd process has already been added" -Verbose
                }
                Else
                {
                    Write-Verbose "- The $citrixUviProcessToAdd process is being added to the string" -Verbose
                    $UviProcessExcludes = $UviProcessExcludes + $citrixUviProcessToAdd + ";"
                    $AddUviProcessExcludes = $True
                }
            }
        }
        Else
        {
            ForEach ($citrixUviProcessToAdd in $citrixUviProcessesToAdd)
            {
                If ($citrixUviProcessToAdd.Length -gt 14)
                {
                    $citrixUviProcessToAdd = $citrixUviProcessToAdd.SubString(0, 14)
                }
                $AddUviProcessExcludes = $True
                If ([String]::IsNullOrEmpty($UviProcessExcludes))
                {
                    $UviProcessExcludes = $citrixUviProcessToAdd + ";"
                }
                Else
                {
                    $UviProcessExcludes = $UviProcessExcludes + $citrixUviProcessToAdd + ";"
                }
            }
        }
        If ($AddUviProcessExcludes)
        {
            Write-Verbose "- Setting the new values: `"$UviProcessExcludes`"" -Verbose
            Set-RegistryKey -Key "HKLM:\SYSTEM\CurrentControlSet\Services\CtxUvi" -Name "UviProcessExcludes" -Value "$UviProcessExcludes" -Type String
        }
    }

    # Disable Citrix Virtual Smart Card process
    If ($enableCitrixVirtualSmartCard -eq $false)
    {
        # "C:\Program Files\Citrix\Virtual Smart Card\Citrix.Authentication.VirtualSmartcard.Launcher.exe"
        Remove-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Citrix Virtual Smart Card"
    }

    # Delete logs and cache files
    Remove-File -Path "$env:ProgramData\Citrix\TelemetryService\CitrixAOT\*.etl"
    Remove-File -Path "$env:ProgramData\Citrix\Citrix\VdaCEIP\*.json"
    Remove-File -Path "$env:ProgramData\Citrix\Logs\*.log"
    Remove-File -Path "$env:ProgramData\Citrix\GroupPolicy\*.*"
    Remove-File -Path "$env:ProgramData\CitrixCseCache\*.*"
    Remove-File -Path "$env:SystemRoot\System32\GroupPolicy\Machine\Citrix\GroupPolicy\*.*"
    Remove-File -Path "$env:SystemRoot\System32\GroupPolicy\User\Citrix\GroupPolicy\*.*"

    # Go back to the parent folder
    Set-Location ..
    Remove-Folder -Path "$envTemp\Install"

    # Set back previous runonce value
    If ((-Not [string]::IsNullOrEmpty($regRunOnceValue)))
    {
        Enable-AutoLogon -Password $localCredentialsPassword -AsynchronousRunOnce
        Set-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Name "(Default)" -Value $regRunOnceValue
    }

    # Verify Citrix Service
    If (Test-ServiceExists -Name "BrokerAgent")
    {
        Write-Log -Message "$appVendor $appName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
    }
    Else
    {
        Write-Log -Message "$appVendor $appName $appVersion installation FAILLED!" -Severity 3 -LogType CMTrace -WriteHost $True
        Start-Sleep -Seconds 5
    }

    # Reboot
    Write-Log -Message "A reboot is required after $appVendor $appName $appVersion installation!" -Severity 2 -LogType CMTrace -WriteHost $True
    Show-InstallationRestartPrompt -CountdownSeconds 10 -CountdownNoHideSeconds 10
}
# VDA in-place update
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

    # Uninstall previous versions
    Write-Log -Message "$appVendor $appName $appInstalledVersion must be uninstalled first." -Severity 2 -LogType CMTrace -WriteHost $True
    Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
    Get-Process -Name $appProcesses | Stop-Process -Force
    Execute-Process -Path $appUninstall -Parameters $appUninstallParameters -WaitForMsiExec -IgnoreExitCodes "3"

    # Run Citrix VDA CleanUp Utility
    #Write-Log -Message "Running $appVendor VDA Cleanup Utility..." -Severity 1 -LogType CMTrace -WriteHost $True
    # Delete previous logs
    #Remove-Folder -Path "$env:Temp\Citrix\VdaCleanup" -Recurse
    #Execute-Process -Path "$appScriptPath\$appCleanupTool" -Parameters "$appCleanupToolParameters" -IgnoreExitCodes 1
    #Write-Log -Message "$appVendor $appName $appVersion was uninstalled successfully!" -Severity 1 -LogType CMTrace -WriteHost $True

    # Reboot and relaunch script
    If ([string]::IsNullOrEmpty($regRunOnceValue))
    {
        Enable-AutoLogon -Password $localCredentialsPassword -LogonCount "1" -AsynchronousRunOnce -Command "$($PSHome)\powershell.exe -NoLogo -NoExit -NoProfile -WindowStyle Maximized -File `"$appScriptPath\$appScriptName`" -ExecutionPolicy ByPass"
    }
    Else
    {
        Enable-AutoLogon -Password $localCredentialsPassword -LogonCount "1" -AsynchronousRunOnce -Command $regRunOnceValue
    }

    Write-Log -Message "A reboot is required to complete $appVendor $appName $appVersion uninstallation! This script will be automatically relaunch next startup." -Severity 2 -LogType CMTrace -WriteHost $True
    Show-InstallationRestartPrompt -CountdownSeconds 10 -CountdownNoHideSeconds 10
}
# VDA is already installed
ElseIf ($appVersion -eq $appInstalledVersion)
{
    # Test Citrix Service
    If (Test-ServiceExists -Name "BrokerAgent")
    {
        Write-Log -Message "$appVendor $appName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
    }
    Else
    {
        Write-Log -Message "$appVendor $appName $appVersion installation FAILLED!" -Severity 3 -LogType CMTrace -WriteHost $True
        Start-Sleep -Seconds 5
        # Run Citrix VDA CleanUp Utility
        Write-Log -Message "Running $appVendor VDA Cleanup Utility..." -Severity 1 -LogType CMTrace -WriteHost $True
        # Delete previous logs
        Remove-Folder -Path "$env:Temp\Citrix\VdaCleanup" -Recurse
        Execute-Process -Path "$appScriptPath\$appCleanupTool" -Parameters "$appCleanupToolParameters" -IgnoreExitCodes 1
        Write-Log -Message "$appVendor $appName $appVersion was uninstalled successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
        # Reboot and relaunch script
        If ([string]::IsNullOrEmpty($regRunOnceValue))
        {
            Enable-AutoLogon -Password $localCredentialsPassword -LogonCount "1" -AsynchronousRunOnce -Command "$($PSHome)\powershell.exe -NoLogo -NoExit -NoProfile -WindowStyle Maximized -File `"$appScriptPath\$appScriptName`" -ExecutionPolicy ByPass"
        }
        Else
        {
            Enable-AutoLogon -Password $localCredentialsPassword -LogonCount "1" -AsynchronousRunOnce -Command $regRunOnceValue
        }

        Write-Log -Message "A reboot is required to relaunch $appVendor $appName $appVersion installation!" -Severity 2 -LogType CMTrace -WriteHost $True
        Show-InstallationRestartPrompt -CountdownSeconds 10 -CountdownNoHideSeconds 10
    }
}
Else
{
    Write-Log -Message "$appVendor $appName $appVersion EXE file and $appCleanupTool MUST BE DOWNLOADED MANUALLY FIRST!" -Severity 3 -LogType CMTrace -WriteHost $True
    Start-Process -FilePath "https://www.citrix.com/downloads/citrix-virtual-apps-and-desktops"
    Start-Sleep -Seconds 2
    Start-Process -FilePath "https://support.citrix.com/article/CTX209255/vda-cleanup-utility"
}

#endregion