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
$Modules = @("PSADT", "Evergreen") # Modules list

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
        If ( [boolean](Get-Module -ListAvailable | Where-Object { $_.Name -eq $Module }) )

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
                EXIT 1
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

Function Get-CitrixWEMAgent
{
    [OutputType([System.Management.Automation.PSObject])]
    [CmdletBinding()]
    Param ()
    $DownloadURL = "https://docs.citrix.com/en-us/workspace-environment-management/current-release/whats-new.html"

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
        $RegEx = "(What’s new in )(\d{4})"
        $Version = ($DownloadText | Select-String -Pattern $RegEx).Matches.Groups[2].Value

        if ($Version)
        {
            [PSCustomObject]@{
                Name    = 'Citrix Workspace Environment Agent'
                Version = $Version
            }
        }

    }
}

#endregion

#----------------------------------------------------------[Declarations]----------------------------------------------------------

[string]$appVendor = "Citrix"
[string]$appName = "Workspace Environment Management Agent"
$appProcesses = @( "Citrix.Wem.Agent.Service", "Citrix.Wem.Agent.LogonService", "VUEMUIAgent", "VUEMAppCmd", "VUEMCmdAgent")
$appInstallParameters = "/quiet Cloud=0" # OnPrem 0 Cloud 1
$Evergreen = Get-CitrixWEMAgent
[string]$appShortVersion = $Evergreen.Version
[string]$appSetup = "Citrix Workspace Environment Management Agent.exe"
If (Test-Path -Path "$appScriptPath\$appShortVersion\$appSetup")
{
    $appVersion = Get-FileVersion -ProductVersion "$appScriptPath\$appShortVersion\$appSetup"
    Set-Location ..
    Rename-Item -Path "$appScriptPath\$appShortVersion" -NewName "$appScriptPath\$appVersion" -Force
    $appVersion = (Get-ChildItem -Path $appScriptPath -Directory | Where-Object { $_.Name -match "^\d+?" } | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Select-Object -ExpandProperty Name)
}
Else
{
    $appVersion = (Get-ChildItem -Path $appScriptPath -Directory | Where-Object { $_.Name -match "^\d+?" } | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Select-Object -ExpandProperty Name)
}
$appDestination = "${env:ProgramFiles(x86)}\Citrix\Workspace Environment Management Agent"
[boolean]$isAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName")
$appInstalledVersion = ((Get-InstalledApplication -Name "$appVendor $appName").DisplayVersion) | Sort-Object -Descending | Select-Object -First 1
[string]$appInstalledFile = (Test-Path -Path "$appDestination\Citrix.Wem.Agent.Service.exe")
[string]$appUninstallString = (Get-InstalledApplication -Name "$appVendor $appName").UninstallString
[string]$appUninstall = ($appUninstallString).Split("/")[0].Trim().Trim("""")
[string]$appUninstallParameters = "/uninstall /quiet /noreboot"

#-----------------------------------------------------------[Execution]------------------------------------------------------------

Set-Location -Path $appScriptPath
Set-Location -Path $appVersion

If (($isAppInstalled -eq $false) -or ([version]$appVersion -gt [version]$appInstalledVersion))
{
    If (-Not(Test-Path -Path "$appScriptPath\$appVersion\$appSetup"))
    {
        Write-Log -Message "$appVendor $appName $appShortVersion MUST BE DOWNLOADED MANUALLY FIRST!" -Severity 3 -LogType CMTrace -WriteHost $True
        Start-Process -FilePath "https://www.citrix.com/downloads/citrix-virtual-apps-and-desktops"
        Exit-Script
    }
    Else
    {
        # Move the policy definitions files
        If (Test-Path -Path "$appScriptPath\$appVersion\Agent Group Policies\ADMX")
        {
            Copy-File -Path "$appScriptPath\$appVersion\Agent Group Policies\ADMX\*" -Destination "$appScriptPath\PolicyDefinitions" -Recurse
            Copy-File -Path "$appScriptPath\$appVersion\Configuration Templates" -Destination "$appScriptPath" -Recurse
        }

        # Cleanup
        Remove-Folder -Path "$appScriptPath\$appVersion\Agent Group Policies"
        Remove-Folder -Path "$appScriptPath\$appVersion\Configuration Templates"
        Remove-File -Path "$appScriptPath\$appVersion\Citrix Workspace Environment Management Console.exe"
        Remove-File -Path "$appScriptPath\$appVersion\Citrix Workspace Environment Management Infrastructure Services.exe"

        # Get real file version
        $appVersion = Get-FileVersion -File "$appScriptPath\$appVersion\$appSetup"

        # Uninstall previous versions
        If ($appInstalledFile)
        {
            Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
            Get-Process -Name $appProcesses | Stop-Process -Force
            Execute-Process -Path $appUninstall -Parameters $appUninstallParameters -WaitForMsiExec -IgnoreExitCodes "3"
        }

        # Install latest version
        Write-Log -Message "Installing $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Execute-Process -Path ".\$appSetup" -Parameters $appInstallParameters

        Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

        # Add Windows Defender exclusion(s) - https://docs.citrix.com/en-us/tech-zone/build/tech-papers/antivirus-best-practices.html
        Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\AgentGroupPolicyUtility.exe.exe" -Force
        Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\Citrix.Wem.Agent.LogonService.exe" -Force
        Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\Citrix.Wem.Agent.Service.exe" -Force
        Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\VUEMCmdAgent.exe" -Force
        Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\VUEMUIAgent.exe" -Force

        # Configure application shortcut
        New-Shortcut -Path "$envCommonStartMenuPrograms\Administrative Tools\$appVendor WEM Agent Log Parser.lnk" -TargetPath "$appDestination\Agent Log Parser.exe"
        New-Shortcut -Path "$envCommonStartMenuPrograms\Administrative Tools\$appVendor WEM Resultant Actions Viewer.lnk" -TargetPath "$appDestination\VUEMRSAV.exe"
        New-Shortcut -Path "$envCommonStartMenuPrograms\Administrative Tools\$appVendor WEM Application Info Viewer.lnk" -TargetPath "$appDestination\AppInfoViewer.exe"
        New-Shortcut -Path "$envCommonStartMenuPrograms\Administrative Tools\$appVendor WEM Manage Applications.lnk" -TargetPath "$appDestination\AppsMgmtUtil.exe"
        New-Shortcut -Path "$envCommonStartMenuPrograms\Administrative Tools\$appVendor WEM Manage Printers.lnk" -TargetPath "$appDestination\PrnsMgmtUtil.exe"
        Remove-File -Path "$envCommonStartMenuPrograms\$appVendor\WEM Enrollment Registration Utility.lnk" -ContinueOnError $True
        New-Shortcut -Path "$envCommonStartMenuPrograms\Administrative Tools\$appVendor WEM Enrollment Registration Utility.lnk" -TargetPath "$appDestination\Citrix.Wem.Agent.Enrollment.RegUtility.exe"

        Write-Log -Message "$appVendor $appName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
    }
}
ElseIf (([version]$appVersion -eq [version]$appInstalledVersion) -and ($appInstalledFile -eq $false))
{
    Write-Log -Message "$appVendor $appName $appInstalledVersion installation is broken. It will now be reinstalled!" -Severity 2 -LogType CMTrace -WriteHost $True

    # Detect if setup file is present
    If (-Not(Test-Path -Path "$appScriptPath\$appVersion\$appSetup"))
    {
        Write-Log -Message "$appVendor $appName $appShortVersion MUST BE DOWNLOADED MANUALLY FIRST!" -Severity 3 -LogType CMTrace -WriteHost $True
        Start-Process -FilePath "https://www.citrix.com/downloads/citrix-virtual-apps-and-desktops"
        Exit-Script
    }
    Else
    {
        # Move the policy definitions files
        If (Test-Path -Path "$appScriptPath\$appVersion\Agent Group Policies\ADMX")
        {
            Copy-File -Path "$appScriptPath\$appVersion\Agent Group Policies\ADMX\*" -Destination "$appScriptPath\PolicyDefinitions" -Recurse
            Copy-File -Path "$appScriptPath\$appVersion\Configuration Templates" -Destination "$appScriptPath" -Recurse
        }

        # Cleanup
        Remove-Folder -Path "$appScriptPath\$appVersion\Agent Group Policies"
        Remove-Folder -Path "$appScriptPath\$appVersion\Configuration Templates"
        Remove-File -Path "$appScriptPath\$appVersion\Citrix Workspace Environment Management Console.exe"
        Remove-File -Path "$appScriptPath\$appVersion\Citrix Workspace Environment Management Infrastructure Services.exe"

        # Get real file version
        $appVersion = Get-FileVersion -File "$appScriptPath\$appVersion\$appSetup"

        # Uninstall previous versions
        If ($appInstalledFile)
        {
            Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
            Get-Process -Name $appProcesses | Stop-Process -Force
            Execute-Process -Path $appUninstall -Parameters $appUninstallParameters -WaitForMsiExec -IgnoreExitCodes "3"
        }

        # Install latest version
        Write-Log -Message "Installing $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Execute-Process -Path ".\$appSetup" -Parameters $appInstallParameters

        Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

        # Add Windows Defender exclusion(s) - https://docs.citrix.com/en-us/tech-zone/build/tech-papers/antivirus-best-practices.html
        Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\AgentGroupPolicyUtility.exe.exe" -Force
        Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\Citrix.Wem.Agent.LogonService.exe" -Force
        Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\Citrix.Wem.Agent.Service.exe" -Force
        Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\VUEMCmdAgent.exe" -Force
        Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\VUEMUIAgent.exe" -Force

        # Configure application shortcut
        New-Shortcut -Path "$envCommonStartMenuPrograms\Administrative Tools\$appVendor WEM Agent Log Parser.lnk" -TargetPath "$appDestination\Agent Log Parser.exe"
        New-Shortcut -Path "$envCommonStartMenuPrograms\Administrative Tools\$appVendor WEM Resultant Actions Viewer.lnk" -TargetPath "$appDestination\VUEMRSAV.exe"
        New-Shortcut -Path "$envCommonStartMenuPrograms\Administrative Tools\$appVendor WEM Application Info Viewer.lnk" -TargetPath "$appDestination\AppInfoViewer.exe"
        New-Shortcut -Path "$envCommonStartMenuPrograms\Administrative Tools\$appVendor WEM Manage Applications.lnk" -TargetPath "$appDestination\AppsMgmtUtil.exe"
        New-Shortcut -Path "$envCommonStartMenuPrograms\Administrative Tools\$appVendor WEM Manage Printers.lnk" -TargetPath "$appDestination\PrnsMgmtUtil.exe"
        Remove-File -Path "$envCommonStartMenuPrograms\$appVendor\WEM Enrollment Registration Utility.lnk" -ContinueOnError $True
        New-Shortcut -Path "$envCommonStartMenuPrograms\Administrative Tools\$appVendor WEM Enrollment Registration Utility.lnk" -TargetPath "$appDestination\Citrix.Wem.Agent.Enrollment.RegUtility.exe"

        Write-Log -Message "$appVendor $appName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
    }
}
ElseIf (([version]$appVersion -eq [version]$appInstalledVersion) -and ($appInstalledFile -eq $true))
{
    Write-Log -Message "$appVendor $appName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}