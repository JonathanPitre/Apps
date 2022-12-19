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
$Modules = @("PSADT") # Modules list

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
    Write-Host -Object "Importing $Module module..." -ForegroundColor Green

    # If module is imported say that and do nothing
    If (Get-Module | Where-Object { $_.Name -eq $Module })
    {
        Write-Host -Object "Module $Module is already imported." -ForegroundColor Green
    }
    Else
    {
        # If module is not imported, but available on disk then import
        If (Get-Module -ListAvailable | Where-Object { $_.Name -eq $Module })
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

# Get the current script directory
$appScriptDirectory = Get-ScriptDirectory

# Install and import modules list
Foreach ($Module in $Modules)
{
    Initialize-Module -Module $Module
}

#-----------------------------------------------------------[Functions]------------------------------------------------------------

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

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$appVendor = "Citrix"
$appName = "Workspace Environment Management Agent"
$appProcesses = @( "Citrix.Wem.Agent.Service", "Citrix.Wem.Agent.LogonService", "VUEMUIAgent", "VUEMAppCmd", "VUEMCmdAgent")
$appInstallParameters = "/quiet Cloud=0" # OnPrem 0 Cloud 1
$Evergreen = Get-CitrixWEMAgent
$appShortVersion = $Evergreen.Version
$appSetup = "Citrix Workspace Environment Management Agent.exe"
If (Test-Path -Path "$appScriptDirectory\$appShortVersion")
{
    $appVersion = Get-FileVersion -ProductVersion "$appScriptDirectory\$appShortVersion\$appSetup"
    Set-Location ..
    Rename-Item -Path "$appScriptDirectory\$appShortVersion" -NewName "$appScriptDirectory\$appVersion" -Force
    $appVersion = (Get-ChildItem $appScriptDirectory | Where-Object { $_.PSIsContainer } | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Select-Object -ExpandProperty Name)
}
Else
{
    $appVersion = (Get-ChildItem $appScriptDirectory | Where-Object { $_.PSIsContainer } | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Select-Object -ExpandProperty Name)

}
$appDestination = "${env:ProgramFiles(x86)}\Citrix\Workspace Environment Management Agent"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName")
$appInstalledVersion = ((Get-InstalledApplication -Name "$appVendor $appName").DisplayVersion) | Sort-Object -Descending | Select-Object -First 1

#-----------------------------------------------------------[Execution]------------------------------------------------------------

If ([version]$appVersion -gt [version]$appInstalledVersion)

{
    Set-Location -Path $appScriptDirectory
    Set-Location -Path $appVersion

    If (-Not(Test-Path -Path "$appScriptDirectory\$appVersion\$appSetup"))
    {
        Write-Log -Message "$appVendor $appName $appShortVersion MUST BE DOWNLOADED MANUALLY FIRST!" -Severity 3 -LogType CMTrace -WriteHost $True
        Start-Sleep -Seconds 5
        Exit-Script
    }
    Else
    {
        # Move the policy definitions files
        Copy-File -Path "$appScriptDirectory\$appVersion\Agent Group Policies\ADMX\*" -Destination "$appScriptDirectory\PolicyDefinitions" -Recurse
        Copy-File -Path "$appScriptDirectory\$appVersion\Configuration Templates" -Destination "$appScriptDirectory" -Recurse

        # Cleanup
        Remove-Folder -Path "$appScriptDirectory\$appVersion\Agent Group Policies"
        Remove-Folder -Path "$appScriptDirectory\$appVersion\Configuration Templates"
        Remove-File -Path "$appScriptDirectory\$appVersion\Citrix Workspace Environment Management Console.exe"
        Remove-File -Path "$appScriptDirectory\$appVersion\Citrix Workspace Environment Management Infrastructure Services.exe"

        # Get real file version
        $appVersion = Get-FileVersion -File "$appScriptDirectory\$appVersion\$appSetup"

        Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
        Get-Process -Name $appProcesses | Stop-Process -Force

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
Else
{
    Write-Log -Message "$appVendor $appName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}