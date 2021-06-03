# Standalone application install script for VDI environment - (C)2021 Jonathan Pitre & Owen Reynolds, inspired by xenappblog.com

#Requires -Version 5.1
#Requires -RunAsAdministrator

# Custom package providers list
$PackageProviders = @("Nuget")

# Custom modules list
$Modules = @("PSADT", "Nevergreen")

Write-Verbose -Message "Importing custom modules..." -Verbose

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials

# Install custom package providers list
Foreach ($PackageProvider in $PackageProviders)
{
    If (-not(Get-PackageProvider -ListAvailable -Name $PackageProvider -ErrorAction SilentlyContinue))
    {
        Install-PackageProvider -Name $PackageProvider -Force
    }
}

# Add the Powershell Gallery as trusted repository
Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted

# Update PowerShellGet
$InstalledPSGetVersion = (Get-PackageProvider -Name PowerShellGet).Version
$PSGetVersion = [version](Find-PackageProvider -Name PowerShellGet).Version
If ($PSGetVersion -gt $InstalledPSGetVersion)
{
    Install-PackageProvider -Name PowerShellGet -Force
}

# Install and import custom modules list
Foreach ($Module in $Modules)
{
    If (-not(Get-Module -ListAvailable -Name $Module))
    {
        Install-Module -Name $Module -AllowClobber -Force | Import-Module -Name $Module -Force
    }
    Else
    {
        $InstalledModuleVersion = (Get-InstalledModule -Name $Module).Version
        $ModuleVersion = (Find-Module -Name $Module).Version
        $ModulePath = (Get-InstalledModule -Name $Module).InstalledLocation
        $ModulePath = (Get-Item -Path $ModulePath).Parent.FullName
        If ([version]$ModuleVersion -gt [version]$InstalledModuleVersion)
        {
            Update-Module -Name $Module -Force
            Remove-Item -Path $ModulePath\$InstalledModuleVersion -Force -Recurse
        }
    }
}

Write-Verbose -Message "Custom modules were successfully imported!" -Verbose

# Get the current script directory
Function Get-ScriptDirectory
{
    Remove-Variable appScriptDirectory
    Try
    {
        If ($psEditor)
        {
            Split-Path $psEditor.GetEditorContext().CurrentFile.Path
        } # Visual Studio Code Host
        ElseIf ($psISE)
        {
            Split-Path $psISE.CurrentFile.FullPath
        } # Windows PowerShell ISE Host
        ElseIf ($PSScriptRoot)
        {
            $PSScriptRoot
        } # Windows PowerShell 3.0-5.1
        Else
        {
            Write-Host -ForegroundColor Red "Cannot resolve script file's path"
            Exit 1
        }
    }
    Catch
    {
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

Function Get-MicrosoftTeams
{
    <#
    .NOTES
        Author: Jonathan Pitre
        Twitter: @PitreJonathan
    #>
    [OutputType([System.Management.Automation.PSObject])]
    [CmdletBinding()]
    Param()
    $DownloadURL = "https://github.com/ItzLevvie/MicrosoftTeams-msinternal/blob/master/defconfig"
    Try
    {
        $DownloadText = (Invoke-WebRequest -Uri $DownloadURL -UseBasicParsing).Content
    }
    Catch
    {
        Throw "Failed to connect to URL: $DownloadURL with error $_."
        Break
    }
    Finally
    {
        $Rings = @('Continuous Deployment', 'Exploration', 'Preview', 'Production')
        $Architectures = @('x64', 'x86', 'Arm64')
        $Types = @('Exe', 'Msi')
        ForEach ($Ring in $Rings)
        {
            ForEach ($Architecture in $Architectures)
            {
                ForEach ($Type in $Types)
                {
                    $RegEx = "$Ring(.*?|\n)*?((?:\d+\.)+\d+).+win-$Architecture.+(http.+\.$Type)"
                    If ($DownloadText -match $RegEx)
                    {
                        [PSCustomObject]@{
                            Version      = $Matches[2]
                            Ring         = $Ring
                            Architecture = $Architecture
                            Type         = $Type
                            URI          = $Matches[3]
                        }
                    }
                    Else
                    {
                        Write-Warning -Debug "No match found for Microsoft Teams $Ring $Architecture $Type"
                    }

                }
            }
        }
    }
}

$appVendor = "Microsoft"
$appName = "Teams"
$appProcesses = @("Teams", "Update", "Squirrel", "Outlook")
$appTransformURL = "https://github.com/JonathanPitre/Apps/raw/master/Microsoft/Teams/Teams.mst"
$appTransform = Split-Path -Path $appTransformURL -Leaf
$appInstallParameters = "/QB"
$appAddParameters = "ALLUSER=1 ALLUSERS=1"
$Nevergreen = Get-MicrosoftTeams | Where-Object {$_.Ring -eq "Preview" -and $_.Architecture -eq "x64" -and $_.Type -eq "Msi"}
$appVersion = $Nevergreen.Version
$appURL = $Nevergreen.URI
$appSetup = Split-Path -Path $appURL -Leaf
$appDestination = "${env:ProgramFiles(x86)}\Microsoft\Teams\current"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName")
$appInstalledVersion = If ($IsAppInstalled) { Get-FileVersion $appDestination\Teams.exe }
##*===============================================

If ([version]$appVersion -gt [version]$appInstalledVersion)
{
    Set-Location -Path $appScriptDirectory
    If (-Not(Test-Path -Path $appVersion))
    {
        New-Folder -Path $appVersion
    }
    Set-Location -Path $appVersion

    # Uninstall previous versions
    Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
    Get-Process -Name $appProcesses | Stop-Process -Force

    # Remove machine-wide install
    Remove-MSIApplications -Name "$appVendor $appName" -Parameters $appInstallParameters -ContinueOnError $True
    Remove-MSIApplications -Name "$appName Machine-Wide Installer" -Parameters $appInstallParameters -ContinueOnError $True

    # Delete left over reg keys
    Remove-RegistryKey -Key "HKCR:\CLSID\{00425F68-FFC1-445F-8EDF-EF78B84BA1C7}" -Recurse -ContinueOnError $True
    Remove-RegistryKey -Key "HKCR:\WOW6432Node\CLSID\{00425F68-FFC1-445F-8EDF-EF78B84BA1C7}" -Recurse -ContinueOnError $True

    # Remove user install
    $TeamsUsers = Get-ChildItem -Path "$($env:SystemDrive)\Users"
    $TeamsUsers | ForEach-Object {
        Try
        {
            If (Test-Path "$($env:SystemDrive)\Users\$($_.Name)\AppData\Local\$appVendor\$appName\Update.exe")
            {
                Remove-Folder -Path "$($env:SystemDrive)\Users\$($_.Name)\AppData\Local\$appVendor\$appName" -ContinueOnError $True
                Remove-Folder -Path "$($env:SystemDrive)\Users\$($_.Name)\AppData\Local\SquirrelTemp" -ContinueOnError $True
                Remove-Folder -Path "$($env:SystemDrive)\Users\$($_.Name)\AppData\Local\$($appName)MeetingAddin" -ContinueOnError $True
                Remove-Folder -Path "$($env:SystemDrive)\Users\$($_.Name)\AppData\Local\$($appName)PresenceAddin" -ContinueOnError $True
                Remove-Folder -Path "$($env:SystemDrive)\Users\$($_.Name)\AppData\Local\SquirrelTemp" -ContinueOnError $True
                Remove-Folder -Path "$($env:SystemDrive)\Users\$($_.Name)\AppData\Roaming\$appVendor\$appName" -ContinueOnError $True
                Remove-File -Path "$($env:SystemDrive)\Users\$($_.Name)\AppData\Roaming\$appVendor\Windows\Start Menu\Programs\$appVendor Corporation\$appVendor $appName.lnk" -ContinueOnError $True
                Remove-File -Path "$($env:SystemDrive)\Users\$($_.Name)\AppData\Roaming\$appVendor\Windows\Start Menu\Programs\$appVendor $appName.lnk" -ContinueOnError $True
                Remove-File -Path "$($env:SystemDrive)\Users\$($_.Name)\Desktop\$appVendor $appName.lnk" -ContinueOnError $True
            }
        }
        Catch
        {
            Out-Null
        }
    }

    # Remove Teams registry entries from all user profiles - https://www.reddit.com/r/MicrosoftTeams/comments/gbq8rg/what_prevents_teams_from_reinstalling_or_how_to
    [scriptblock]$HKCURegistrySettings = {
        Remove-RegistryKey -Key "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Teams" -Recurse -ContinueOnError $True -SID $UserProfile.SID
        Remove-RegistryKey -Key "HKCU:\Software\Microsoft\Microsoft\Office\Teams" -Recurse -ContinueOnError $True -SID $UserProfile.SID
    }
    Invoke-HKCURegistrySettingsForAllUsers -RegistrySettings $HKCURegistrySettings

    # Download latest setup file(s)
    If (-Not(Test-Path -Path $appScriptDirectory\$appVersion\$appSetup))
    {
        Write-Log -Message "Downloading $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURL -OutFile $appSetup
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Download required transform file
    If (-Not(Test-Path -Path $appScriptDirectory\$appTransform))
    {
        Write-Log -Message "Downloading $appVendor $appName Transform.." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appTransformURL -OutFile $appScriptDirectory\$appTransform
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Install latest version
    Write-Log -Message "Installing $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    # Required if not using the custom MST
    #New-Item -Path "HKLM:\SOFTWARE\Citrix" -Name "PortICA" -Force
    Execute-MSI -Action Install -Path $appSetup -Parameters $appInstallParameters -AddParameters $appAddParameters -Transform "$appScriptDirectory\$appTransform"

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

    # Remove unneeded applications from running at start-up
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" -Name "TeamsMachineUninstallerLocalAppData" -ContinueOnError $True
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" -Name "TeamsMachineUninstallerProgramData" -ContinueOnError $True
    # Uncomment to disable Teams auto-startup
    #Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" -Name $appName -ContinueOnError $True

    # Fix application Start Menu shorcut
    Copy-File -Path "$envCommonStartMenuPrograms\$appVendor $appName.lnk" -Destination "$envCommonStartMenuPrograms\$appName.lnk" -ContinueFileCopyOnError $True
    Remove-File -Path "$envCommonStartMenuPrograms\$appVendor $appName.lnk" -ContinueOnError $True
    Remove-Folder -Path "$envCommonStartMenuPrograms\$appVendor Corporation" -ContinueOnError $True

    # Register Teams add-in for Outlook - https://microsoftteams.uservoice.com/forums/555103-public/suggestions/38846044-fix-the-teams-meeting-addin-for-outlook
    $appDLLs = (Get-ChildItem -Path "$envProgramFilesX86\Microsoft\TeamsMeetingAddin" -Include "Microsoft.Teams.AddinLoader.dll" -Recurse).FullName
    $appX64DLL = $appDLLs[0]
    $appX86DLL = $appDLLs[1]
    Execute-Process -Path "$envWinDir\SysWOW64\regsvr32.exe" -Parameters "/s /n /i:user `"$appX64DLL`"" -ContinueOnError $True
    Execute-Process -Path "$envWinDir\SysWOW64\regsvr32.exe" -Parameters "/s /n /i:user `"$appX86DLL`"" -ContinueOnError $True

    # Register Teams as the chat app for Office
    Set-RegistryKey -Key "HKLM:\SOFTWARE\IM Providers\Teams" -Name "FriendlyName" -Type "String" -Value "Microsoft Teams"
    Set-RegistryKey -Key "HKLM:\SOFTWARE\IM Providers\Teams" -Name "GUID" -Type "String" -Value "{00425F68-FFC1-445F-8EDF-EF78B84BA1C7}"
    Set-RegistryKey -Key "HKLM:\SOFTWARE\IM Providers\Teams" -Name "ProcessName" -Type "String" -Value "Teams.exe"
    Set-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\IM Providers\Teams" -Name "FriendlyName" -Type "String" -Value "Microsoft Teams"
    Set-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\IM Providers\Teams" -Name "GUID" -Type "String" -Value "{00425F68-FFC1-445F-8EDF-EF78B84BA1C7}"
    Set-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\IM Providers\Teams" -Name "ProcessName" -Type "String" -Value "Teams.exe"

    # Add Windows Defender exclusion(s) - https://docs.microsoft.com/en-us/microsoftteams/troubleshoot/teams-administration/include-exclude-teams-from-antivirus-dlp
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Microsoft\Teams\Update.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Microsoft\Teams\current\Squirrel.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Microsoft\Teams\current\Teams.exe" -Force

    # Add Windows Firewall rule(s) - https://docs.microsoft.com/en-us/microsoftteams/get-clients#windows
    If (-Not(Get-NetFirewallRule -DisplayName "$appVendor $appName"))
    {
        New-NetFirewallRule -Displayname "$appVendor $appName" -Direction Inbound -Program "$appDestination\$($appProcesses[0]).exe" -Profile 'Domain, Private, Public'
    }

    # Go back to the parent folder
    Set-Location ..

    Write-Log -Message "$appVendor $appName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
}
Else
{
    Write-Log -Message "$appVendor $appName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}