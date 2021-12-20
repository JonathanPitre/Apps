# Standalone application install script for VDI environment - (C)2021 Jonathan Pitre & Owen Reynolds, inspired by xenappblog.com

#Requires -Version 5.1
#Requires -RunAsAdministrator

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"
$env:SEE_MASK_NOZONECHECKS = 1
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

Function Search-Registry
{
    <#
.SYNOPSIS
Searches registry key names, value names, and value data (limited).
.DESCRIPTION
This function can search registry key names, value names, and value data (in a limited fashion). It outputs custom objects that contain the key and the first match type (KeyName, ValueName, or ValueData).
.EXAMPLE
Search-Registry -Path HKLM:\SYSTEM\CurrentControlSet\Services\* -SearchRegex "svchost" -ValueData
.EXAMPLE
Search-Registry -Path HKLM:\SOFTWARE\Microsoft -Recurse -ValueNameRegex "ValueName1|ValueName2" -ValueDataRegex "ValueData" -KeyNameRegex "KeyNameToFind1|KeyNameToFind2"
.LINK
https://github.com/asheroto/Search-Registry
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias("PsPath")]
        # Registry path to search
        [string[]] $Path,
        # Specifies whether or not all subkeys should also be searched
        [switch] $Recurse,
        [Parameter(ParameterSetName = "SingleSearchString", Mandatory)]
        # A regular expression that will be checked against key names, value names, and value data (depending on the specified switches)
        [string] $SearchRegex,
        [Parameter(ParameterSetName = "SingleSearchString")]
        # When the -SearchRegex parameter is used, this switch means that key names will be tested (if none of the three switches are used, keys will be tested)
        [switch] $KeyName,
        [Parameter(ParameterSetName = "SingleSearchString")]
        # When the -SearchRegex parameter is used, this switch means that the value names will be tested (if none of the three switches are used, value names will be tested)
        [switch] $ValueName,
        [Parameter(ParameterSetName = "SingleSearchString")]
        # When the -SearchRegex parameter is used, this switch means that the value data will be tested (if none of the three switches are used, value data will be tested)
        [switch] $ValueData,
        [Parameter(ParameterSetName = "MultipleSearchStrings")]
        # Specifies a regex that will be checked against key names only
        [string] $KeyNameRegex,
        [Parameter(ParameterSetName = "MultipleSearchStrings")]
        # Specifies a regex that will be checked against value names only
        [string] $ValueNameRegex,
        [Parameter(ParameterSetName = "MultipleSearchStrings")]
        # Specifies a regex that will be checked against value data only
        [string] $ValueDataRegex
    )

    begin
    {
        switch ($PSCmdlet.ParameterSetName)
        {
            SingleSearchString
            {
                $NoSwitchesSpecified = -not ($PSBoundParameters.ContainsKey("KeyName") -or $PSBoundParameters.ContainsKey("ValueName") -or $PSBoundParameters.ContainsKey("ValueData"))
                if ($KeyName -or $NoSwitchesSpecified) { $KeyNameRegex = $SearchRegex }
                if ($ValueName -or $NoSwitchesSpecified) { $ValueNameRegex = $SearchRegex }
                if ($ValueData -or $NoSwitchesSpecified) { $ValueDataRegex = $SearchRegex }
            }
            MultipleSearchStrings
            {
                # No extra work needed
            }
        }
    }

    process
    {
        foreach ($CurrentPath in $Path)
        {
            Get-ChildItem $CurrentPath -Recurse:$Recurse |
                ForEach-Object {
                $Key = $_

                if ($KeyNameRegex)
                {
                    Write-Verbose ("{0}: Checking KeyNamesRegex" -f $Key.Name)

                    if ($Key.PSChildName -match $KeyNameRegex)
                    {
                        Write-Verbose "  -> Match found!"
                        return [PSCustomObject] @{
                            Key    = $Key
                            Reason = "KeyName"
                        }
                    }
                }

                if ($ValueNameRegex)
                {
                    Write-Verbose ("{0}: Checking ValueNamesRegex" -f $Key.Name)

                    if ($Key.GetValueNames() -match $ValueNameRegex)
                    {
                        Write-Verbose "  -> Match found!"
                        return [PSCustomObject] @{
                            Key    = $Key
                            Reason = "ValueName"
                        }
                    }
                }

                if ($ValueDataRegex)
                {
                    Write-Verbose ("{0}: Checking ValueDataRegex" -f $Key.Name)

                    if (($Key.GetValueNames() | ForEach-Object { $Key.GetValue($_) }) -match $ValueDataRegex)
                    {
                        Write-Verbose "  -> Match!"
                        return [PSCustomObject] @{
                            Key    = $Key
                            Reason = "ValueData"
                        }
                    }
                }
            }
        }
    }
}

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$appVendor = "Microsoft"
$appName = "Teams"
$appProcesses = @("Teams", "Update", "Squirrel", "Outlook")
$appRing = "Preview"
$appArchitecture = "x64"
$appLanguage = "fr-CA"
$appTransformURL = "https://github.com/JonathanPitre/Apps/raw/master/Microsoft/Teams/Teams.mst"
$appTransform = Split-Path -Path $appTransformURL -Leaf
$appTeamsConfigURL = "https://raw.githubusercontent.com/JonathanPitre/Apps/raw/master/Microsoft/Teams/desktop-config.json"
$appTeamsConfig = Split-Path -Path $appTeamsConfigURL -Leaf
$appInstallParameters = "/QB"
$appAddParameters = "ALLUSER=1 ALLUSERS=1"
$Evergreen = Get-EvergreenApp $appVendor$appName | Where-Object {$_.Ring -eq $appRing -and $_.Architecture -eq $appArchitecture -and $_.Type -eq "Msi"}
$appVersion = $Evergreen.Version
$appURL = $Evergreen.URI
$appSetup = Split-Path -Path $appURL -Leaf
$appDestination = "${env:ProgramFiles(x86)}\Microsoft\Teams\current"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName")
$appInstalledVersion = If ($IsAppInstalled) { Get-FileVersion -File "$appDestination\Teams.exe" }

#-----------------------------------------------------------[Execution]------------------------------------------------------------

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

    # Delete left over folders and reg keys
    Remove-Folder -Path "$envProgramFilesX86\Teams Installer" -ContinueOnError $True
    Remove-RegistryKey -Key "HKCR:\CLSID\{00425F68-FFC1-445F-8EDF-EF78B84BA1C7}" -Recurse -ContinueOnError $True
    Remove-RegistryKey -Key "HKCR:\WOW6432Node\CLSID\{00425F68-FFC1-445F-8EDF-EF78B84BA1C7}" -Recurse -ContinueOnError $True
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders" -Name "C:\Program Files (x86)\Teams Installer\"
    $RegKey = Search-Registry -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" -Recurse -ValueDataRegex ".*Teams.*Installer.*"  | Select-Object -ExpandProperty Key
    Remove-RegistryKey -Key $RegKey
    $RegKeys = Search-Registry -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components" -Recurse -ValueDataRegex ".*Teams.*Installer.*" | Select-Object -ExpandProperty Key
    foreach ($RegKey in $RegKeys)
    {
        try
        {
            Remove-RegistryKey -Key $RegKey
        }
        catch
        {
        }
    }


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
    # If Teams is configured to Auto-start, the issue in the bullet above might also manifest. We recommend disabling auto-start by deleting the Teams regkeys
    # https://support.citrix.com/article/CTX253754
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" -Name $appName -ContinueOnError $True

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

    # Download required Microsoft Teams config file
    If (-Not(Test-Path -Path $appScriptDirectory\$appTeamsConfig))
    {
        Write-Log -Message "Downloading $appVendor $appName config file..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appTeamsConfigURL -OutFile $appScriptDirectory\$appTeamsConfig
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Change language into desktop-config.json
    If (Test-Path -Path $appScriptDirectory\$appTeamsConfig)
    {
        $json = Get-Content -Path $appScriptDirectory\$appTeamsConfig -Raw | ConvertFrom-Json
        If ($json.currentWebLanguage -ne $appLanguage)
        {
            $json.currentWebLanguage = $appLanguage
            $json | ConvertTo-Json | Out-File $appScriptDirectory\$appTeamsConfig -Encoding utf8
            Write-Log -Message "$appVendor $appName config file was modified successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
        }
    }

    # Copy Microsoft Teams config file to the default profile
    Copy-File -Path "$appScriptDirectory\$appTeamsConfig" -Destination "$envSystemDrive\Users\Default\AppData\Roaming\Microsoft\Teams"
    Write-Log -Message "$appVendor $appName settings were configured for the Default User profile." -Severity 1 -LogType CMTrace -WriteHost $True

    # Register Teams as the chat app for Office
    Set-RegistryKey -Key "HKLM:\SOFTWARE\IM Providers\Teams" -Name "FriendlyName" -Type "String" -Value "Microsoft Teams"
    Set-RegistryKey -Key "HKLM:\SOFTWARE\IM Providers\Teams" -Name "GUID" -Type "String" -Value "{00425F68-FFC1-445F-8EDF-EF78B84BA1C7}"
    Set-RegistryKey -Key "HKLM:\SOFTWARE\IM Providers\Teams" -Name "ProcessName" -Type "String" -Value "Teams.exe"
    Set-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\IM Providers\Teams" -Name "FriendlyName" -Type "String" -Value "Microsoft Teams"
    Set-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\IM Providers\Teams" -Name "GUID" -Type "String" -Value "{00425F68-FFC1-445F-8EDF-EF78B84BA1C7}"
    Set-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\IM Providers\Teams" -Name "ProcessName" -Type "String" -Value "Teams.exe"

    # Load the Default User registry hive
    Execute-Process -Path "$envWinDir\System32\reg.exe" -Parameters "LOAD HKLM\DefaultUser $envSystemDrive\Users\Default\NTUSER.DAT" -WindowStyle Hidden

    # Set Microsoft Teams as the default chat app for Office - https://www.msoutlook.info/question/setting-skype-or-other-im-client-to-integrate-with-outlook
    Set-RegistryKey -Key "HKLM:\DefaultUser\Software\IM Providers" -Name "DefaultIMApp" -Type String -Value "Teams"

    # Open Microsoft Teams links without prompts - https://james-rankin.com/articles/microsoft-teams-on-citrix-virtual-apps-and-desktops-part-2-default-settings-and-json-wrangling
    Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Classes\msteams\shell\open\command" -Name "(Default)" -Type String -Value "`"C:\Program Files (x86)\Microsoft\Teams\current\Teams.exe`" `"%1`""
    Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Classes\TeamsURL\shell\open\command" -Name "(Default)" -Type String -Value "`"C:\Program Files (x86)\Microsoft\Teams\current\Teams.exe`" `"%1`""
    Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Classes\msteams" -Name "DefaultIMApp" -Type String -Value "URL:msteams"
    Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" -Name "msteams_msteams" -Type DWord -Value "00000000"
    Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Classes\msteams" -Name "URL Protocol" -Type String -Value ""
    Set-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Internet Explorer\ProtocolExecute\msteams" -Name "WarnOnOpen" -Type String -Value "00000000"

    # Unload the Default User registry hive
    Start-Sleep -Seconds 3
    Execute-Process -Path "$envWinDir\System32\reg.exe" -Parameters "UNLOAD HKLM\DefaultUser" -WindowStyle Hidden

    # Cleanup temp files
    Remove-Item -Path "$envSystemDrive\Users\Default\*.LOG1" -Force
    Remove-Item -Path "$envSystemDrive\Users\Default\*.LOG2" -Force
    Remove-Item -Path "$envSystemDrive\Users\Default\*.blf" -Force
    Remove-Item -Path "$envSystemDrive\Users\Default\*.regtrans-ms" -Force

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