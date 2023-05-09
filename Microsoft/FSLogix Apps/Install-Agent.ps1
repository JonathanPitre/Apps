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
Function Get-Version
{
    <#
    .SYNOPSIS
        Extracts a version number from either a string or the content of a web page using a chosen or pre-defined match pattern.

    .DESCRIPTION
        Extracts a version number from either a string or the content of a web page using a chosen or pre-defined match pattern.

    .NOTES
        Site: https://packageology.com
        Author: Dan Gough
        Twitter: @packageologist

    .LINK
        https://github.com/DanGough/Nevergreen

    .PARAMETER String
        The string to process.

    .PARAMETER Uri
        The Uri to load web content from to process.

    .PARAMETER UserAgent
        Optional parameter to provide a user agent for Invoke-WebRequest to use. Examples are:

        Googlebot: 'Googlebot/2.1 (+http://www.google.com/bot.html)'
        Microsoft Edge: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246'

    .PARAMETER Pattern
        Optional RegEx pattern to use for version matching. Pattern to return must be included in parentheses.

    .PARAMETER ReplaceWithDot
        Switch to automatically replace characters - or _ with . in detected version.

    .EXAMPLE
        Get-Version -String 'http://somewhere.com/somefile_1.2.3.exe'

        Description:
        Returns '1.2.3'
    #>
    [CmdletBinding(SupportsShouldProcess = $False)]
    param (
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ParameterSetName = 'String')]
        [ValidateNotNullOrEmpty()]
        [String[]] $String,
        [Parameter(
            Mandatory = $true,
            ParameterSetName = 'Uri')]
        [ValidatePattern('^(http|https)://')]
        [String] $Uri,
        [Parameter(
            Mandatory = $false,
            ParameterSetName = 'Uri')]
        [String] $UserAgent,
        [Parameter(
            Mandatory = $false,
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String] $Pattern = '((?:\d+\.)+\d+)',
        [Switch] $ReplaceWithDot
    )

    begin
    {

    }

    process
    {

        if ($PsCmdlet.ParameterSetName -eq 'Uri')
        {

            try
            {
                $ParamHash = @{
                    Uri              = $Uri
                    Method           = 'GET'
                    UseBasicParsing  = $True
                    DisableKeepAlive = $True
                    ErrorAction      = 'Stop'
                }

                if ($UserAgent)
                {
                    $ParamHash.UserAgent = $UserAgent
                }

                $String = (Invoke-WebRequest @ParamHash).Content
            }
            catch
            {
                Write-Error "Unable to query URL '$Uri': $($_.Exception.Message)"
            }

        }

        foreach ($CurrentString in $String)
        {

            if ($CurrentString -match $Pattern)
            {
                if ($ReplaceWithDot)
                {
                    $matches[1].Replace('-', '.').Replace('_', '.')
                }
                else
                {
                    $matches[1]
                }
            }
            else
            {
                Write-Warning "No version found within $CurrentString using pattern $Pattern"
            }

        }

    }

    end
    {
    }

}

Function Get-Link
{
    <#
    .SYNOPSIS
        Returns a specific link from a web page.

    .DESCRIPTION
        Returns a specific link from a web page.

    .NOTES
        Site: https://packageology.com
        Author: Dan Gough
        Twitter: @packageologist

    .LINK
        https://github.com/DanGough/Nevergreen

    .PARAMETER Uri
        The URI to query.

    .PARAMETER MatchProperty
        Whether the RegEx pattern should be applied to the href, outerHTML, class, title or data-filename of the link.

    .PARAMETER Pattern
        The RegEx pattern to apply to the selected property. Supply an array of patterns to receive multiple links.

    .PARAMETER ReturnProperty
        Optional. Specifies which property to return from the link. Defaults to href, but 'data-filename' can also be useful to retrieve.

    .PARAMETER UserAgent
        Optional parameter to provide a user agent for Invoke-WebRequest to use. Examples are:

        Googlebot: 'Googlebot/2.1 (+http://www.google.com/bot.html)'
        Microsoft Edge: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246'

    .EXAMPLE
        Get-Link -Uri 'http://somewhere.com' -MatchProperty href -Pattern '\.exe$'

        Description:
        Returns first download link matching *.exe from http://somewhere.com.
    #>
    [CmdletBinding(SupportsShouldProcess = $False)]
    param (
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline)]
        [ValidatePattern('^(http|https)://')]
        [Alias('Url')]
        [String] $Uri,
        [Parameter(
            Mandatory = $true,
            Position = 1)]
        [ValidateSet('href', 'outerHTML', 'innerHTML', 'outerText', 'innerText', 'class', 'title', 'tagName', 'data-filename')]
        [String] $MatchProperty,
        [Parameter(
            Mandatory = $true,
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [String[]] $Pattern,
        [Parameter(
            Mandatory = $false,
            Position = 3)]
        [ValidateNotNullOrEmpty()]
        [String] $ReturnProperty = 'href',
        [Parameter(
            Mandatory = $false)]
        [String] $UserAgent,
        [System.Collections.Hashtable] $Headers,
        [Switch] $PrefixDomain,
        [Switch] $PrefixParent
    )

    $ParamHash = @{
        Uri              = $Uri
        Method           = 'GET'
        UseBasicParsing  = $True
        DisableKeepAlive = $True
        ErrorAction      = 'Stop'
    }

    if ($UserAgent)
    {
        $ParamHash.UserAgent = $UserAgent
    }

    if ($Headers)
    {
        $ParamHash.Headers = $Headers
    }

    try
    {
        $Response = Invoke-WebRequest @ParamHash

        foreach ($CurrentPattern in $Pattern)
        {
            $Link = $Response.Links | Where-Object $MatchProperty -Match $CurrentPattern | Select-Object -First 1 -ExpandProperty $ReturnProperty

            if ($PrefixDomain)
            {
                $BaseURL = ($Uri -split '/' | Select-Object -First 3) -join '/'
                $Link = Set-UriPrefix -Uri $Link -Prefix $BaseURL
            }
            elseif ($PrefixParent)
            {
                $BaseURL = ($Uri -split '/' | Select-Object -SkipLast 1) -join '/'
                $Link = Set-UriPrefix -Uri $Link -Prefix $BaseURL
            }

            $Link

        }
    }
    catch
    {
        Write-Error "$($MyInvocation.MyCommand): $($_.Exception.Message)"
    }

}

Function Get-MicrosoftFSLogixApps
{
    <#
    .NOTES
        Author: Jonathan Pitre
        Twitter: @PitreJonathan
    #>

    [OutputType([System.Management.Automation.PSObject])]
    [CmdletBinding()]
    Param()

    Try
    {
        $Pattern = "\(((?:\d+\.)+\d+)\) - Public Preview"
        $URL = "https://learn.microsoft.com/en-us/fslogix/whats-new"
        $DownloadURL = Get-Link -Uri $URL -MatchProperty outerHTML -Pattern $Pattern
        $Version = Get-Version -String $DownloadURL
        $Date = Get-Version -Uri $URL -Pattern "((?:\d+\/)+\d+)"

    }
    Catch
    {
        Throw "Failed to connect to URL: $DownloadURL with error $_."
        Break
    }
    Finally
    {

        if ($Version -and $DownloadURL)
        {
            [PSCustomObject]@{
                Version = $Version
                Date    = $Date
                Channel = 'Public Preview'
                Uri     = $DownloadURL
            }
        }

        Get-EvergreenApp -Name MicrosoftFSLogixApps

    }
}

#endregion

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$appVendor = "Microsoft"
$appName = "FSLogix Apps"
$appSetup = "FSLogixAppsSetup.exe"
$appProcesses = @("frxsvc", "frxtray", "frxshell", "frxccds")
$appInstallParameters = "/install /quiet /norestart"
$Evergreen = Get-MicrosoftFSLogixApps | Where-Object { $_.Channel -eq "Production" }
$appVersion = $Evergreen.Version
$appURL = $Evergreen.URI
$appZip = Split-Path -Path $appURL -Leaf
$appDestination = "$env:ProgramFiles\FSLogix\Apps"
$appURLScript = "https://raw.githubusercontent.com/FSLogix/Invoke-FslShrinkDisk/master/Invoke-FslShrinkDisk.ps1"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName" -Exact) | Select-Object -Last 1
$appInstalledVersion = (Get-InstalledApplication -Name "$appVendor $appName" -Exact).DisplayVersion | Select-Object -Last 1

#-----------------------------------------------------------[Execution]------------------------------------------------------------

If ([version]$appVersion -gt [version]$appInstalledVersion)
{
    Set-Location -Path $appScriptPath
    If (-Not(Test-Path -Path $appVersion)) { New-Folder -Path $appVersion }
    Set-Location -Path $appVersion

    Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
    Get-Process -Name $appProcesses | Stop-Process -Force

    If (-Not(Test-Path -Path $appScriptPath\$appVersion\x64\Release\$appSetup))
    {
        Write-Log -Message "Downloading $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURL -OutFile $appZip
        Expand-Archive -Path $appZip -DestinationPath $appScriptPath\$appVersion
        # Move the policy definitions files
        If (-Not(Test-Path -Path "$appScriptPath\PolicyDefinitions")) { New-Folder -Path "$appScriptPath\PolicyDefinitions" }
        If (-Not(Test-Path -Path "$appScriptPath\PolicyDefinitions\en-US")) { New-Folder -Path "$appScriptPath\PolicyDefinitions\en-US" }
        Move-Item -Path .\fslogix.admx -Destination "$appScriptPath\PolicyDefinitions\fslogix.admx" -Force
        Move-Item -Path .\fslogix.adml -Destination "$appScriptPath\PolicyDefinitions\en-US\fslogix.adml" -Force
        Remove-File -Path $appZip
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    Write-Log -Message "Installing $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    Execute-Process -Path .\x64\Release\$appSetup -Parameters $appInstallParameters

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

    Write-Log -Message "Installing $appVendor $appName Management Utility..." -Severity 1 -LogType CMTrace -WriteHost $True
    # https://docs.microsoft.com/en-us/fslogix/disk-management-utility-reference
    Execute-Process -Path $appDestination\frxcontext.exe -Parameters "--install"

    # Configure application shortcut
    New-Shortcut -Path "$envCommonStartMenuPrograms\Administrative Tools\FSLogix Tray Icon.lnk" -TargetPath "$appDestination\frxtray.exe" -IconLocation "$appDestination\frxtray.exe" -Description "FSLogix Tray Icon" -WorkingDirectory "$appDestination"

    # Enable FSLogix Apps agent search roaming - Apply different configurations based on operating system
    If ($envOSName -like "*Windows Server 2012*" -or $envOSName -like "*Windows Server 2016")
    {
        # Install Windows Search feature when missing, if Office was installed before it must be repair!
        If (-Not(Get-WindowsFeature -Name Search-Service)) { Install-WindowsFeature Search-Service }
    }
    If ($envOSName -like "*Windows Server 2016")
    {
        # Limit Windows Search to a single cpu core - https://social.technet.microsoft.com/Forums/en-US/88725f57-67ed-4c09-8ae6-780ff785e555/problems-with-search-service-on-server-2012-r2-rds?forum=winserverTS
        #Set-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows Search" -Name "CoreCount" -Type "DWord" -Value "1"
        # Configure multi-user search - https://docs.microsoft.com/en-us/fslogix/configure-search-roaming-ht
        Set-RegistryKey -Key "HKLM:\SOFTWARE\FSLogix\Apps" -Name "RoamSearch" -Value "2" -Type DWord
        Set-RegistryKey -Key "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "RoamSearch" -Value "2" -Type DWord
        Set-RegistryKey -Key "HKLM:\SOFTWARE\Policies\FSLogix\ODFC" -Name "RoamSearch" -Value "0" -Type DWord
    }
    If ($envOSName -like "*Windows Server 2019*" -or $envOSName -like "*Windows Server 2022*" -or $envOSName -like "*Windows 10 Enterprise for Virtual Desktops")
    {
        # Limit Windows Search to a single cpu core - https://social.technet.microsoft.3.com/Forums/en-US/88725f57-67ed-4c09-8ae6-780ff785e555/problems-with-search-service-on-server-2012-r2-rds?forum=winserverTS
        Set-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows Search" -Name "CoreCount" -Value "1" -Type DWord
        # Enable Windows per user search catalog since FSLogix search indexing functionality is not recommended on Windows Server 2019 and Windows 10 multi-session
        # https://docs.microsoft.com/en-us/fslogix/configure-search-roaming-ht
        # https://jkindon.com/2020/03/15/windows-search-in-server-2019-and-multi-session-windows-10
        Set-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows Search" -Name "EnablePerUserCatalog" -Value 1 -Type DWord
        Set-RegistryKey -Key "HKLM:\SOFTWARE\FSLogix\Apps" -Name "RoamSearch" -Value "0" -Type DWord
        Set-RegistryKey -Key "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "RoamSearch" -Value "0" -Type DWord
        Set-RegistryKey -Key "HKLM:\SOFTWARE\Policies\FSLogix\ODFC" -Name "RoamSearch" -Value "0" -Type DWord

        # Define CIM object variables - https://virtualwarlock.net/how-to-install-the-fslogix-apps-agent
        # This is needed for accessing the non-default trigger settings when creating a schedule task using Powershell
        $Class = Get-CimClass MSFT_TaskEventTrigger root/Microsoft/Windows/TaskScheduler
        $Trigger = $class | New-CimInstance -ClientOnly
        $Trigger.Enabled = $true
        $Trigger.Subscription = "<QueryList><Query Id=`"0`" Path=`"Application`"><Select Path=`"Application`">*[System[Provider[@Name='Microsoft-Windows-Search-ProfileNotify'] and EventID=2]]</Select></Query></QueryList>"

        # Define additional variables containing scheduled task action and scheduled task principal
        $A = New-ScheduledTaskAction -Execute powershell.exe -Argument "Restart-Service Wsearch"
        $P = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount
        $S = New-ScheduledTaskSettingsSet

        # Cook it all up and create the scheduled task
        $RegSchTaskParameters = @{
            TaskName    = "Restart Windows Search Service on Event ID 2"
            Description = "Restarts the Windows Search service on event ID 2"
            TaskPath    = "\"
            Action      = $A
            Principal   = $P
            Settings    = $S
            Trigger     = $Trigger
        }
        Register-ScheduledTask @RegSchTaskParameters
        Write-Log -Message "Scheduled Task to reset Windows Search was registered!" -Severity 1 -LogType CMTrace -WriteHost $True
    }
    If ($envOSName -like "*Windows 10*" -and $envOSName -ne "*Windows 10 Enterprise for Virtual Desktops")
    {
        Set-RegistryKey -Key "HKLM:\SOFTWARE\FSLogix\Apps" -Name "RoamSearch" -Value "1" -Type DWord
        Set-RegistryKey -Key "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "RoamSearch" -Value "1" -Type DWord
        Set-RegistryKey -Key "HKLM:\SOFTWARE\Policies\FSLogix\ODFC" -Name "RoamSearch" -Value "0" -Type DWord
    }

    # Configure Windows Search service auto-start and start it
    $serviceName = "WSearch"
    If ((Get-ServiceStartMode -Name $serviceName) -ne "Automatic") { Set-ServiceStartMode -Name $serviceName -StartMode "Automatic" }
    Start-ServiceAndDependencies -Name $serviceName

    # Fix for Citrix App Layering and FSLogix integration, must be done in the platform layer - https://support.citrix.com/article/CTX249873
    # https://social.msdn.microsoft.com/Forums/windows/en-US/660959a4-f9a9-486b-8a0d-dec3eba549e3/using-citrix-app-layering-unidesk-with-fslogix?forum=FSLogix
    If ((Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\unifltr") -and (Get-RegistryKey -Key "HKLM:\SYSTEM\CurrentControlSet\Services\frxdrvvt\Instances\frxdrvvt" -Value "Altitude") -ne 138010)
    {
        Write-Log -Message "Modifying $appVendor $appName altitude setting to be compatible with Citrix App Layering..." -Severity 1 -LogType CMTrace -WriteHost $True
        Set-RegistryKey -Key "HKLM:\SYSTEM\CurrentControlSet\Services\frxdrvvt\Instances\frxdrvvt" -Name "Altitude" -Value "138010" -Type String
    }

    # Disable Citrix Profile Management if detected
    If ((Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ctxProfile") -and (Get-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Citrix\UserProfileManager" -Value "PSEnabled") -ne "0")
    {
        Write-Log -Message "Disabling Citrix Profile Management..." -Severity 1 -LogType CMTrace -WriteHost $True
        Set-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Citrix\UserProfileManager" -Name "PSEnabled" -Value "0" -Type DWord
    }

    # Enable frxrobocopy - https://docs.microsoft.com/en-us/fslogix/fslogix-installed-components-functions-reference
    Copy-File -Path "$envWinDir\System32\Robocopy.exe" -Destination "$appDestination\frxrobocopy.exe"
    # https://github.com/MicrosoftDocs/fslogix-docs/issues/78
    New-Folder -Path "$appDestination\en-us"
    Copy-File -Path "$envWinDir\System32\en-us\Robocopy.exe.mui" -Destination "$appDestination\en-us\frxrobocopy.exe.mui"

    # Add Windows Defender exclusion(s) - https://docs.microsoft.com/en-us/azure/architecture/example-scenario/wvd/windows-virtual-desktop-fslogix
    Add-MpPreference -ExclusionPath "%ProgramFiles%\FSLogix\Apps\frxdrv.sys" -Force
    Add-MpPreference -ExclusionPath "%ProgramFiles%\FSLogix\Apps\frxdrvvt.sys" -Force
    Add-MpPreference -ExclusionPath "%ProgramFiles%\FSLogix\Apps\frxccd.sys" -Force
    Add-MpPreference -ExclusionPath "%TEMP%\*.VHD" -Force
    Add-MpPreference -ExclusionPath "%TEMP%\*.VHDX" -Force
    Add-MpPreference -ExclusionPath "%Windir%\TEMP\*.VHD" -Force
    Add-MpPreference -ExclusionPath "%Windir%\TEMP­­\*.VHDX" -Force
    Add-MpPreference -ExclusionPath "%ProgramData%\FSLogix\Cache\*.VHD" -Force
    Add-MpPreference -ExclusionPath "%ProgramData%\FSLogix\Cache\*.VHDX" -Force
    Add-MpPreference -ExclusionPath "%ProgramData%\FSLogix\Proxy\*.VHD" -Force
    Add-MpPreference -ExclusionPath "%ProgramData%\FSLogix\Proxy\*.VHDX" -Force
    #Add-MpPreference -ExclusionProcess "%ProgramFiles%\FSLogix\Apps\frxccd.exe" -Force # No longuer exist
    Add-MpPreference -ExclusionProcess "%ProgramFiles%\FSLogix\Apps\frxccds.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles%\FSLogix\Apps\frxsvc.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles%\FSLogix\Apps\frxrobocopy.exe" -Force
    # Avoid locked VHDX files and local_username directories at logoff
    #Add-MpPreference -ExclusionProcess "%windir%\System32\lsass.exe" -Force

    # Add built-in administrators group to exclude list
    Add-LocalGroupMember -Group "FSLogix ODFC Exclude List" -Member "BUILTIN\Administrators"
    Add-LocalGroupMember -Group "FSLogix Profile Exclude List" -Member "BUILTIN\Administrators"

    # Go back to the parent folder
    Set-Location ..

    Write-Log -Message "$appVendor $appName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
}
Else
{
    Write-Log -Message "$appVendor $appName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}