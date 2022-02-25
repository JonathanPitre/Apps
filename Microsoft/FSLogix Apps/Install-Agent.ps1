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

Function Resolve-Uri
{
    <#
    .SYNOPSIS
        Resolves a URI and also returns the filename and last modified date if found.

    .DESCRIPTION
        Resolves a URI and also returns the filename and last modified date if found.

    .NOTES
        Site: https://packageology.com
        Author: Dan Gough
        Twitter: @packageologist

    .LINK
        https://github.com/DanGough/Nevergreen

    .PARAMETER Uri
        The URI resolve. Accepts an array of strings or pipeline input.

    .PARAMETER UserAgent
        Optional parameter to provide a user agent for Invoke-WebRequest to use. Examples are:

        Googlebot: 'Googlebot/2.1 (+http://www.google.com/bot.html)'
        Microsoft Edge: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246'

    .EXAMPLE
        Resolve-Uri -Uri 'http://somewhere.com/somefile.exe'

        Description:
        Returns the absolute redirected URI, filename and last modified date.
    #>
    [CmdletBinding(SupportsShouldProcess = $False)]
    param (
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidatePattern('^(http|https)://')]
        [Alias('Url')]
        [String[]] $Uri,
        [Parameter(
            Mandatory = $false,
            Position = 1)]
        [String] $UserAgent
    )

    begin
    {
        $ProgressPreference = 'SilentlyContinue'
    }

    process
    {

        foreach ($UriToResolve in $Uri)
        {

            try
            {

                $ParamHash = @{
                    Uri              = $UriToResolve
                    Method           = 'Head'
                    UseBasicParsing  = $True
                    DisableKeepAlive = $True
                    ErrorAction      = 'Stop'
                }

                if ($UserAgent)
                {
                    $ParamHash.UserAgent = $UserAgent
                }

                $Response = Invoke-WebRequest @ParamHash

                if ($IsCoreCLR)
                {
                    $ResolvedUri = $Response.BaseResponse.RequestMessage.RequestUri.AbsoluteUri
                }
                else
                {
                    $ResolvedUri = $Response.BaseResponse.ResponseUri.AbsoluteUri
                }

                Write-Verbose "$($MyInvocation.MyCommand): URI resolved to: $ResolvedUri"

                #PowerShell 7 returns each header value as single unit arrays instead of strings which messes with the -match operator coming up, so use Select-Object:
                $ContentDisposition = $Response.Headers.'Content-Disposition' | Select-Object -First 1

                if ($ContentDisposition -match 'filename="?([^\\/:\*\?"<>\|]+)')
                {
                    $FileName = $matches[1]
                    Write-Verbose "$($MyInvocation.MyCommand): Content-Disposition header found: $ContentDisposition"
                    Write-Verbose "$($MyInvocation.MyCommand): File name determined from Content-Disposition header: $FileName"
                }
                else
                {
                    $Slug = [uri]::UnescapeDataString($ResolvedUri.Split('?')[0].Split('/')[-1])
                    if ($Slug -match '^[^\\/:\*\?"<>\|]+\.[^\\/:\*\?"<>\|]+$')
                    {
                        Write-Verbose "$($MyInvocation.MyCommand): URI slug is a valid file name: $FileName"
                        $FileName = $Slug
                    }
                    else
                    {
                        $FileName = $null
                    }
                }

                try
                {
                    $LastModified = [DateTime]($Response.Headers.'Last-Modified' | Select-Object -First 1)
                    Write-Verbose "$($MyInvocation.MyCommand): Last modified date: $LastModified"
                }
                catch
                {
                    Write-Verbose "$($MyInvocation.MyCommand): Unable to parse date from last modified header: $($Response.Headers.'Last-Modified')"
                    $LastModified = $null
                }

            }
            catch
            {
                Throw "$($MyInvocation.MyCommand): Unable to resolve URI: $($_.Exception.Message)"
            }

            if ($ResolvedUri)
            {
                [PSCustomObject]@{
                    Uri          = $ResolvedUri
                    FileName     = $FileName
                    LastModified = $LastModified
                }
            }

        }
    }

    end
    {
    }

}

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

            $ProgressPreference = 'SilentlyContinue'

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
        $DownloadURL = "https://aka.ms/fslogix/downloadpreview"
        $DownloadURL = Resolve-Uri -Uri $DownloadURL | Select-Object -ExpandProperty Uri
        $PreviewVersion = Get-Version -String $DownloadURL
    }
    Catch
    {
        Throw "Failed to connect to URL: $DownloadURL with error $_."
        Break
    }
    Finally
    {

        if ($PreviewVersion -and $DownloadURL)
        {
            [PSCustomObject]@{
                Version = $PreviewVersion
                Date    = "24/02/2022"
                Channel = 'Preview'
                Uri     = $DownloadURL
            }
        }

        Get-EvergreenApp MicrosoftFSLogixApps

    }
}

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$appVendor = "Microsoft"
$appName = "FSLogix Apps"
$appSetup = "FSLogixAppsSetup.exe"
$appProcesses = @("frxsvc", "frxtray", "frxshell", "frxccds")
$appInstallParameters = "/install /quiet /norestart"
$Evergreen = Get-MicrosoftFSLogixApps| Where-Object { $_.Channel -eq "Preview" }
$appVersion = $Evergreen.Version
$appURL = $Evergreen.URI
$appZip = "FSLogix_Apps_$appVersion.zip"
$appDestination = "$env:ProgramFiles\FSLogix\Apps"
$appURLScript = "https://raw.githubusercontent.com/FSLogix/Invoke-FslShrinkDisk/master/Invoke-FslShrinkDisk.ps1"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName" -Exact) | Select-Object -Last 1
$appInstalledVersion = (Get-InstalledApplication -Name "$appVendor $appName" -Exact).DisplayVersion | Select-Object -Last 1

#----------------------------------------------------------[Declarations]----------------------------------------------------------

If ([version]$appVersion -gt [version]$appInstalledVersion)
{
    Set-Location -Path $appScriptDirectory
    If (-Not(Test-Path -Path $appVersion)) {New-Folder -Path $appVersion}
    Set-Location -Path $appVersion

    Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
    Get-Process -Name $appProcesses | Stop-Process -Force

    If (-Not(Test-Path -Path $appScriptDirectory\$appVersion\x64\Release\$appSetup))
    {
        Write-Log -Message "Downloading $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURL -OutFile $appZip
        Expand-Archive -Path $appZip -DestinationPath $appScriptDirectory\$appVersion
        # Move the policy definitions files
        If (-Not(Test-Path -Path "$appScriptDirectory\PolicyDefinitions")) {New-Folder -Path "$appScriptDirectory\PolicyDefinitions"}
        If (-Not(Test-Path -Path "$appScriptDirectory\PolicyDefinitions\en-US")) {New-Folder -Path "$appScriptDirectory\PolicyDefinitions\en-US"}
        Move-Item -Path .\fslogix.admx -Destination "$appScriptDirectory\PolicyDefinitions\fslogix.admx" -Force
        Move-Item -Path .\fslogix.adml -Destination "$appScriptDirectory\PolicyDefinitions\en-US\fslogix.adml" -Force
        Remove-File -Path $appZip
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Download latest version of Jim Moyle's Invoke-FslShrinkDisk.ps1 script
    Invoke-WebRequest -UseBasicParsing -Uri $appURLScript -OutFile "$appScriptDirectory\FileServer Maintenance\Invoke-FslShrinkDisk.ps1"

    Write-Log -Message "Installing $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    Execute-Process -Path .\x64\Release\$appSetup -Parameters $appInstallParameters

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

    Write-Log -Message "Installing $appVendor $appName Management Utility..." -Severity 1 -LogType CMTrace -WriteHost $True
    # https://docs.microsoft.com/en-us/fslogix/disk-management-utility-reference
    Execute-Process -Path $appDestination\frxcontext.exe -Parameters "--install"

    # Add shortcut on the Start Menu
    New-Folder -Path "$envCommonStartMenuPrograms\Troubleshooting Tools" -ContinueOnError $True
    New-Shortcut -Path "$envCommonStartMenuPrograms\Troubleshooting Tools\FSLogix Tray Icon.lnk" -TargetPath "$appDestination\frxtray.exe" -IconLocation "$appDestination\frxtray.exe" -Description "FSLogix Tray Icon" -WorkingDirectory "$appDestination"

    # Enable FSLogix Apps agent search roaming - Apply different configurations based on operating system
    If ($envOSName -like "*Windows Server 2012*" -or $envOSName -like "*Windows Server 2016")
    {
        # Install Windows Search feature when missing, if Office was installed before it must be repair!
        If (-Not(Get-WindowsFeature -Name Search-Service)) {Install-WindowsFeature Search-Service}
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
    }
    If ($envOSName -like "*Windows Server 2019*" -or $envOSName -like "*Windows Server 2022*")
    {
        # Define CIM object variables - https://virtualwarlock.net/how-to-install-the-fslogix-apps-agent
        # This is needed for accessing the non-default trigger settings when creating a schedule task using Powershell
        $Class = cimclass MSFT_TaskEventTrigger root/Microsoft/Windows/TaskScheduler
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
    If ((Get-ServiceStartMode -Name $serviceName) -ne "Automatic") {Set-ServiceStartMode -Name $serviceName -StartMode "Automatic"}
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
    Add-MpPreference -ExclusionProcess "%ProgramFiles%\FSLogix\Apps\frxsvc.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles%\FSLogix\Apps\frxccds.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles%\FSLogix\Apps\frxsvc.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles%\FSLogix\Apps\frxrobocopy.exe" -Force

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