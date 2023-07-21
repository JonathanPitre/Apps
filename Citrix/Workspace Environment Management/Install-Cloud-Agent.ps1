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
[array]$Modules = @("PSADT", "BetterCredentials") # Modules list

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

# Set JSON file path
[string]$scriptParametersFile = "$appScriptPath\parameters.json"
# Read script parameters from JSON file
$scriptParameters = Get-Content -Path $scriptParametersFile | ConvertFrom-Json
# For each object in the JSON file, create a powershell variable
$scriptParameters.PSObject.Properties | ForEach-Object {
    New-Variable -Name $_.Name -Value $_.Value -Force
}

#endregion

#-----------------------------------------------------------[Functions]------------------------------------------------------------

#region Functions

Function Get-CitrixWEMAgent
{
    [OutputType([System.Management.Automation.PSObject])]
    [CmdletBinding()]
    Param ()
    $DownloadURL = "https://docs.citrix.com/en-us/workspace-environment-management/service/whats-new.html"

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
        $RegEx = "(Minimum agent version required\: )(\d{4}.\d.\d.\d)"
        $Version = ($DownloadText | Select-String -Pattern $RegEx).Matches.Groups[2].Value
        $ZipVersion = $Version.Substring(0, $Version.Length - 4)
        $URL = "https://secureportal.citrix.com/Licensing/Downloads/UnrestrictedDL.aspx?DLID=$($appDlNumber)&URL=https://downloads.citrix.com/$($appDlNumber)/Workspace-Environment-Management-Agent-$($ZipVersion).zip"

        if ($Version -and $URL)
        {
            [PSCustomObject]@{
                Name    = 'Citrix Workspace Environment Agent'
                Version = $Version
                Uri     = $URL
            }
        }
    }
}

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
        [Parameter(Mandatory = $true)]$citrixUserName,
        [Parameter(Mandatory = $true)]$citrixPassword
    )

    # Initialize Session
    Invoke-WebRequest "https://identity.citrix.com/Utility/STS/Sign-In?ReturnUrl=%2fUtility%2fSTS%2fsaml20%2fpost-binding-response" -SessionVariable websession -UseBasicParsing | Out-Null

    # Set Form
    $Form = @{
        "persistent" = "on"
        "userName"   = $citrixUserName
        "password"   = $citrixPassword
    }

    # Authenticate
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
    # Download
    Invoke-WebRequest -Uri $dlURL -WebSession $WebSession -Method POST -Body $Webform -ContentType "application/x-www-form-urlencoded" -UseBasicParsing -OutFile $OutFile
    return $OutFile
}

#endregion

#----------------------------------------------------------[Declarations]----------------------------------------------------------

#region Declarations

[string]$appVendor = "Citrix"
[string]$appName = "Workspace Environment Management Agent"
[array]$appProcesses = @( "Citrix.Wem.Agent.Service", "Citrix.Wem.Agent.LogonService", "VUEMUIAgent", "VUEMAppCmd", "VUEMCmdAgent")
[string]$appInstallParameters = "/quiet Cloud=1" # OnPrem 0 Cloud 1
[int]$appDlNumber = "16122"
[array]$Evergreen = Get-CitrixWEMAgent
$appVersion = $Evergreen.Version
[string]$appURL = $Evergreen.URI
[string]$appZip = Split-Path -Path $appURL -Leaf
[string]$appSetup = "Citrix Workspace Environment Management Agent.exe"
[string]$appDestination = "${env:ProgramFiles(x86)}\Citrix\Workspace Environment Management Agent"
[boolean]$isAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName")
$appInstalledVersion = ((Get-InstalledApplication -Name "$appVendor $appName").DisplayVersion) | Sort-Object -Descending | Select-Object -First 1
[string]$appInstalledFile = (Test-Path -Path "$appDestination\Citrix.Wem.Agent.Service.exe")
[string]$appUninstallString = (Get-InstalledApplication -Name "$appVendor $appName").UninstallString
[string]$appUninstall = ($appUninstallString).Split('"')[1]
[string]$appUninstallParameters = "/uninstall /quiet /noreboot"

#endregion

#-----------------------------------------------------------[Execution]------------------------------------------------------------

#region Execution

Set-Location -Path $appScriptPath
If (-Not(Test-Path -Path $appVersion)) { New-Folder -Path $appVersion }
Set-Location -Path $appVersion

If (($isAppInstalled -eq $false) -or ([version]$appVersion -gt [version]$appInstalledVersion))
{
    # Detect if setup file is present
    If (-Not(Test-Path -Path "$appScriptPath\$appVersion\$appSetup"))
    {
        # Get Citrix account credentials
        If ($null -eq $citrixUserName)
        {
            $citrixUserName = "myCitrixUserName"
        }
        Else
        {
            [bool]$isCitrixCredentialsStored = [bool](Find-Credential -Filter "*$citrixUserName")
        }
        # Read stored credentials
        If ($isCitrixCredentialsStored)
        {
            Write-Host -Object "Stored credentials found for Citrix Account." -ForegroundColor Green
            $CitrixCredentials = (BetterCredentials\Get-Credential -UserName $citrixUserName -Store)
            $citrixUserName = $CitrixCredentials.UserName
            $CitrixCredentialsPassword = $CitrixCredentials.Password
        }
        Else
        {
            # Ask for credentials
            Write-Host -Object "Please enter your Citrix credentials" -ForegroundColor Green
            $null = BetterCredentials\Get-Credential -UserName $citrixUserName -Store
            $CitrixCredentials = (BetterCredentials\Get-Credential -UserName $citrixUserName -Store)
            $citrixUserName = $CitrixCredentials.UserName
            $CitrixCredentialsPassword = $CitrixCredentials.Password
            # Create JSON object to store citrixUserName
            $jsonObj = @{
                "citrixUserName" = "$citrixUserName"
            }
            # Convert object to JSON
            $json = $jsonObj | ConvertTo-Json
            # Save JSON to file
            $json | Set-Content -Path $scriptParametersFile -Force
            Write-Host -Object "Citrix credentials were saved!" -ForegroundColor Green
        }

        # Decrypt Citrix account password
        $citrixPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($CitrixCredentialsPassword))

        # Download latest version
        Write-Log -Message "Downloading $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Get-CitrixDownload -dlNumber $appDlNumber -dlEXE $appZip -CitrixUserName $citrixUserName -CitrixPassword $citrixPassword -dlPath .\

        # Verify if downloaded file is present
        If ([bool](Get-ChildItem -Path $appScriptPath\$appVersion -Filter *.zip))
        {
            # Expand archive
            Expand-Archive -Path $appZip -DestinationPath $appScriptPath\$appVersion
            # Move the policy definitions files
            Copy-File -Path "$appScriptPath\$appVersion\Agent Group Policies\ADMX\*" -Destination "$appScriptPath\PolicyDefinitions" -Recurse
            Copy-File -Path "$appScriptPath\$appVersion\Configuration Templates" -Destination "$appScriptPath" -Recurse

            # Cleanup
            Remove-Folder -Path "$appScriptPath\$appVersion\Agent Group Policies"
            Remove-Folder -Path "$appScriptPath\$appVersion\Configuration Templates"
            Remove-File -Path $appZip
        }
        Else
        {
            Write-Log -Message "Unable to find $appZip, download failed! Verify your Citrix credentials." -Severity 3 -LogType CMTrace -WriteHost $True
            Start-Sleep -Seconds 3
            Exit-Script
        }
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

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
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\AgentCacheUtility.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\AgentGroupPolicyUtility.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\AppInfoViewer.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\Agent Log Parser.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\AppsMgmtUtil.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\Citrix.Wem.Agent.EnrollmentUtility.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\Citrix.Wem.Agent.Service.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\Citrix.Wem.Agent.LogonService.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\PrnsMgmtUtil.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\VUEMAppCmd.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\VUEMAppCmdDbg.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\VUEMAppHide.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\VUEMCmdAgent.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\VUEMMaintMsg.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\VUEMRSAV.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\VUEMUIAgent.exe" -Force

    # Remove logs and cache files
    Get-Process -Name $appProcesses | Stop-Process -Force
    Remove-File -Path "$env:ProgramData\Citrix\WEM\*.log"
    Remove-File -Path "${env:ProgramFiles(x86)}\Citrix\Workspace Environment Management Agent\Local Databases\*.*"

    # Configure application shortcut
    New-Shortcut -Path "$envCommonStartMenuPrograms\$appVendor WEM Agent Log Parser.lnk" -TargetPath "$appDestination\Agent Log Parser.exe"
    New-Shortcut -Path "$envCommonStartMenuPrograms\$appVendor WEM Resultant Actions Viewer.lnk" -TargetPath "$appDestination\VUEMRSAV.exe"
    New-Shortcut -Path "$envCommonStartMenuPrograms\Administrative Tools\$appVendor WEM Application Info Viewer.lnk" -TargetPath "$appDestination\AppInfoViewer.exe"
    New-Shortcut -Path "$envCommonStartMenuPrograms\Administrative Tools\$appVendor WEM Manage Applications.lnk" -TargetPath "$appDestination\AppsMgmtUtil.exe"
    New-Shortcut -Path "$envCommonStartMenuPrograms\Administrative Tools\$appVendor WEM Manage Printers.lnk" -TargetPath "$appDestination\PrnsMgmtUtil.exe"
    Remove-File -Path "$envCommonStartMenuPrograms\$appVendor\WEM Enrollment Registration Utility.lnk" -ContinueOnError $True
    New-Shortcut -Path "$envCommonStartMenuPrograms\Administrative Tools\$appVendor WEM Enrollment Registration Utility.lnk" -TargetPath "$appDestination\Citrix.Wem.Agent.Enrollment.RegUtility.exe"

    Write-Log -Message "$appVendor $appName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
}
ElseIf (([version]$appVersion -eq [version]$appInstalledVersion) -and ($appInstalledFile -eq $false))
{
    Write-Log -Message "$appVendor $appName $appInstalledVersion installation is broken. It will now be reinstalled!" -Severity 2 -LogType CMTrace -WriteHost $True

    # Detect if setup file is present
    If (-Not(Test-Path -Path "$appScriptPath\$appVersion\$appSetup"))
    {
        # Get Citrix account credentials
        If ($null -eq $citrixUserName)
        {
            $citrixUserName = "myCitrixUserName"
        }
        Else
        {
            [bool]$isCitrixCredentialsStored = [bool](Find-Credential -Filter "*$citrixUserName")
        }
        # Read stored credentials
        If ($isCitrixCredentialsStored)
        {
            Write-Host -Object "Stored credentials found for Citrix Account." -ForegroundColor Green
            $CitrixCredentials = (BetterCredentials\Get-Credential -UserName $citrixUserName -Store)
            $citrixUserName = $CitrixCredentials.UserName
            $CitrixCredentialsPassword = $CitrixCredentials.Password
        }
        Else
        {
            # Ask for credentials
            Write-Host -Object "Please enter your Citrix credentials" -ForegroundColor Green
            $null = BetterCredentials\Get-Credential -UserName $citrixUserName -Store
            $CitrixCredentials = (BetterCredentials\Get-Credential -UserName $citrixUserName -Store)
            $citrixUserName = $CitrixCredentials.UserName
            $CitrixCredentialsPassword = $CitrixCredentials.Password
            # Create JSON object to store citrixUserName
            $jsonObj = @{
                "citrixUserName" = "$citrixUserName"
            }
            # Convert object to JSON
            $json = $jsonObj | ConvertTo-Json
            # Save JSON to file
            $json | Set-Content -Path $scriptParametersFile -Force
            Write-Host -Object "Citrix credentials were saved!" -ForegroundColor Green
        }

        # Decrypt Citrix account password
        $citrixPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($CitrixCredentialsPassword))

        # Download latest version
        Write-Log -Message "Downloading $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Get-CitrixDownload -dlNumber $appDlNumber -dlEXE $appZip -CitrixUserName $citrixUserName -CitrixPassword $citrixPassword -dlPath .\
        # Expand archive
        If (Get-ChildItem -Path $appScriptPath\$appVersion -Filter *.zip)
        {
            Expand-Archive -Path $appZip -DestinationPath $appScriptPath\$appVersion
            # Move the policy definitions files
            Copy-File -Path "$appScriptPath\$appVersion\Agent Group Policies\ADMX\*" -Destination "$appScriptPath\PolicyDefinitions" -Recurse
            Copy-File -Path "$appScriptPath\$appVersion\Configuration Templates" -Destination "$appScriptPath" -Recurse

            # Cleanup
            Remove-Folder -Path "$appScriptPath\$appVersion\Agent Group Policies"
            Remove-Folder -Path "$appScriptPath\$appVersion\Configuration Templates"
            Remove-File -Path $appZip
        }
        Else
        {
            Write-Log -Message "Unable to find $appZip, download failed!" -Severity 3 -LogType CMTrace -WriteHost $True
            Start-Sleep -Seconds 3
            Exit-Script
        }
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

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
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\AgentCacheUtility.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\AgentGroupPolicyUtility.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\AppInfoViewer.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\Agent Log Parser.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\AppsMgmtUtil.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\Citrix.Wem.Agent.EnrollmentUtility.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\Citrix.Wem.Agent.Service.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\Citrix.Wem.Agent.LogonService.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\PrnsMgmtUtil.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\VUEMAppCmd.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\VUEMAppCmdDbg.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\VUEMAppHide.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\VUEMCmdAgent.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\VUEMMaintMsg.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\VUEMRSAV.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\Workspace Environment Management Agent\VUEMUIAgent.exe" -Force

    # Remove logs and cache files
    Remove-File -Path "$env:ProgramData\Citrix\WEM\*.log"

    # Configure application shortcut
    New-Shortcut -Path "$envCommonStartMenuPrograms\$appVendor WEM Agent Log Parser.lnk" -TargetPath "$appDestination\Agent Log Parser.exe"
    New-Shortcut -Path "$envCommonStartMenuPrograms\$appVendor WEM Resultant Actions Viewer.lnk" -TargetPath "$appDestination\VUEMRSAV.exe"
    New-Shortcut -Path "$envCommonStartMenuPrograms\Administrative Tools\$appVendor WEM Application Info Viewer.lnk" -TargetPath "$appDestination\AppInfoViewer.exe"
    New-Shortcut -Path "$envCommonStartMenuPrograms\Administrative Tools\$appVendor WEM Manage Applications.lnk" -TargetPath "$appDestination\AppsMgmtUtil.exe"
    New-Shortcut -Path "$envCommonStartMenuPrograms\Administrative Tools\$appVendor WEM Manage Printers.lnk" -TargetPath "$appDestination\PrnsMgmtUtil.exe"
    Remove-File -Path "$envCommonStartMenuPrograms\$appVendor\WEM Enrollment Registration Utility.lnk" -ContinueOnError $True
    New-Shortcut -Path "$envCommonStartMenuPrograms\Administrative Tools\$appVendor WEM Enrollment Registration Utility.lnk" -TargetPath "$appDestination\Citrix.Wem.Agent.Enrollment.RegUtility.exe"

    Write-Log -Message "$appVendor $appName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
}
ElseIf (([version]$appVersion -eq [version]$appInstalledVersion) -and ($appInstalledFile -eq $true))
{
    # Stop processes
    Get-Process -Name $appProcesses | Stop-Process -Force

    # Remove logs and cache files
    Remove-File -Path "$env:ProgramData\Citrix\WEM\*.log"
    Remove-File -Path "${env:ProgramFiles(x86)}\Citrix\Workspace Environment Management Agent\Local Databases\*.*"

    Write-Log -Message "$appVendor $appName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}

#endregion