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
#endregion

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$appVendor = "Microsoft"
$appName = "OneDrive"
$appLongName = "for Business"
$appProcesses = @("OneDrive", "explorer")
$appServices = @("OneDrive Updater Service")
$appInstallParameters = "/allusers /silent"
$appArchitecture = "AMD64"
$appRing = "Insider"
$Evergreen = (Get-EvergreenApp -Name MicrosoftOneDrive | Where-Object {$_.Architecture -eq $appArchitecture -and $_.Ring -eq $appRing -and $_.Type -eq "exe"}) | `
    Sort-Object -Property @{ Expression = { [System.Version]$_.Version }; Descending = $true } | Select-Object -First 1
$appVersion = $Evergreen.Version
$appURL = $Evergreen.URI
$appSetup = Split-Path -Path $appURL -Leaf
$appModuleURL = "https://github.com/rodneyviana/ODSyncService/raw/master/Binaries/PowerShell/OneDriveLib.dll"
$GitHubReleases = "https://api.github.com/repos/rodneyviana/ODSyncService/releases"
$appModuleVersion = (Invoke-WebRequest -UseBasicParsing -Uri $GitHubReleases | ConvertFrom-Json)[0].tag_name
$appModule = Split-Path -Path $appModuleURL -Leaf
$appDestination = "${env:ProgramFiles}\Microsoft OneDrive"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName")
$appInstalledVersion = (Get-InstalledApplication -Name "$appVendor $appName").DisplayVersion
$appUninstallString = ((Get-InstalledApplication -Name "$appVendor $appName").UninstallString).Split("/")[0]
$appUninstallParameters = ((Get-InstalledApplication -Name "$appVendor $appName").UninstallString).TrimStart($appUninstallString)

#-----------------------------------------------------------[Execution]------------------------------------------------------------

If ([version]$appVersion -gt [version]$appInstalledVersion)
{
    Set-Location -Path $appScriptPath
    If (-Not(Test-Path -Path $appVersion))
    {
        New-Folder -Path $appVersion
    }
    Set-Location -Path $appVersion

    # Download latest setup file(s)
    If (-Not(Test-Path -Path $appScriptPath\$appVersion\$appSetup))
    {
        Write-Log -Message "Downloading $appVendor $appName $appLongName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURL -OutFile $appSetup
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Uninstall previous versions
    Get-Process -Name $appProcesses | Stop-Process -Force
    If ($IsAppInstalled)
    {
        Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
        Execute-Process -Path $appUninstallString -Parameters $appUninstallParameters
    }

    # Uninstall built-in OneDrive
    If (Test-Path "$envWinDir\System32\OneDriveSetup.exe")`

    {
        Execute-Process -Path "$envWinDir\System32\OneDriveSetup.exe" -Parameters "/uninstall"
    }
    If (Test-Path "$envWinDir\SysWOW64\OneDriveSetup.exe")`

    {
        Execute-Process -Path "$envWinDir\SysWOW64\OneDriveSetup.exe" -Parameters "/uninstall" -UseShellExecute -IgnoreExitCodes "-2147219813"

        # Take Ownsership of OneDriveSetup.exe
        $ACL = Get-ACL -Path "$envWinDir\SysWOW64\OneDriveSetup.exe"
        $Group = New-Object System.Security.Principal.NTAccount("$envUserName")
        $ACL.SetOwner($Group)
        Set-Acl -Path "$envWinDir\SysWOW64\OneDriveSetup.exe" -AclObject $ACL

        # Assign Full R/W Permissions to $envUserName (Administrator)
        $Acl = Get-Acl "$envWinDir\SysWOW64\OneDriveSetup.exe"
        $Ar = New-Object  system.security.accesscontrol.filesystemaccessrule("$envUserName", "FullControl", "Allow")
        $Acl.SetAccessRule($Ar)
        Set-Acl "$envWinDir\SysWOW64\OneDriveSetup.exe" $Acl

        # Take Ownsership of OneDrive.ico
        $ACL = Get-ACL -Path "$envWinDir\SysWOW64\OneDriveSetup.exe"
        $Group = New-Object System.Security.Principal.NTAccount("$envUserName")
        $ACL.SetOwner($Group)
        Set-Acl -Path "$envWinDir\SysWOW64\OneDriveSetup.exe" -AclObject $ACL

        # Assign Full R/W Permissions to $envUserName (Administrator)
        $Acl = Get-Acl "$env:SystemRoot\SysWOW64\OneDrive.ico"
        $Ar = New-Object  system.security.accesscontrol.filesystemaccessrule("$envUserName", "FullControl", "Allow")
        $Acl.SetAccessRule($Ar)
        Set-Acl "$env:SystemRoot\SysWOW64\OneDrive.ico" $Acl

        Remove-File -Path "$envWinDir\SysWOW64\OneDriveSetup.exe"
        Remove-File -Path "$envWinDir\SysWOW64\OneDrive.ico"
    }
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive"

    # Remove left over files
    Remove-File -Path "$envWinDir\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" -ContinueOnError $True
    Remove-File -Path "$envWinDir\ServiceProfiles\NetworkService\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" -ContinueOnError $True
    Remove-Folder -Path "$envProgramData\Microsoft\OneDrive" -ContinueOnError $True
    Remove-Folder -Path "$envSystemDrive\OneDriveTemp" -ContinueOnError $True

    # Remove user install
    $OneDriveUsers = Get-ChildItem -Path "$($envSystemDrive)\Users"
    $OneDriveUsers | ForEach-Object {
        Try
        {
            If (Test-Path "$($envSystemDrive)\Users\$($_.Name)\AppData\Local\Microsoft\OneDrive.exe")
            {
                Remove-Folder -Path "$($envSystemDrive)\Users\$($_.Name)\AppData\Local\Microsoft\OneDrive" -ContinueOnError $True
                Remove-Folder -Path "$($envSystemDrive)\Users\$($_.Name)\OneDrive" -ContinueOnError $True
                Remove-File -Path "$($envSystemDrive)\Users\$($_.Name)\AppData\Roaming\$appVendor\Windows\Start Menu\Programs\OneDrive.lnk" -ContinueOnError $True
            }
        }
        Catch
        {
            Out-Null
        }
    }

    # Remove remaining OneDrive entries WinSxS folders
    #ForEach ($Item in Get-ChildItem -Path "$envWinDir\WinSxS\*onedrive*")
    #{
    #    Execute-Process -Path "$envWinDir\System32\takeown.exe" -Parameters "/F $Item.FullName /R /A"
    #    [void](Grant-FolderOwnership -Path $Item.FullName)
    #    Remove-Folder -Path $Item.FullName -ContinueOnError $True
    #}

    # Removes OneDrive from File Explorer
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\Wow6432Node\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse

    Write-Log -Message "Installing $appVendor $appName $appLongName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    Execute-Process -Path .\$appSetup -Parameters $appInstallParameters

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

    # Load the Default User registry hive
    Start-Sleep -Seconds 5
    Execute-Process -Path "$envWinDir\System32\reg.exe" -Parameters "LOAD HKLM\DefaultUser $envSystemDrive\Users\Default\NTUSER.DAT" -WindowStyle Hidden

    # Set OneDriveSetup variable
    $regOneDriveSetup = Get-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Run" -Value "OneDriveSetup"

    # Remove the built-in OneDrive setup from running on new user profile
    # https://byteben.com/bb/installing-the-onedrive-sync-client-in-per-machine-mode-during-your-task-sequence-for-a-lightening-fast-first-logon-experience
    If ($regOneDriveSetup)
    {
        Remove-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Run" -Name "OneDriveSetup"
    }

    # Cleanup (to prevent access denied issue unloading the registry hive)
    Get-Variable reg* | Remove-Variable
    [GC]::Collect()
    Start-Sleep -Seconds 5

    # Unload the Default User registry hive
    Execute-Process -Path "$envWinDir\System32\reg.exe" -Parameters "UNLOAD HKLM\DefaultUser" -WindowStyle Hidden

    # Cleanup temp files
    Remove-Item -Path "$envSystemDrive\Users\Default\*.LOG1" -Force
    Remove-Item -Path "$envSystemDrive\Users\Default\*.LOG2" -Force
    Remove-Item -Path "$envSystemDrive\Users\Default\*.blf" -Force
    Remove-Item -Path "$envSystemDrive\Users\Default\*.regtrans-ms" -Force

    # Stop and disable unneeded scheduled tasks
    Get-ScheduledTask -TaskName "$appName*" | Stop-ScheduledTask
    Get-ScheduledTask -TaskName "$appName*" | Disable-ScheduledTask

    # Stop and disable unneeded services
    Stop-ServiceAndDependencies -Name $appServices[0]
    Set-ServiceStartMode -Name $appServices[0] -StartMode "Disabled"

    # Download OneDrive Status powershell module - https://github.com/rodneyviana/ODSyncService/tree/master/Binaries/PowerShell
    If (-Not(Test-Path -Path $appScriptPath\PSModule\$appModuleVersion\$appModule))
    {
        Write-Log -Message "Downloading $appVendor $appName $appLongName $appModule..." -Severity 1 -LogType CMTrace -WriteHost $True
        New-Folder -Path "$appScriptPath\PSModule\$appModuleVersion"
        Invoke-WebRequest -UseBasicParsing -Uri $appModuleURL -OutFile $appScriptPath\PSModule\$appModuleVersion\$appModule
        If (-Not(Test-Path -Path "$envProgramFiles\WindowsPowerShell\Modules\ODStatus\$appModule"))
        {
            Copy-File -Path "$appScriptPath\PSModule\$appModuleVersion\$appModule" -Destination "$envProgramFiles\WindowsPowerShell\Modules\ODStatus"
        }

    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Go back to the parent folder
    Set-Location ..

    Write-Log -Message "$appVendor $appName $appLongName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
}
Else
{
    Write-Log -Message "$appVendor $appName $appLongName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}