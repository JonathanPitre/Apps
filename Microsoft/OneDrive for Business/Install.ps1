# Standalone application install script for VDI environment - (C)2021 Jonathan Pitre & Owen Reynolds, inspired by xenappblog.com

#Requires -Version 5.1
#Requires -RunAsAdministrator

# Custom package providers list
$PackageProviders = @("Nuget")

# Custom modules list
$Modules = @("PSADT", "Evergreen")

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
$appVendor = "Microsoft"
$appName = "OneDrive"
$appLongName = "for Business"
$appProcesses = @("OneDrive", "explorer")
$appServices = @("OneDrive Updater Service")
$appInstallParameters = "/allusers /silent"
$Evergreen = (Get-EvergreenApp -Name MicrosoftOneDrive | Where-Object {$_.Architecture -eq "AMD64" -and $_.Ring -eq "Insider" -and $_.Type -eq "exe"}) | `
    Sort-Object -Property @{ Expression = { [System.Version]$_.Version }; Descending = $true } | Select-Object -First 1
$appVersion = $Evergreen.Version
$appURL = $Evergreen.URI
$appSetup = Split-Path -Path $appURL -Leaf
$appDestination = "${env:ProgramFiles}\Microsoft OneDrive"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName")
$appInstalledVersion = (Get-InstalledApplication -Name "$appVendor $appName").DisplayVersion
$appUninstallString = ((Get-InstalledApplication -Name "$appVendor $appName").UninstallString).Split("/")[0]
$appUninstallParameters = ((Get-InstalledApplication -Name "$appVendor $appName").UninstallString).TrimStart($appUninstallString)
##*===============================================

If ([version]$appVersion -gt [version]$appInstalledVersion)
{
    Set-Location -Path $appScriptDirectory
    If (-Not(Test-Path -Path $appVersion))
    {
        New-Folder -Path $appVersion
    }
    Set-Location -Path $appVersion

    # Download latest setup file(s)
    If (-Not(Test-Path -Path $appScriptDirectory\$appVersion\$appSetup))
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
    Execute-Process -Path "$envWinDir\System32\reg.exe" -Parameters "LOAD HKLM\DefaultUser $envSystemDrive\Users\Default\NTUSER.DAT" -WindowStyle Hidden

    # Set OneDriveSetup variable
    $OneDriveSetup = Get-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Run" -Value "OneDriveSetup"

    # Remove the built-in OneDrive setup from running on new user profile
    # https://byteben.com/bb/installing-the-onedrive-sync-client-in-per-machine-mode-during-your-task-sequence-for-a-lightening-fast-first-logon-experience
    If ($OneDriveSetup)
    {
        Remove-RegistryKey -Key "HKLM:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Run" -Name "OneDriveSetup"
    }

    # Unload the Default User registry hive
    Execute-Process -Path "$envWinDir\System32\reg.exe" -Parameters "UNLOAD HKLM\DefaultUser" -WindowStyle Hidden

    # Cleanup temp files
    Remove-Item -Path "$envSystemDrive\Users\Default\*.LOG1" -Force
    Remove-Item -Path "$envSystemDrive\Users\Default\*.LOG2" -Force
    Remove-Item -Path "$envSystemDrive\Users\Default\*.blf" -Force
    Remove-Item -Path "$envSystemDrive\Users\Default\*.regtrans-ms" -Force

    # Get latest policy definitions
    If (Test-Path -Path "$appDestination\$appVersion\adm\$appName.admx")
    {
        Write-Log -Message "Copying $appVendor $appName $appLongName $appVersion ADMX templates..." -Severity 1 -LogType CMTrace -WriteHost $True
        Copy-File -Path "$appDestination\$appVersion\adm\$appName.admx" -Destination "$appScriptDirectory\PolicyDefinitions" -ContinueOnError $True
        Copy-File -Path "$appDestination\$appVersion\adm\$appName.adml" -Destination "$appScriptDirectory\PolicyDefinitions\en-US" -ContinueOnError $True
        Copy-File -Path "$appDestination\$appVersion\adm\fr\$appName.adml" -Destination "$appScriptDirectory\PolicyDefinitions\fr-FR" -ContinueOnError $True
    }

    # Stop and disable unneeded scheduled tasks
    Get-ScheduledTask -TaskName "$appName*" | Stop-ScheduledTask
    Get-ScheduledTask -TaskName "$appName*" | Disable-ScheduledTask

    # Stop and disable unneeded services
    Stop-ServiceAndDependencies -Name $appServices[0]
    Set-ServiceStartMode -Name $appServices[0] -StartMode "Disabled"

    Update-GroupPolicy

    # Go back to the parent folder
    Set-Location ..

    Write-Log -Message "$appVendor $appName $appLongName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
}
Else
{
    Write-Log -Message "$appVendor $appName $appLongName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}