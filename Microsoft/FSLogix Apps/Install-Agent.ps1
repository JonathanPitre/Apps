# PowerShell Wrapper for MDT, Standalone and Chocolatey Installation - (C)2020 Jonathan Pitre, inspired by xenappblog.com
# Example 1 Install EXE:
# Execute-Process -Path .\appName.exe -Parameters "/silent"
# Example 2 Install MSI:
# Execute-MSI -Action Install -Path appName.msi -Parameters "/QB" -AddParameters "ALLUSERS=1"
# Example 3 Uninstall MSI:
# Remove-MSIApplications -Name "appName" -Parameters "/QB"

#Requires -Version 5.1

# Custom package providers list
$PackageProviders = @("Nuget")

# Custom modules list
$Modules = @("PSADT", "Evergreen")

Set-ExecutionPolicy -ExecutionPolicy Bypass -Force

# Checking for elevated permissions...
If (-not([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning -Message "Insufficient permissions to continue! PowerShell must be run with admin rights."
    Break
}
Else {
    Write-Verbose -Message "Importing custom modules..." -Verbose

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials

    # Install custom package providers list
    Foreach ($PackageProvider in $PackageProviders) {
        If (-not(Get-PackageProvider -ListAvailable -Name $PackageProvider -ErrorAction SilentlyContinue)) { Install-PackageProvider -Name $PackageProvider -Force }
    }

    # Add the Powershell Gallery as trusted repository
    Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted

    # Update PowerShellGet
    $InstalledPSGetVersion = (Get-PackageProvider -Name PowerShellGet).Version
    $PSGetVersion = [version](Find-PackageProvider -Name PowerShellGet).Version
    If ($PSGetVersion -gt $InstalledPSGetVersion) { Install-PackageProvider -Name PowerShellGet -Force }

    # Install and import custom modules list
    Foreach ($Module in $Modules) {
        If (-not(Get-Module -ListAvailable -Name $Module)) { Install-Module -Name $Module -AllowClobber -Force | Import-Module -Name $Module -Force }
        Else {
            $InstalledModuleVersion = (Get-InstalledModule -Name $Module).Version
            $ModuleVersion = (Find-Module -Name $Module).Version
            $ModulePath = (Get-InstalledModule -Name $Module).InstalledLocation
            $ModulePath = (Get-Item -Path $ModulePath).Parent.FullName
            If ([version]$ModuleVersion -gt [version]$InstalledModuleVersion) {
                Update-Module -Name $Module -Force
                Remove-Item -Path $ModulePath\$InstalledModuleVersion -Force -Recurse
            }
        }
    }

    Write-Verbose -Message "Custom modules were successfully imported!" -Verbose
}

# Get the current script directory
Function Get-ScriptDirectory {
    Remove-Variable appScriptDirectory
    Try {
        If ($psEditor) { Split-Path $psEditor.GetEditorContext().CurrentFile.Path } # Visual Studio Code Host
        ElseIf ($psISE) { Split-Path $psISE.CurrentFile.FullPath } # Windows PowerShell ISE Host
        ElseIf ($PSScriptRoot) { $PSScriptRoot } # Windows PowerShell 3.0-5.1
        Else {
            Write-Host -ForegroundColor Red "Cannot resolve script file's path"
            Exit 1
        }
    }
    Catch {
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
$appName = "FSLogix Apps"
$appSetup = "FSLogixAppsSetup.exe"
$appProcess = @("frxsvc", "frxtray", "frxshell", "frxccds")
$appInstallParameters = "/install /quiet /norestart"
$Evergreen = Get-MicrosoftFSLogixApps
$appVersion = $Evergreen.Version
$appURL = $Evergreen.URI
$appURLScript = "https://raw.githubusercontent.com/FSLogix/Invoke-FslShrinkDisk/master/Invoke-FslShrinkDisk.ps1"
$appZip = "FSLogix Apps.zip"
$appSource = "$appVersion"
$appDestination = "$env:ProgramFiles\FSLogix\Apps"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName" -Exact) | Select-Object -Last 1
$appInstalledVersion = (Get-InstalledApplication -Name "$appVendor $appName" -Exact).DisplayVersion | Select-Object -Last 1
##*===============================================

If ([version]$appVersion -gt [version]$appInstalledVersion) {
    Set-Location -Path $appScriptDirectory
    If (-Not(Test-Path -Path $appSource)) {New-Folder -Path $appSource}
    Set-Location -Path $appSource

    If (-Not(Test-Path -Path $appScriptDirectory\$appSource\x64\Release\$appSetup)) {
        Write-Log -Message "Downloading $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURL -OutFile $appZip
        Expand-Archive -Path $appZip -DestinationPath $appScriptDirectory\$appSource
        # Move the policy definitions files
        If (-Not(Test-Path -Path "$appScriptDirectory\PolicyDefinitions")) {New-Folder -Path "$appScriptDirectory\PolicyDefinitions"}
        If (-Not(Test-Path -Path "$appScriptDirectory\PolicyDefinitions\en-US")) {New-Folder -Path "$appScriptDirectory\PolicyDefinitions\en-US"}
        Move-Item -Path .\fslogix.admx -Destination "$appScriptDirectory\PolicyDefinitions\fslogix.admx" -Force
        Move-Item -Path .\fslogix.adml -Destination "$appScriptDirectory\PolicyDefinitions\en-US\fslogix.adml" -Force
        Remove-File -Path $appZip
    }
    Else {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Download latest version of Jim Moyle's Invoke-FslShrinkDisk.ps1 script
    Invoke-WebRequest -UseBasicParsing -Uri $appURLScript -OutFile "$appScriptDirectory\FileServer Maintenance\Invoke-FslShrinkDisk.ps1"

    Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
    Get-Process -Name $appProcess | Stop-Process -Force

    Write-Log -Message "Installing $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    Execute-Process -Path .\x64\Release\$appSetup -Parameters $appInstallParameters

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

    # Add shortcut on the Start Menu
    New-Folder -Path "$envCommonStartMenuPrograms\Troubleshooting Tools" -ContinueOnError $True
    New-Shortcut -Path "$envCommonStartMenuPrograms\Troubleshooting Tools\FSLogix Tray Icon.lnk" -TargetPath "$appDestination\frxtray.exe" -IconLocation "$appDestination\frxtray.exe" -Description "FSLogix Tray Icon" -WorkingDirectory "$appDestination"

    # Enable FSLogix Apps agent search roaming - Apply different configurations based on operating system
    If (-not(Get-ItemProperty -Path "HKLM:SOFTWARE\FSLogix\Apps" -Name "RoamSearch")) {
        If ($envOSName -Like "*Windows Server 2012*" -or $envOSName -Like "*Windows Server 2016") {
            # Install Windows Search feature when missing, if Office was installed before it must be repair!
            If (!(Get-WindowsFeature -Name Search-Service)) {Install-WindowsFeature Search-Service}
        }
        If ($envOSName -Like "*Windows Server 201*" -or $envOSName -eq "Microsoft Windows 10 Enterprise for Virtual Desktops") {
            # Limit Windows Search to a single cpu core - https://social.technet.microsoft.com/Forums/en-US/88725f57-67ed-4c09-8ae6-780ff785e555/problems-with-search-service-on-server-2012-r2-rds?forum=winserverTS
            Set-RegistryKey -Key "HKLM\SOFTWARE\Microsoft\Windows Search" -Name "CoreCount" -Type "DWord" -Value "1"
            # Configure multi-user search - https://docs.microsoft.com/en-us/fslogix/configure-search-roaming-ht
            Set-RegistryKey -Key "HKLM\SOFTWARE\FSLogix\Apps" -Name "RoamSearch" -Type "DWord" -Value "2"
            Set-RegistryKey -Key "HKLM\SOFTWARE\FSLogix\Profiles" -Name "RoamSearch" -Type "DWord" -Value "2"
        }
        If ($envOSName -Like "*Windows Server 2019*" -or $envOSName -eq "Microsoft Windows 10 Enterprise for Virtual Desktops") {
            # Disable built-in Windnows per user search catalog since it's buggy - https://support.citrix.com/article/CTX270433
            # https://jkindon.com/2020/03/15/windows-search-in-server-2019-and-multi-session-windows-10
            Set-RegistryKey -Key "HKLM\SOFTWARE\Microsoft\Windows Search" -Name "EnablePerUserCatalog" -Value 0 -Type "DWord"
        }
        If ($envOSName -Like "*Windows 10*" -and $envOSName -ne "Microsoft Windows 10 Enterprise for Virtual Desktops") {
            Set-RegistryKey -Key "HKLM\SOFTWARE\FSLogix\Apps" -Name "RoamSearch" -Type "DWord" -Value "1"
            Set-RegistryKey -Key "HKLM\SOFTWARE\FSLogix\Profiles" -Name "RoamSearch" -Type "DWord" -Value "1"
        }
        Else {
            Write-Log -Message "$appVendor $appNameSearch search roaming was enabled" -Severity 1 -LogType CMTrace -WriteHost $True
        }
    }

    # Configure Windows Search service auto-start and start it
    $serviceName = "WSearch"
    If ((Get-ServiceStartMode -Name $serviceName) -ne "Automatic (Delayed Start)") {Set-ServiceStartMode -Name $serviceName -StartMode "Automatic (Delayed Start)"}
    Start-ServiceAndDependencies -Name $serviceName

    # Fix for Citrix App Layering and FSLogix integration, must be done in the platform layer - https://social.msdn.microsoft.com/Forums/windows/en-US/660959a4-f9a9-486b-8a0d-dec3eba549e3/using-citrix-app-layering-unidesk-with-fslogix?forum=FSLogix
    # https://www.citrix.com/blogs/2020/01/07/citrix-app-layering-and-fslogix-profile-containers
    If ((Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\unifltr") -and (Get-RegistryKey -Key "HKLM\SYSTEM\CurrentControlSet\Services\frxdrvvt\Instances\frxdrvvt" -Value "Altitude") -ne 138010) {
        Write-Log -Message "Modifying $appVendor $appName altitude setting to be compatible with Citrix App Layering..." -Severity 1 -LogType CMTrace -WriteHost $True
        Set-RegistryKey -Key "HKLM\SYSTEM\CurrentControlSet\Services\frxdrvvt\Instances\frxdrvvt" -Name "Altitude" -Value "138010" -Type "String"
    }

    # Disable Citrix Profile Management if detected
    If ((Test-Path -Path "HKLM\SYSTEM\CurrentControlSet\Services\ctxProfile") -and (Get-RegistryKey -Key "HKLM\SOFTWARE\Policies\Citrix\UserProfileManager" -Value "PSEnabled") -ne "0") {
        Write-Log -Message "Disabling Citrix Profile Management..." -Severity 1 -LogType CMTrace -WriteHost $True
        Set-RegistryKey -Key "HKLM\SOFTWARE\Policies\Citrix\UserProfileManager" -Name "PSEnabled" -Value "0" -Type "DWord"
    }

    # Add Windows Defender exclusion(s) - https://docs.microsoft.com/en-us/azure/architecture/example-scenario/wvd/windows-virtual-desktop-fslogix
    Add-MpPreference -ExclusionPath "%ProgramFiles%\FSLogix\Apps\frxdrv.sys" -Force
    Add-MpPreference -ExclusionPath "%ProgramFiles%\FSLogix\Apps\frxdrvvt.sys" -Force
    Add-MpPreference -ExclusionPath "%ProgramFiles%\FSLogix\Apps\frxccd.sys" -Force
    Add-MpPreference -ExclusionPath "%TEMP%*.VHD" -Force
    Add-MpPreference -ExclusionPath "%TEMP%*.VHDX" -Force
    Add-MpPreference -ExclusionPath "%windir%\TEMP*.VHD" -Force
    Add-MpPreference -ExclusionPath "%windir%\TEMP*.VHDX" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles%\FSLogix\Apps\frxsvc.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles%\FSLogix\Apps\frxccds.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles%\FSLogix\Apps\frxsvc.exe" -Force
    #Add-MpPreference -ExclusionProcess "%ProgramFiles%\FSLogix\Apps\frx.exe" -Force

    Write-Log -Message "$appVendor $appName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True

}
Else {
    Write-Log -Message "$appVendor $appName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}

<#
Write-Verbose -Message "Uninstalling custom modules..." -Verbose
Foreach ($Module in $Modules) {
    If ((Get-InstalledModule -Name $Module)) {Uninstall-Module -Name $Module -Force}
    Write-Verbose -Message "Custom modules were uninstalled!" -Verbose
}
#>