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
$appName = "Edge"
$appLongName = "for Business"
$appSetup = "MicrosoftEdgeEnterpriseX64.msi"
$appProcesses = @("msedge", "MicrosoftEdgeUpdate", "MicrosoftEdgeUpdateBroker", "MicrosoftEdgeUpdateCore", "msedgewebview2", "elevation_service")
$appServices = @("edgeupdate", "edgeupdatem", "MicrosoftEdgeElevationService")
$appInstallParameters = "/QB"
$appAddParameters = "DONOTCREATEDESKTOPSHORTCUT=TRUE DONOTCREATETASKBARSHORTCUT=TRUE"
$Evergreen = Get-MicrosoftEdge | Where-Object { $_.Architecture -eq "x64" -and $_.Channel -eq "Stable" -and $_.Platform -eq "Windows" }
$appVersion = $Evergreen.Version
$appURL = $Evergreen.URI
$appURLADMX = (Get-MicrosoftEdge | Where-Object { $_.Channel -eq "Policy" }).URI
$appADMX = ($appURLADMX).Split("/")[6]
$appSource = $appVersion
$appDestination = "${env:ProgramFiles(x86)}\$appVendor\$appName\Application"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName" -Exact)
$appInstalledVersion = (Get-InstalledApplication -Name "$appVendor $appName" -Exact).DisplayVersion | Select-Object -First 1
##*===============================================

If ([version]$appVersion -gt [version]$appInstalledVersion) {
    Set-Location -Path $appScriptDirectory
    If (-Not(Test-Path -Path $appSource)) { New-Folder -Path $appSource }
    Set-Location -Path $appSource

    # Download latest file installer
    If (-Not(Test-Path -Path $appScriptDirectory\$appSource\$appSetup)) {
        Write-Log -Message "Downloading $appVendor $appName $appLongName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURL -OutFile $appSetup
    }
    Else {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Download latest policy definitions
    If (-Not(Test-Path -Path $appScriptDirectory\PolicyDefinitions\*.admx)) {
        Write-Log -Message "Downloading $appVendor $appName $appLongName $appVersion ADMX templates..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURLADMX -OutFile $appADMX
        New-Folder -Path "$appScriptDirectory\PolicyDefinitions"
        If (Get-ChildItem -Path -Filter *.cab) {
            Execute-Process -Path "$envSystem32Directory\cmd.exe" -Parameters "/C $envSystem32Directory\expand.exe `"$appScriptDirectory\$appVersion\$appADMX`" `"$appScriptDirectory\PolicyDefinitions\MicrosoftEdgePolicyTemplates.zip`""
            Remove-File -Path $appADMX -ContinueOnError $True
        }
        If (Get-ChildItem -Path $appScriptDirectory\PolicyDefinitions\*.zip) {
            Expand-Archive -Path $appScriptDirectory\PolicyDefinitions\*.zip -DestinationPath $appScriptDirectory\PolicyDefinitions -Force
            Remove-File -Path $appScriptDirectory\PolicyDefinitions\*.zip -ContinueOnError $True
        }
        If (Get-ChildItem -Path *.zip) {
            Expand-Archive -Path $appADMX -DestinationPath $appScriptDirectory\PolicyDefinitions -Force
            Remove-File -Path $appADMX -ContinueOnError $True
        }
        Move-Item -Path $appScriptDirectory\PolicyDefinitions\windows\admx\* -Destination $appScriptDirectory\PolicyDefinitions -Force
        Remove-Item -Path $appScriptDirectory\PolicyDefinitions -Include "examples", "html", "mac", "windows", "$appADMX", "VERSION" -Force -Recurse
    }
    Else {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    Get-Process -Name $appProcesses | Stop-Process -Force

    # Delete machine policies to prevent issue during installation
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\Policies\$appVendor\Update" -Recurse -ContinueOnError $True
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\Policies\$appVendor\$appName" -Recurse -ContinueOnError $True
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Policies\$appVendor\Temp" -Recurse -ContinueOnError $True
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Policies\$appVendor\Update" -Recurse -ContinueOnError $True
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Policies\$appVendor\$appName" -Recurse -ContinueOnError $True

    # Uninstall previous versions
    If ($IsAppInstalled) {
        Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
        Remove-MSIApplications -Name "$appVendor $appName" -Parameters $appInstallParameters
    }

    # Uninstall Microsoft Edge Update
    If (Test-Path -Path "$envLocalAppData\$appVendor\$($appName)Update\$appVendor$($appName)Update.exe") {
        Write-Log -Message "Removing previous $appVendor $appName $appLongName folder to fix issues with new installation." -Severity 1 -LogType CMTrace -WriteHost $True
        Execute-Process -Path "$envLocalAppData\$appVendor\$($appName)Update\$appVendor$($appName)Update.exe" -Parameters "-uninstall" -IgnoreExitCodes 1606220281 -ContinueOnError $True
    }
    If (Test-Path -Path "$envProgramFilesX86\$appVendor\$($appName)Update\$appVendor$($appName)Update.exe") {
        Write-Log -Message "Removing previous $appVendor $appName $appLongName folder to fix issues with new installation." -Severity 1 -LogType CMTrace -WriteHost $True
        Execute-Process -Path "$envProgramFilesX86\$appVendor\$($appName)Update\$appVendor$($appName)Update.exe" -Parameters "-uninstall" -IgnoreExitCodes 1606220281 -ContinueOnError $True
    }

    # Remove previous install folders
    Remove-Folder -Path "$envLocalAppData\$appVendor\$appName" -ContinueOnError $True
    Remove-Folder -Path "$envLocalAppData\$appVendor\$($appName)Update" -ContinueOnError $True
    Remove-Folder -Path "$envLocalAppData\$appVendor\Temp" -ContinueOnError $True
    Remove-Folder -Path "$envProgramFilesX86\$appVendor\$appName" -ContinueOnError $True
    Remove-Folder -Path "$envProgramFilesX86\$appVendor\$($appName)Update" -ContinueOnError $True
    Remove-Folder -Path "$envProgramFilesX86\$appVendor\Temp" -ContinueOnError $True

    Write-Log -Message "Installing $appVendor $appName $appLongName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    Execute-MSI -Action Install -Path $appSetup -Parameters $appInstallParameters #-AddParameters $appAddParameters

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

    # Copy preferences file
    Copy-File -Path "$appScriptDirectory\master_preferences" -Destination $appDestination

    # Stop and disable unneeded scheduled tasks
    Get-ScheduledTask -TaskName "$appVendor$appName*" | Stop-ScheduledTask
    Get-ScheduledTask -TaskName "$appVendor$appName*" | Disable-ScheduledTask

    # Stop and disable unneeded services
    Stop-ServiceAndDependencies -Name $appServices[0]
    Stop-ServiceAndDependencies -Name $appServices[1]
    Stop-ServiceAndDependencies -Name $appServices[2]
    Set-ServiceStartMode -Name $appServices[0] -StartMode "Disabled"
    Set-ServiceStartMode -Name $appServices[1] -StartMode "Disabled"
    Set-ServiceStartMode -Name $appServices[3] -StartMode "Disabled"

    # Creates a pinned taskbar icons for all users
    New-Shortcut -Path "$envSystemDrive\Users\Default\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\Taskbar\$appVendor $appName.lnk" -TargetPath "$appDestination\$($appProcesses[0]).exe" -IconLocation "$appDestination\$($appProcesses[0]).exe" -Description "$appVendor $appName" -WorkingDirectory "$appDestination"

    # Remove Active Setup
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{9459C573-B17A-45AE-9F64-1857B5D58CEE}" -Name "StubPath"

    # Remove desktop shortcut for all users
    #Remove-File "$envCommonDesktop\$appVendor $appName.lnk" -ContinueOnError $True

    # Disable Citrix API hook - https://discussions.citrix.com/topic/406494-microsoft-new-edge-ready-for-citrix-terminal-serves
    # https://blog.vermeerschconsulting.be/index.php/2020/04/23/edge-chromium-in-citrix-virtual-apps-server-2016-or-2019-with-a-working-smart-card-reader
    $regKey = "HKLM:\SOFTWARE\Citrix\CtxHook\AppInit_Dlls\SfrHook"
    $regKeyProcess = "$($appProcesses[0]).exe"
    If ((Test-Path -Path $regKey) -and (-Not(Test-Path -Path $regKey\$regKeyProcess))) {
        Write-Log -Message "Fixing Citrix API Hook..." -Severity 1 -LogType CMTrace -WriteHost $True
        # Add the msedge.exe key
        Set-RegistryKey -Key $regKey\$regKeyProcess -Value "(Default)"
    }

    Update-GroupPolicy

    Write-Log -Message "$appVendor $appName $appLongName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True

}
Else {
    Write-Log -Message "$appVendor $appName $appLongName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}

<#
Write-Verbose -Message "Uninstalling custom modules..." -Verbose
Foreach ($Module in $Modules) {
    If ((Get-Module -ListAvailable -Name $Module)) {Uninstall-Module -Name $Module -Force}
}
Write-Verbose -Message "Custom modules were succesfully uninstalled!" -Verbose
#>