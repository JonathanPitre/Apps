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
# Get the current script directory
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
Filter Get-FileSize
{
    "{0:N2} {1}" -f $(
        If ($_ -lt 1kb) { $_, 'Bytes' }
        ElseIf ($_ -lt 1mb) { ($_ / 1kb), 'KB' }
        ElseIf ($_ -lt 1gb) { ($_ / 1mb), 'MB' }
        ElseIf ($_ -lt 1tb) { ($_ / 1gb), 'GB' }
        ElseIf ($_ -lt 1pb) { ($_ / 1tb), 'TB' }
        Else { ($_ / 1pb), 'PB' }
    )
}
Function Get-Download
{
    Param (
        [Parameter(Mandatory = $true)]
        $Url,
        $Destination = $appScriptDirectory,
        $FileName,
        [switch]$IncludeStats
    )
    $destinationPath = Join-Path -Path $Destination -ChildPath $FileName
    $start = Get-Date
    Invoke-WebRequest -UseBasicParsing -Uri $Url -DisableKeepAlive -OutFile $destinationPath
    $timeElapsed = ((Get-Date) - $start).ToString('hh\:mm\:ss')
    $fileSize = (Get-Item -Path $destinationPath).Length | Get-FileSize
    If ($IncludeStats.IsPresent)
    {
        $downloadStats = [PSCustomObject]@{FileSize = $fileSize; Time = $timeElapsed}
        Write-Information -MessageData $downloadStats
    }
    Get-Item -Path $destinationPath| Unblock-File
}


# Variables Declaration
# Generic
$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"
$env:SEE_MASK_NOZONECHECKS = 1
$appScriptDirectory = Get-ScriptDirectory

# Application related
##*===============================================

Function Get-ZoomAdmx
{
    Try
    {
        $sourceUrl = "https://support.zoom.us/hc/en-us/articles/360039100051"
        # Grab content
        $web = Invoke-WebRequest -Uri $sourceUrl -UseBasicParsing
        # Find ADMX download
        $admxUrl = (($web.links | Where-Object {$_.href -like "*msi-templates*.zip"})[-1]).href
        # Grab version
        $admxVersion = ($admxUrl.Split("/")[-1] | Select-String -Pattern "(\d+(\.\d+){1,4})" -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value }).ToString()

        # Return object
        return @{ Version = $admxVersion; URI = $admxUrl }
    }
    Catch
    {
        Throw $_
    }
}

$appShortName = "Zoom"
$appName = "Zoom Client for VDI"
$appProcesses = @("Zoom", "Zoom_launcher", "ZoomOutlookIMPlugin")
$appInstallParameters = "/QB"
# https://support.zoom.us/hc/en-us/articles/201362163-Mass-Installation-and-Configuration-for-Windows
$appAddParameters = "zNoDesktopShortCut=1"
$Nevergreen = Get-NevergreenApp Zoom | Where-Object {$_.Name -like "*VDI Client" }
$appVersion = $Nevergreen.Version
$appURL = $Nevergreen.URI
$appSetup = Split-Path -Path $appURL -Leaf
$appDestination = "${env:ProgramFiles(x86)}\ZoomVDI\bin"
$appUninstallerURL = "https://support.zoom.us/hc/en-us/article_attachments/360084068792/CleanZoom.zip"
$appUninstallerZip = Split-Path -Path $appUninstallerURL -Leaf
$appUninstallerSetup = "CleanZoom.exe"
$appAdmxVersion = (Get-ZoomAdmx).Version
$appAdmxUrl = (Get-ZoomAdmx).URI
$appAdmx = Split-Path -Path $appAdmxUrl -Leaf
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appName")
$appInstalledVersion = If ($IsAppInstalled) { Get-FileVersion $appDestination\Zoom.exe }
$appInstalledVersion = $appInstalledVersion.Replace(",", ".").Split(".", 1).Substring(0, $appInstalledVersion.Length - 6)
##*===============================================

If ([version]$appVersion -gt [version]$appInstalledVersion)
{
    Set-Location -Path $appScriptDirectory
    If (-Not(Test-Path -Path $appVersion))
    {
        New-Folder -Path $appVersion
    }
    Set-Location -Path $appVersion

    # Download required cleanup tool
    If (-Not(Test-Path -Path $appScriptDirectory\$appUninstallerSetup))
    {
        Write-Log -Message "Downloading $appShortName Cleanup Tool..." -Severity 1 -LogType CMTrace -WriteHost $True
        Get-Download -Url $appUninstallerURL -Destination $appScriptDirectory -FileName $appUninstallerZip -IncludeStats
        Expand-Archive -Path $appScriptDirectory\$appUninstallerZip -DestinationPath $appScriptDirectory
        Remove-File -Path $appScriptDirectory\$appUninstallerZip
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Uninstall previous versions
    Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
    Get-Process -Name $appProcesses | Stop-Process -Force
    Remove-MSIApplications -Name "$appShortName" -Parameters $appInstallParameters -ContinueOnError $True
    Execute-Process -Path $appScriptDirectory\$appUninstallerSetup -Parameters "/silent"

    # Remove user install
    $ZoomUsers = Get-ChildItem -Path "$($env:SystemDrive)\Users"
    $ZoomUsers | ForEach-Object {
        Try
        {
            If (Test-Path "$($env:SystemDrive)\Users\$($_.Name)\AppData\Roaming\$appShortName\bin\$appShortName.exe")
            {
                Remove-Folder -Path "$($env:SystemDrive)\Users\$($_.Name)\AppData\Roaming\$appShortName" -ContinueOnError $True
                Remove-Folder -Path "$($env:SystemDrive)\Users\$($_.Name)\AppData\Roaming\$($appShortName)VDI" -ContinueOnError $True
                Remove-Folder -Path "$($env:SystemDrive)\Users\$($_.Name)\AppData\Roaming\Windows\Start Menu\Programs\$appShortName" -ContinueOnError $True
                Remove-Folder -Path "$($env:SystemDrive)\Users\$($_.Name)\AppData\Roaming\Windows\Start Menu\Programs\$appShortName VDI" -ContinueOnError $True
            }
        }
        Catch
        {
            Out-Null
        }
    }

    # Remove registry entries from all user profiles - https://www.reddit.com/r/SCCM/comments/fu3q6f/zoom_uninstall_if_anyone_needs_this_information
    [scriptblock]$HKCURegistrySettings = {
        Remove-RegistryKey -Key "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Zoom" -Recurse -ContinueOnError $True -SID $UserProfile.SID
        Remove-RegistryKey -Key "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\ZoomUMX" -Recurse -ContinueOnError $True -SID $UserProfile.SID
        Remove-RegistryKey -Key "HKCU:\Software\Zoom" -Recurse -ContinueOnError $True -SID $UserProfile.SID
        Remove-RegistryKey -Key "HKCU:\Software\ZoomUMX" -Recurse -ContinueOnError $True -SID $UserProfile.SID
        Remove-RegistryKey -Key "HKCU:\Software\Policies\Zoom\Zoom Meetings\VDI" -Recurse -ContinueOnError $True -SID $UserProfile.SID
    }
    Invoke-HKCURegistrySettingsForAllUsers -RegistrySettings $HKCURegistrySettings

    # Download latest policy definitions
    Write-Log -Message "Downloading $appShortName ADMX templates $appAdmxVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    Get-Download -Url $appAdmxUrl -Destination $appScriptDirectory $appAdmx -IncludeStats
    Expand-Archive -Path "$appScriptDirectory\$appAdmx" -DestinationPath "$appScriptDirectory\Temp" -Force
    Remove-File -Path "$appScriptDirectory\$appAdmx"
    If (-Not(Test-Path -Path "$appScriptDirectory\ADMX")) { New-Folder -Path "$appScriptDirectory\ADMX" }
    Move-Item -Path "$appScriptDirectory\Temp\*\*.admx" -Destination "$appScriptDirectory\ADMX" -Force
    If (-Not(Test-Path -Path "$appScriptDirectory\ADMX\en-US")) { New-Folder -Path "$appScriptDirectory\ADMX\en-US" }
    Move-Item -Path "$appScriptDirectory\Temp\*\en-US\*.adml" -Destination "$appScriptDirectory\ADMX\en-US" -Force
    Remove-Folder -Path "$appScriptDirectory\Temp"
    Write-Log -Message "$appShortName ADMX templates $appAdmxVersion were downloaded successfully!" -Severity 1 -LogType CMTrace -WriteHost $True

    # Download latest setup file(s)
    If (-Not(Test-Path -Path $appScriptDirectory\$appVersion\$appSetup))
    {
        Write-Log -Message "Downloading $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Get-Download -Url $appUrl -Destination $appScriptDirectory\$appVersion -FileName $appSetup -IncludeStats
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Install latest version
    Write-Log -Message "Installing $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    Execute-MSI -Action Install -Path $appSetup -Parameters $appInstallParameters -AddParameters $appAddParameters

    # Remove desktop shortcut for all users
    Remove-File -Path "$envCommonDesktop\$appShortName VDI.lnk" -ContinueOnError $True

    # Go back to the parent folder
    Set-Location ..

    Write-Log -Message "$appName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
}
Else
{
    Write-Log -Message "$appName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}