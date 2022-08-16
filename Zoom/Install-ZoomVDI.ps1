# Standalone application install script for VDI environment - (C)2022 Jonathan Pitre, inspired by xenappblog.com

#Requires -Version 7.0
#Requires -RunAsAdministrator

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"
# Set the script execution policy for this process
Try { Set-ExecutionPolicy -ExecutionPolicy 'ByPass' -Scope 'Process' -Force } Catch {}
$env:SEE_MASK_NOZONECHECKS = 1
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
$Modules = @("Nevergreen") # Modules list

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

# Get the current script directory
$appScriptDirectory = Get-ScriptDirectory

# Install and import modules list
Foreach ($Module in $Modules)
{
    Initialize-Module -Module $Module
}

#-----------------------------------------------------------[Functions]------------------------------------------------------------

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
        $downloadStats = [PSCustomObject]@{FileSize = $fileSize; Time = $timeElapsed }
        Write-Information -MessageData $downloadStats
    }
    Get-Item -Path $destinationPath | Unblock-File
}

Function Get-ZoomAdmx
{
    Try
    {
        $sourceUrl = "https://support.zoom.us/hc/en-us/articles/360039100051"
        # Grab content
        $web = Invoke-WebRequest -Uri $sourceUrl -UseBasicParsing
        # Find ADMX download
        $admxUrl = (($web.links | Where-Object { $_.href -like "*msi-templates*.zip" })[-1]).href
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

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$appShortName = "Zoom"
$appName = "Zoom Client for VDI"
$appProcesses = @("Zoom", "Zoom_launcher", "ZoomOutlookIMPlugin")
$appServices = @("ZoomCptService")
$appInstallParameters = "/QB"
# https://support.zoom.us/hc/en-us/articles/201362163-Mass-Installation-and-Configuration-for-Windows
$appAddParameters = "zNoDesktopShortCut=1"
$Evergreen = Get-NevergreenApp Zoom | Where-Object { $_.Name -like "*VDI Client" }
$appVersion = $Evergreen.Version
$appURL = $Evergreen.URI
$appSetup = Split-Path -Path $appURL -Leaf
$appDestination = "${env:ProgramFiles(x86)}\ZoomVDI\bin"
$appUninstallerURL = "https://support.zoom.us/hc/en-us/article_attachments/360084068792/CleanZoom.zip"
$appUninstallerZip = Split-Path -Path $appUninstallerURL -Leaf
$appUninstallerSetup = "CleanZoom.exe"
$appAdmxVersion = (Get-ZoomAdmx).Version
$appAdmxUrl = (Get-ZoomAdmx).URI
$appAdmx = Split-Path -Path $appAdmxUrl -Leaf
[boolean]$IsAppInstalled = [boolean](Get-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -like "*$appName*" })
$appInstalledVersion = (Get-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -like "*$appName*"}).Comments | Sort-Object -Property Version -Descending | Select-Object -First 1
$appInstalledVersion = $appInstalledVersion.Split("(")[0]

#-----------------------------------------------------------[Execution]------------------------------------------------------------

If ([version]$appVersion -gt [version]$appInstalledVersion)
{
    Set-Location -Path $appScriptDirectory
    If (-Not(Test-Path -Path $appVersion))
    {
        New-Item -Path $appVersion -ItemType Directory -Force | Out-Null
    }
    Set-Location -Path $appVersion

    # Download required cleanup tool
    If (-Not(Test-Path -Path $appScriptDirectory\$appUninstallerSetup))
    {
        Write-Host -Object "Downloading $appShortName Cleanup Tool..." -ForegroundColor Green -Debug
        Get-Download -Url $appUninstallerURL -Destination $appScriptDirectory -FileName $appUninstallerZip -IncludeStats
        Expand-Archive -Path $appScriptDirectory\$appUninstallerZip -DestinationPath $appScriptDirectory
        Remove-Item -Path $appScriptDirectory\$appUninstallerZip -Force
    }
    Else
    {
        Write-Host -Object "File(s) already exists, download was skipped." -ForegroundColor Yellow -Debug
    }

    # Uninstall previous versions
    Write-Host -Object "Uninstalling previous versions..." -ForegroundColor Green -Debug
    Get-Process -Name $appProcesses | Stop-Process -Force
    #Start-Process -FilePath msiexec.exe -ArgumentList "/x $appSetup" -PassThru -Wait -ErrorAction Stop | Out-Null
    Start-Process -FilePath $appScriptDirectory\$appUninstallerSetup -ArgumentList '/silent' -NoNewWindow -Wait

    # Remove user install
    $ZoomUsers = Get-ChildItem -Path "$($env:SystemDrive)\Users"
    $ZoomUsers | ForEach-Object {
        Try
        {
            If (Test-Path "$($env:SystemDrive)\Users\$($_.Name)\AppData\Roaming\$appShortName\bin\$appShortName.exe")
            {
                Remove-Item -Path "$($env:SystemDrive)\Users\$($_.Name)\AppData\Roaming\$appShortName" -Force -Recurse
                Remove-Item -Path "$($env:SystemDrive)\Users\$($_.Name)\AppData\Roaming\$($appShortName)VDI" -Force -Recurse
                Remove-Item -Path "$($env:SystemDrive)\Users\$($_.Name)\AppData\Roaming\Windows\Start Menu\Programs\$appShortName" -Force -Recurse
                Remove-Item -Path "$($env:SystemDrive)\Users\$($_.Name)\AppData\Roaming\Windows\Start Menu\Programs\$appShortName VDI" -Force -Recurse
            }
        }
        Catch
        {
            Out-Null
        }
    }

    # Remove registry entries from all user profiles - https://www.reddit.com/r/SCCM/comments/fu3q6f/zoom_uninstall_if_anyone_needs_this_information
    <#
    [scriptblock]$HKCURegistrySettings = {
        Remove-RegistryKey -Key "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Zoom" -Recurse -ContinueOnError $True -SID $UserProfile.SID
        Remove-RegistryKey -Key "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\ZoomUMX" -Recurse -ContinueOnError $True -SID $UserProfile.SID
        Remove-RegistryKey -Key "HKCU:\Software\Zoom" -Recurse -ContinueOnError $True -SID $UserProfile.SID
        Remove-RegistryKey -Key "HKCU:\Software\ZoomUMX" -Recurse -ContinueOnError $True -SID $UserProfile.SID
        Remove-RegistryKey -Key "HKCU:\Software\Policies\Zoom\Zoom Meetings\VDI" -Recurse -ContinueOnError $True -SID $UserProfile.SID
    }
    Invoke-HKCURegistrySettingsForAllUsers -RegistrySettings $HKCURegistrySettings
    #>

    # Download latest policy definitions
    Write-Host -Object "Downloading $appShortName ADMX templates $appAdmxVersion..." -ForegroundColor Green -Debug
    Get-Download -Url $appAdmxUrl -Destination $appScriptDirectory $appAdmx -IncludeStats
    Expand-Archive -Path "$appScriptDirectory\$appAdmx" -DestinationPath "$appScriptDirectory\Temp" -Force
    Remove-Item -Path "$appScriptDirectory\$appAdmx" -Force

    If (-Not(Test-Path -Path "$appScriptDirectory\PolicyDefinitions")) { New-Folder -Path "$appScriptDirectory\PolicyDefinitions" }
    Move-Item -Path "$appScriptDirectory\Temp\*\*.admx" -Destination "$appScriptDirectory\PolicyDefinitions" -Force
    If (-Not(Test-Path -Path "$appScriptDirectory\PolicyDefinitions\en-US")) { New-Folder -Path "$appScriptDirectory\PolicyDefinitions\en-US" }
    Move-Item -Path "$appScriptDirectory\Temp\*\en-US\*.adml" -Destination "$appScriptDirectory\PolicyDefinitions\en-US" -Force
    Remove-Item -Path "$appScriptDirectory\Temp" -Force -Recurse
    Write-Host -Object "$appShortName ADMX templates $appAdmxVersion were downloaded successfully!" -ForegroundColor Green -Debug

    # Download latest setup file(s)
    If (-Not(Test-Path -Path $appScriptDirectory\$appVersion\$appSetup))
    {
        Write-Host -Object "Downloading $appName $appVersion..." -ForegroundColor Green -Debug
        Get-Download -Url $appUrl -Destination $appScriptDirectory\$appVersion -FileName $appSetup -IncludeStats
    }
    Else
    {
        Write-Host -Object "File(s) already exists, download was skipped." -ForegroundColor Yellow -Debug
    }

    # Install latest version
    Write-Log -Message "Installing $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    Start-Process -FilePath msiexec.exe -ArgumentList "/i $appSetup $appInstallParameters $appAddParameters" -NoNewWindow -Wait

    # Stop and disable unneeded services
    Stop-Service -Name $appServices[0] -Force
    Set-Service -Name $appServices[0] -StartupType Manual

    # Configure application shortcut
    Remove-Item -Path "$env:PUBLIC\Desktop\$appShortName VDI.lnk" -Force
    Move-Item -Path "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\$appShortName VDI\$appShortName VDI.lnk" -Destination "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\$appShortName VDI.lnk" -Force
    Remove-Item -Path "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\$appShortName VDI\$appShortName VDI" -Force

    # Go back to the parent folder
    Set-Location ..

    Write-Host -Object "$appName $appVersion was installed successfully!" -ForegroundColor Green -Debug
}
Else
{
    Write-Host -Object "$appName $appInstalledVersion is already installed." -ForegroundColor Yellow -Debug
}