# Standalone application install script for VDI environment - (C)2022 Jonathan Pitre, inspired by xenappblog.com

#Requires -Version 5.1
#Requires -RunAsAdministrator

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"
# Set the script execution policy for this process
Try { Set-ExecutionPolicy -ExecutionPolicy 'ByPass' -Scope 'Process' -Force } Catch {}
$env:SEE_MASK_NOZONECHECKS = 1
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
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
    Write-Host -Object "Importing $Module module..." -ForegroundColor Green

    # If module is imported say that and do nothing
    If (Get-Module | Where-Object { $_.Name -eq $Module })
    {
        Write-Host -Object "Module $Module is already imported." -ForegroundColor Green
    }
    Else
    {
        # If module is not imported, but available on disk then import
        If (Get-Module -ListAvailable | Where-Object { $_.Name -eq $Module })
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

Function Get-AnalyzeLogonDuration
{
    <#
    .SYNOPSIS
    Returns latest version of Analyze Logon Duration script
    #>
    $DownloadURL = "https://raw.githubusercontent.com/controlup/script-library/master/Analyze%20Logon%20Duration/README.md"

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
        $RegEx = "(Version\: )((?:\d+\.)+(?:\d+))"
        $Version = ($DownloadText | Select-String -Pattern $RegEx).Matches.Groups[2].Value
        $URL = "https://raw.githubusercontent.com/controlup/script-library/master/Analyze%20Logon%20Duration/Analyze%20Logon%20Duration.ps1"

        If ($Version -and $URL)
        {
            [PSCustomObject]@{
                Version = $Version
                URI     = $URL
            }
        }
    }
}

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$appName = "Analyze Logon Duration"
$Evergreen = Get-AnalyzeLogonDuration
$appVersion = $Evergreen.Version
$appURL = $Evergreen.URI
$appSetup = (Split-Path -Path $appURL -Leaf).Replace("%20", " ")
$appDestination = "$env:ProgramFiles\WindowsPowerShell\Scripts"
$appIconURL = "https://github.com/JonathanPitre/Apps/raw/master/Analyze%20Logon%20Duration/Analyze%20Logon%20Duration.ico"
$appIcon = (Split-Path -Path $appIconURL -Leaf).Replace("%20", " ")
[boolean]$IsAppInstalled = [boolean](Test-Path -Path "$appDestination\$appSetup")
If ($IsAppInstalled)
{
    (Get-Content -Path "$appDestination\$appSetup" -Raw) -match "(Version\: )((?:\d+\.)+(?:\d+))"
    $appInstalledVersion = $Matches[2]
}

#-----------------------------------------------------------[Execution]------------------------------------------------------------

If ([version]$appVersion -gt [version]$appInstalledVersion)
{
    Set-Location -Path $appScriptDirectory
    If (-Not(Test-Path -Path $appVersion)) { New-Folder -Path $appVersion }
    Set-Location -Path $appVersion

    # Download latest setup file(s)
    If (-Not(Test-Path -Path $appScriptDirectory\$appVersion\$appSetup))
    {
        Write-Log -Message "Downloading $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURL -OutFile $appSetup
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Download icon
    If (-Not(Test-Path -Path $appScriptDirectory\$appIcon))
    {
        Write-Log -Message "Downloading $appName icon..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appIconURL -OutFile $appIcon
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Install latest version
    Write-Log -Message "Installing $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    Copy-File -Path .\$appSetup -Destination $appDestination
    Copy-File -Path .\$appIcon -Destination $appDestination

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

    If (Test-Path -Path "$appDestination\$appSetup")
    {
        Try
        {
            Write-Log -Message "Customizig script for $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
            #((Get-Content "$appDestination\$appSetup" -Raw) -replace "[String]$DomainUser,", "[String]$DomainUser = #<$env:USERDNSDOMAIN>\<$env:USERNAME>,") | Set-Content -Path "$appDestination\$appSetup"

            ((Get-Content "$appDestination\$appSetup" -Raw) -replace "@guyrleech", "@guyrleech Version: $appVersion") | Set-Content -Path "$appDestination\$appSetup"
        }
        Catch
        {
            Write-Log -Message "Error when customizing scripts" -Severity 2 -LogType CMTrace -WriteHost $True
        }
    }

    # Configure application shortcut
    New-Shortcut -Path "$envCommonStartMenuPrograms\Administrative Tools\$appName.lnk" -TargetPath "powershell.exe" -Arguments "-Ex ByPass -NoExit -File `"$appDestination\$appSetup`"" -IconLocation "$appDestination\$appIcon" -Description "$appName" -WorkingDirectory "$appDestination"

    # Go back to the parent folder
    Set-Location ..

    Write-Log -Message "$appName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
}
Else
{
    Write-Log -Message "$appName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}