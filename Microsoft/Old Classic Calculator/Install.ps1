﻿# Standalone application install script for VDI environment - (C)2023 Jonathan Pitre

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
$Modules = @("PSADT") # Modules list

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
Function Get-OldClassicCalculator
{
    [OutputType([System.Management.Automation.PSObject])]
    [CmdletBinding()]
    Param ()
    $DownloadURL = "https://win7games.com"

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
        $RegEx = 'href\=\"(.+)\"\>Download Calculator'
        $URL = $DownloadURL + ($DownloadText | Select-String -Pattern $RegEx).Matches.Groups[1].Value

        if ($URL)
        {
            [PSCustomObject]@{
                Name = 'Old Classic Calculator'
                Type = 'Zip'
                Uri  = $URL
            }
        }
    }
}

#endregion

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$appVendor = "Microsoft"
$appName = "Old Classic Calculator"
$appName2 = "for Windows 11 and Windows 10"
$appProcesses = @("calc", "calc1")
$appInstallParameters = "/SILENT /NORESTART"
$Evergreen = Get-OldClassicCalculator
#$appURL = $Evergreen.URI
$appURL = "https://github.com/JonathanPitre/Apps/raw/master/Microsoft/Old%20Classic%20Calculator/2.0/OldClassicCalc-2.0-setup.exe"
#$appZip = Split-Path -Path $appURL -Leaf
$appSetup = Split-Path -Path $appURL -Leaf
$appDestination = "${env:ProgramFiles}\OldClassicCalc"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appName $appName2")
$appInstalledVersion = (Get-InstalledApplication -Name "$appName $appName2").DisplayVersion

#-----------------------------------------------------------[Execution]------------------------------------------------------------

Set-Location -Path $appScriptPath

# Download latest setup file(s)
If (-Not(Test-Path -Path $appScriptPath\$appVersion\$appSetup))
{
    Write-Log -Message "Downloading $appVendor $appName $appName2..." -Severity 1 -LogType CMTrace -WriteHost $True
    #Invoke-WebRequest -UseBasicParsing -Uri $appURL -OutFile $appScriptPath\$appZip
    #Expand-Archive -Path $appZip -DestinationPath $appScriptPath -Force
    #Remove-File -Path $appZip
    #$appSetup = Get-ChildItem -Filter *.exe | Select-Object -ExpandProperty Name
    Invoke-WebRequest -UseBasicParsing -Uri $appURL -OutFile $appScriptPath\$appSetup
    $appSetup -match '((?:\d+\.)+\d+(?:-\d+)?)'
    $appVersion = $Matches[0]
    New-Folder -Path $appScriptPath\$appVersion
    Copy-File -Path $appScriptPath\$appSetup -Destination $appScriptPath\$appVersion\$appSetup
    Remove-File -Path $appScriptPath\$appSetup
}
Else
{
    Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    $appSetup = Get-ChildItem -Filter *.exe -Recurse | Select-Object -ExpandProperty Name
    $appSetup -match '((?:\d+\.)+\d+(?:-\d+)?)'
    $appVersion = $Matches[0]
}

If ([version]$appVersion -gt [version]$appInstalledVersion)
{

    # Uninstall previous versions
    Get-Process -Name $appProcesses | Stop-Process -Force

    # Install latest version
    Execute-Process -Path ".\$appVersion\$appSetup" -Parameters $appInstallParameters

    # Configure application shortcut
    Rename-Item -Path "$envCommonStartMenuPrograms\Calculator (Classic).lnk" -NewName "$envCommonStartMenuPrograms\Calculator.lnk" -Force
    Remove-File -Path "$envCommonDesktop\Calculator (Classic).lnk"

    # Replace calc.exe by calc1.exe
    Set-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\calc.exe" -Name "Debugger" -Value "`"$appDestination\calc1.exe`"" -Type "String"
    Set-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\calc.exe" -Name "UseFilter" -Value "0" -Type "Dword"

    # Go back to the parent folder
    Set-Location ..

    Write-Log -Message "$appVendor $appName $appName2 $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
}
Else
{
    Write-Log -Message "$appVendor $appName $appName2 $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}