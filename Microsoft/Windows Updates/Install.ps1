# Standalone application install script for VDI environment - (C)2023 Jonathan Pitre

#Requires -Version 5.1
#Requires -RunAsAdministrator

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

#region Initialisations

$ProgressPreference = "Continue"
$ErrorActionPreference = "SilentlyContinue"
# Set the script execution policy for this process
Try { Set-ExecutionPolicy -ExecutionPolicy 'ByPass' -Scope 'Process' -Force } Catch {}
# Unblock ps1 script
Get-ChildItem -Recurse *.ps*1 | Unblock-File
$env:SEE_MASK_NOZONECHECKS = 1
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
$Modules = @("PSADT", "PSWindowsUpdate") # Modules list

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

#endregion

#-----------------------------------------------------------[Functions]------------------------------------------------------------

#region Functions
#endregion

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$appVendor = "Microsoft"
$appName = "Updates"
$appService = "wuauserv"
$appLog = "$env:ProgramData\Logs\Software\PSWindowsUpdate.log"

#-----------------------------------------------------------[Execution]------------------------------------------------------------

# Create folder to store log files
New-Folder -Path "$env:ProgramData\Logs\Software"

# Stop Windows Update service
Stop-ServiceAndDependencies -Name $appService

# Clear Windows Update policies
Remove-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Recurse -ContinueOnError $True

# Get updates for other Microsoft products
$null = Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d -Confirm:$False

# Pause and give the service time to update
Start-Sleep -Seconds 10

# Start Windows Update service
Set-ServiceStartMode -Name $appService -StartMode "Automatic"
Start-ServiceAndDependencies -Name $appService

Write-Log -Message "Gettings available $appVendor $appName..." -Severity 1 -LogType CMTrace -WriteHost $True
$WinUpdates = Get-WindowsUpdate -NotCategory "Drivers", "Upgrades" -NotTitle "Preview" -MicrosoftUpdate
$WinUpdates = $WinUpdates | Select-Object KB, Size, Title

If ($null -ne $WinUpdates)
{
    Write-Log -Message "Installing $appVendor $appName...`n $($WinUpdates | Out-String)" -Severity 1 -LogType CMTrace -WriteHost $True
    Get-WindowsUpdate -NotCategory "Drivers", "Upgrades" -NotTitle "Preview" -MicrosoftUpdate -Install -AcceptAll -UpdateType Software -IgnoreReboot -IgnoreUserInput | Out-File $appLog -Append
}
ElseIf (-Not[bool](Get-InstalledModule -Name PSWindowsUpdate))
{
    Write-Log -Message "PSWindowsUpdate module could not be installed, reverting to Microsoft native method." -Severity 2 -LogType CMTrace -WriteHost $True
    Write-Log -Message "Installing $appVendor $appName..." -Severity 1 -LogType CMTrace -WriteHost $True
    # Windows 10/Server 2016 native method
    Start-Process -NoNewWindow "$env:windir\System32\UsoClient.exe" -argument "ScanInstallWait" -Wait
    Start-Process -NoNewWindow "$env:windir\System32\UsoClient.exe" -argument "StartInstall" -Wait
}
Else
{
    Write-Log -Message "No $appVendor $appName are available." -Severity 1 -LogType CMTrace -WriteHost $True
}

# Check for pending restart
[bool]$WURebootStatus = Get-WURebootStatus -Silent
[bool]$isRebootPending = (Get-PendingReboot).IsSystemRebootPending
If ($WURebootStatus)
{
    Write-Log -Message "$appVendor $appName were installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
    Write-Log -Message "A computer restart is required." -Severity 2 -LogType CMTrace -WriteHost $True
    Show-InstallationRestartPrompt -CountdownSeconds 10 -CountdownNoHideSeconds 10
}
ElseIf ($isRebootPending)
{
    Write-Log -Message "$appVendor $appName were installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
    Write-Log -Message "A computer restart is required." -Severity 2 -LogType CMTrace -WriteHost $True
    Show-InstallationRestartPrompt -CountdownSeconds 10 -CountdownNoHideSeconds 10
}