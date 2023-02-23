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

            # If module is not imported, not available on disk, but is in online gallery then install and import
            If (Find-Module -Name $Module | Where-Object { $_.Name -eq $Module })
            {

                # Add the Powershell Gallery as trusted repository
                Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted

                # Install Nuget
                If (-not(Get-PackageProvider -ListAvailable -Name Nuget -ErrorAction SilentlyContinue)) { Install-PackageProvider -Name Nuget -Force }
                # Update PowerShellGet
                $InstalledPSGetVersion = (Get-PackageProvider -Name PowerShellGet).Version
                $PSGetVersion = [version](Find-PackageProvider -Name PowerShellGet).Version
                If ($PSGetVersion -gt $InstalledPSGetVersion) { Install-PackageProvider -Name PowerShellGet -Force }


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
Function Get-CitrixOptimizerTool
{
    [OutputType([System.Management.Automation.PSObject])]
    [CmdletBinding()]
    Param ()
    $DownloadURL = "https://support.citrix.com/article/CTX224676"

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
        $RegExVersion = "v((?:\d+\.)+(?:\d+))"
        $Version = ($DownloadText | Select-String -Pattern $RegExVersion).Matches.Groups[1].Value
        $RegExURL = "https.+CitrixOptimizerTool\.zip"
        $URL = ($DownloadText | Select-String -Pattern $RegExURL).Matches.Value

        if ($Version -and $URL)
        {
            [PSCustomObject]@{
                Name         = 'Citrix Optimizer Tool'
                Architecture = 'x86'
                Type         = 'Zip'
                Version      = $Version
                Uri          = $URL
            }
        }
    }
}

#endregion

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$appVendor = "Citrix"
$appName = "Optimizer Tool"
$appProcesses = @("CitrixOptimizer")
$Evergreen = Get-CitrixOptimizerTool
$appVersion = $Evergreen.Version
$appURL = $Evergreen.Uri
$appZip = Split-Path -Path $appURL -Leaf
$appSetup = "CitrixOptimizerTool.exe"
$appDestination = "$env:ProgramFiles\Citrix\Optimizer Tool"
[boolean]$IsAppInstalled = Test-Path -Path "$appDestination\$appSetup"
$appInstalledVersion = If ($IsAppInstalled) { Get-FileVersion -File "$appDestination\$appSetup" }
$appTemplateURL = "https://raw.githubusercontent.com/JonathanPitre/Apps/master/Citrix/Optimizer Tool/ITI_Windows_$($envOSVersionMajor)_2009.xml"
$appTemplate = Split-Path -Path $appTemplateURL -Leaf
$appConfigURL = "https://raw.githubusercontent.com/JonathanPitre/Apps/master/Citrix/Optimizer Tool/CitrixOptimizerTool.exe.config"
$appConfig = Split-Path -Path $appConfigURL -Leaf
$appInstallParameters = "-Source `"$appDestination\Templates\$appTemplate`" -Mode Execute -OutputLogFolder `"$appDestination\Logs`" -OutputHtml `"$appDestination\Reports\Report.html`" -OutputXml `"$appDestination\Rollback\Rollback.xml`""

#-----------------------------------------------------------[Execution]------------------------------------------------------------

If ([version]$appVersion -gt [version]$appInstalledVersion)
{
    Set-Location -Path $appScriptPath
    If (-Not(Test-Path -Path $appVersion)) { New-Folder -Path $appVersion }
    Set-Location -Path $appVersion

    If (-Not(Test-Path -Path $appScriptPath\$appVersion\$appSetup))
    {
        # Download latest version
        Write-Log -Message "$appVendor $appName $appVersion MUST BE DOWNLOADED MANUALLY FIRST!" -Severity 3 -LogType CMTrace -WriteHost $True
        Start-Sleep -Seconds 5
        Exit-Script
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True

        # Download configuration to add community template marketplace
        If (-Not(Test-Path -Path "$appScriptPath\Templates\$appConfig"))
        {
            Write-Log -Message "Downloading $appVendor $appName configuration file..." -Severity 1 -LogType CMTrace -WriteHost $True
            Invoke-WebRequest -UseBasicParsing -Uri $appConfigURL -OutFile "$appScriptPath\$appConfig"
        }
        Else
        {
            Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
        }

        # Download template
        If (-Not(Test-Path -Path "$appScriptPath\Templates\$appTemplate"))
        {
            Write-Log -Message "Downloading $appVendor $appName template file..." -Severity 1 -LogType CMTrace -WriteHost $True
            New-Folder -Path "$appScriptPath\Templates"
            Invoke-WebRequest -UseBasicParsing -Uri $appTemplateURL -OutFile "$appScriptPath\Templates\$appTemplate"
        }
        Else
        {
            Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
        }

        Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
        Get-Process -Name $appProcesses | Stop-Process -Force

        Write-Log -Message "Installing $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Remove-Folder -Path "$env:ProgramFiles\Citrix\Optimizer" -ContinueOnError $True
        If (-Not(Test-Path -Path $appDestination)) { New-Folder -Path $appDestination }
        Copy-File -Path "$appScriptPath\$appVersion\*" -Destination $appDestination -Recurse
        Copy-File -Path "$appScriptPath\$appConfig " -Destination $appDestination -Recurse
        Copy-File -Path "$appScriptPath\Templates\*" -Destination "$appDestination\Templates"
        New-Folder -Path "$appDestination\Logs"
        New-Folder -Path "$appDestination\Rollback"
        New-Folder -Path "$appDestination\Reports"
        Write-Log -Message "$appVendor $appName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
        Write-Log -Message "$appVendor $appName $appVersion must be run manually to optimize the system." -Severity 1 -LogType CMTrace -WriteHost $True
        #Write-Log -Message "Executing $appVendor $appName $appVersion optimizations from $appTemplate..." -Severity 1 -LogType CMTrace -WriteHost $True
        #Execute-Process -Path powershell.exe -Parameters "-file `"$appDestination\CtxOptimizerEngine.ps1`" $appInstallParameters" -WindowStyle Hidden -CreateNoWindow

        # Configure application shortcut
        New-Shortcut -Path "$envCommonStartMenuPrograms\Administrative Tools\$appVendor $appName.lnk" -TargetPath "$appDestination\$appSetup"

        Write-Log -Message "$appVendor $appName $appVersion applied the optimizations successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
    }
}

Else
{
    Write-Log -Message "$appVendor $appName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
    Write-Log -Message "$appVendor $appName $appVersion must be run manually to optimize the system." -Severity 1 -LogType CMTrace -WriteHost $True
    #Write-Log -Message "$appVendor $appName $appVersion will now run to optimize the system..." -Severity 1 -LogType CMTrace -WriteHost $True
    #Execute-Process -Path powershell.exe -Parameters "-file `"$appDestination\CtxOptimizerEngine.ps1`" $appInstallParameters" -WindowStyle Hidden -CreateNoWindow
    #Write-Log -Message "$appVendor $appName $appVersion applied the optimizations successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
}