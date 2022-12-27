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
$Modules = @("PSADT") # Modules list

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

# Get the current script directory
$appScriptDirectory = Get-ScriptDirectory

# Install and import modules list
Foreach ($Module in $Modules)
{
    Initialize-Module -Module $Module
}

#-----------------------------------------------------------[Functions]------------------------------------------------------------

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
    Set-Location -Path $appScriptDirectory
    If (-Not(Test-Path -Path $appVersion)) { New-Folder -Path $appVersion }
    Set-Location -Path $appVersion

    If (-Not(Test-Path -Path $appScriptDirectory\$appVersion\$appSetup))
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
        If (-Not(Test-Path -Path "$appScriptDirectory\Templates\$appConfig"))
        {
            Write-Log -Message "Downloading $appVendor $appName configuration file..." -Severity 1 -LogType CMTrace -WriteHost $True
            Invoke-WebRequest -UseBasicParsing -Uri $appConfigURL -OutFile "$appScriptDirectory\$appConfig"
        }
        Else
        {
            Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
        }

        # Download template
        If (-Not(Test-Path -Path "$appScriptDirectory\Templates\$appTemplate"))
        {
            Write-Log -Message "Downloading $appVendor $appName template file..." -Severity 1 -LogType CMTrace -WriteHost $True
            New-Folder -Path "$appScriptDirectory\Templates"
            Invoke-WebRequest -UseBasicParsing -Uri $appTemplateURL -OutFile "$appScriptDirectory\Templates\$appTemplate"
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
        Copy-File -Path "$appScriptDirectory\$appVersion\*" -Destination $appDestination -Recurse
        Copy-File -Path "$appScriptDirectory\$appConfig " -Destination $appDestination -Recurse
        Copy-File -Path "$appScriptDirectory\Templates\*" -Destination "$appDestination\Templates"
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