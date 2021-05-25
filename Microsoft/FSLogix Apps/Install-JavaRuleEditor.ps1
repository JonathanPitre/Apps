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
    If (-not(Get-PackageProvider -ListAvailable -Name $PackageProvider -ErrorAction SilentlyContinue)) { Install-PackageProvider -Name $PackageProvider -Force }
}

# Add the Powershell Gallery as trusted repository
Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted

# Update PowerShellGet
$InstalledPSGetVersion = (Get-PackageProvider -Name PowerShellGet).Version
$PSGetVersion = [version](Find-PackageProvider -Name PowerShellGet).Version
If ($PSGetVersion -gt $InstalledPSGetVersion) { Install-PackageProvider -Name PowerShellGet -Force }

# Install and import custom modules list
Foreach ($Module in $Modules)
{
    If (-not(Get-Module -ListAvailable -Name $Module)) { Install-Module -Name $Module -AllowClobber -Force | Import-Module -Name $Module -Force }
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

# Variables Declaration
# Generic
$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"
$env:SEE_MASK_NOZONECHECKS = 1
$appScriptDirectory = Get-ScriptDirectory

# Application related
##*===============================================
Function Get-MicrosoftFSLogixApps
{
    <#
    .NOTES
        Author: Jonathan Pitre
        Twitter: @PitreJonathan
    #>
    [OutputType([System.Management.Automation.PSObject])]
    [CmdletBinding()]
    Param()
    $URLPreview = "https://download.microsoft.com/download/d/b/e/dbeeff02-b137-4971-a70b-83c22f82380f/FSLogix_Apps_2.9.7802.10873.zip"
    Try
    {
        Invoke-WebRequest -Uri $URLPreview -UseBasicParsing
    }
    Catch
    {
        Throw "Failed to connect to URL: $URLPreview with error $_."
        Break
    }
    Finally
    {
        $Evergreen = Get-EvergreenApp -Name MicrosoftFSLogixApps
        $VersionProd = $Evergreen.Version
        $DateProd = $Evergreen.Date
        $URLProd = $Evergreen.URI

        $VersionPreview = ($URLPreview | Select-String -Pattern 'FSLogix_Apps_((?:\d+\.)+(?:\d+))').Matches.Groups[1].Value

        if ($VersionProd -and $DateProd -and $URLProd)
        {
            [PSCustomObject]@{
                Version = $VersionProd
                Date    = $DateProd
                Ring    = 'Production'
                URI     = $URLProd
            }
        }

        if ($VersionPreview -and $URLPreview)
        {
            [PSCustomObject]@{
                Version = $VersionPreview
                Date    = '2021-05-24'
                Ring    = 'Preview'
                URI     = $URLPreview
            }
        }
    }
}
$appVendor = "Microsoft"
$appName = "FSLogix Apps Java RuleEditor"
$appSetup = "FSLogixAppsJavaRuleEditorSetup.exe"
$appProcesses = @("JavaRuleEditor")
$appInstallParameters = "/install /quiet /norestart"
$Nevergreen = Get-MicrosoftFSLogixApps | Where-Object { $_.Ring -eq "Preview" }
$appVersion = $Nevergreen.Version
$appURL = $Nevergreen.URI
$appZip = Split-Path -Path $appURL -Leaf
$appDestination = "$env:ProgramFiles\FSLogix\Apps"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName" -Exact) | Select-Object -Last 1
$appInstalledVersion = (Get-InstalledApplication -Name "$appVendor $appName" -Exact).DisplayVersion | Select-Object -Last 1
##*===============================================

If ([version]$appVersion -gt [version]$appInstalledVersion)
{
    Set-Location -Path $appScriptDirectory
    If (-Not(Test-Path -Path $appVersion)) {New-Folder -Path $appVersion}
    Set-Location -Path $appVersion

    If (-Not(Test-Path -Path $appScriptDirectory\$appVersion\x64\Release\$appSetup)) {
        Write-Log -Message "Downloading $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURL -OutFile $appZip
        Expand-Archive -Path $appZip -DestinationPath $appScriptDirectory\$appVersion
        Remove-File -Path $appZip
    }
    Else {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
    Get-Process -Name $appProcesses | Stop-Process -Force

    Write-Log -Message "Installing $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    Execute-Process -Path .\x64\Release\$appSetup -Parameters $appInstallParameters

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

    # Go back to the parent folder
    Set-Location ..

    Write-Log -Message "$appVendor $appName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
}
Else {
    Write-Log -Message "$appVendor $appName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}