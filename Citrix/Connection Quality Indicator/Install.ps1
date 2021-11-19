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
Function Get-CitrixCQI
{
    [OutputType([System.Management.Automation.PSObject])]
    [CmdletBinding()]
    Param ()
    $DownloadURL = "https://support.citrix.com/article/CTX220774"

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
        $RegExVersion = "What's New in ((?:\d+\.)+(?:\d+))"
        $Version = ($DownloadText | Select-String -Pattern $RegExVersion).Matches.Groups[1].Value
        $RegExURL = "https.+CitrixCQI\.zip"
        $URL = ($DownloadText | Select-String -Pattern $RegExURL).Matches.Value

        if ($Version -and $URL)
        {
            [PSCustomObject]@{
                Name         = 'Citrix Quality Indicator'
                Architecture = 'x86'
                Type         = 'Zip'
                Version      = $Version
                Uri          = $URL
            }
        }
    }
}
Function Get-CitrixDownload
{
    <#
.SYNOPSIS
  Downloads a Citrix file from Citrix.com utilizing authentication
.DESCRIPTION
  Downloads a Citrix file from Citrix.com utilizing authentication
.PARAMETER CitrixKB
  Citrix KB Article number
.PARAMETER CitrixFile
  File name to be downloaded
.PARAMETER FilePath
  Path to store downloaded file
.PARAMETER CitrixUserName
  Citrix.com username
.PARAMETER CitrixPassword
  Citrix.com password
.EXAMPLE
  Get-CitrixDownload -CitrixKB "220774" -CitrixFile "CitrixCQI.zip" -CitrixUserName "MyCitrixUsername" -CitrixPassword "MyCitrixPassword"
#>
    Param(
        [Parameter(Mandatory = $true)]$CitrixKB,
        [Parameter(Mandatory = $true)]$CitrixFile,
        [Parameter(Mandatory = $true)]$FilePath,
        [Parameter(Mandatory = $true)]$CitrixUserName,
        [Parameter(Mandatory = $true)]$CitrixPassword
    )
    #Initialize Session
    Invoke-WebRequest "https://identity.citrix.com/Utility/STS/Sign-In" -SessionVariable websession -UseBasicParsing | Out-Null

    #Set Form
    $Form = @{
        "persistent" = "1"
        "userName"   = $CitrixUserName
        "loginbtn"   = "Log+in"
        "password"   = $CitrixPassword
        "returnURL"  = "https://login.citrix.com/bridge?url=https://support.citrix.com/article/CTX${CitrixKB}"
        "errorURL"   = "https://login.citrix.com?url=https://support.citrix.com/article/CTX${CitrixKB}&err=y"
    }

    #Authenticate
    Try
    {
        Invoke-WebRequest -Uri ("https://identity.citrix.com/Utility/STS/Sign-In") -WebSession $websession -Method POST -Body $Form -ContentType "application/x-www-form-urlencoded" -UseBasicParsing | Out-Null
    }
    Catch
    {
        If ($_.Exception.Response.StatusCode.Value__ -eq 500)
        {
            Write-Verbose "500 returned on auth. Ignoring"
            Write-Verbose $_.Exception.Response
            Write-Verbose $_.Exception.Message
        }
        Else
        {
            Throw $_
        }
    }

    #$OutFile = ($FilePath + $CitrixFile)
    $OutFile = Join-Path -Path $FilePath -ChildPath $CitrixFile
    #Download
    Invoke-WebRequest -WebSession $websession -Uri "https://fileservice.citrix.com/download/secured/support/article/CTX${CitrixKB}/downloads/${CitrixFile}" -OutFile $OutFile -UseBasicParsing
    return $OutFile
}

$appVendor = "Citrix"
$appName = "Connection Quality Indicator"
$appProcesses = @("Citrix.CQI")
$appInstallParameters = "/quiet DISABLE_CEIP=1"
$Evergreen = Get-CitrixCQI
$appVersion = $Evergreen.Version
$appURL = $Evergreen.Uri
$appZip = Split-Path -Path $appURL -Leaf
$appSetup = "CitrixCQI.msi"
$appCitrixKB = "220774"
$appDestination = "${env:ProgramFiles(x86)}\Citrix\HDX\bin\Connection Quality Indicator"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName")
$appInstalledVersion = ((Get-InstalledApplication -Name "$appVendor $appName").DisplayVersion)
##*===============================================

If ([version]$appVersion -gt [version]$appInstalledVersion) {
    Set-Location -Path $appScriptDirectory
    If (-Not(Test-Path -Path $appVersion)) {New-Folder -Path $appVersion}
    Set-Location -Path $appVersion

    If (-Not(Test-Path -Path $appScriptDirectory\$appVersion\$appSetup))
    {
        Write-Log -Message "Signing in with your Citrix account..." -Severity 1 -LogType CMTrace -WriteHost $True
        $CitrixUserName = Read-Host -Prompt "Please supply your Citrix.com username"
        $CitrixPassword1 = Read-Host -Prompt "Please supply your Citrix.com password" -AsSecureString
        $CitrixPassword2 = Read-Host -Prompt "Please supply your Citrix.com password once more" -AsSecureString
        $CitrixPassword1Temp = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($CitrixPassword1))
        $CitrixPassword2Temp = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($CitrixPassword2))

        If ($CitrixPassword1Temp -ne $CitrixPassword2Temp)
        {
            Write-Log -Message "The supplied Citrix passwords missmatch!" -Severity 3 -LogType CMTrace -WriteHost $True
            Exit-Script -ExitCode 1
        }

        Remove-Variable -Name CitrixPassword1Temp, CitrixPassword2Temp
        $CitrixCredentials = New-Object System.Management.Automation.PSCredential ($CitrixUserName, $CitrixPassword1)

        # Verify Citrix credentials
        $CitrixUserName = $CitrixCredentials.UserName
        $CitrixPassword = $CitrixCredentials.GetNetworkCredential().Password

        # Download latest version
        Write-Log -Message "Downloading $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Get-CitrixDownload -CitrixKB $appCitrixKB -CitrixFile $appZip -CitrixUserName $CitrixUserName -CitrixPassword $CitrixPassword -FilePath $appScriptDirectory\$appVersion
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
    Get-Process -Name $appProcesses | Stop-Process -Force

    Write-Log -Message "Installing $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    Execute-MSI -Action Install -Path $appSetup -Parameters $appInstallParameters

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

    # Go back to the parent folder
    Set-Location ..

    Write-Log -Message "$appVendor $appName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True

}
Else {
    Write-Log -Message "$appVendor $appName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}