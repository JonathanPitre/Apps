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

Function Get-AdobeCreativeCloud
{
    <#
    .NOTES
        Author: Jonathan Pitre
        Twitter: @PitreJonathan
    #>
    [OutputType([System.Management.Automation.PSObject])]
    [CmdletBinding()]
    Param()

    $VersionDesktop = ((Invoke-WebRequest 'https://helpx.adobe.com/ie/creative-cloud/release-note/cc-release-notes.html' -UseBasicParsing).Content | Select-String -Pattern '((?:\d+\.)+\d+).+mandatory release').Matches.Groups[1].Value
    $URLDesktop = 'https://prod-rel-ffc-ccm.oobesaas.adobe.com/adobe-ffc-external/core/v1/wam/download?sapCode=KCCC&productName=Creative%20Cloud&os=win&environment=prod&api_key=CCHomeWeb1'

    $URL64ZipEnterprise = ((Invoke-WebRequest -Uri 'https://helpx.adobe.com/ca/download-install/kb/creative-cloud-desktop-app-download.html' -UseBasicParsing).Links | Where-Object href -Like '*win64*')[0].href
    $Version64Enterprise = ($URL64ZipEnterprise | Select-String -Pattern 'ACCCx((?:\d+_)+(?:\d+)).zip$').Matches.Groups[1] -replace ("_", ".")
    $URL64Enterprise = 'https://prod-rel-ffc-ccm.oobesaas.adobe.com/adobe-ffc-external/core/v1/wam/download?sapCode=KCCC&productName=Creative%20Cloud&os=win&guid=db6d0d93-606a-4dad-be46-4d7ca43fdf10&contextParams=%7B%22component%22%3A%22cc-home%22%2C%22visitor_guid%22%3A%2280873655155223673852670279815058766993%22%2C%22browser%22%3A%22Chrome%22%2C%22context_guid%22%3A%228929cf6c-c4f0-4dff-a1f5-d0a84e26caf6%22%2C%22planCodeList%22%3A%22dc_free%7Ccc_free%22%2C%22installerWaitTime%22%3A30%2C%22updateCCD%22%3A%22true%22%2C%22secondarySapcodeList%22%3A%22%22%2C%22Product_ID_Promoted%22%3A%22KCCC%22%2C%22userGuid%22%3A%22839D16724F1F72C40A490D45%40AdobeID%22%2C%22authId%22%3A%22839D16724F1F72C40A490D45%40AdobeID%22%2C%22contextComName%22%3A%22ACom%3ACCH%22%2C%22contextSvcName%22%3A%22NO-CCD%22%2C%22contextOrigin%22%3A%22ACom%3ACCH%22%2C%22gpv%22%3A%22helpx.adobe.com%3Adownload-install%3Akb%3Acreative-cloud-desktop-app-download%22%2C%22creative-cloud-referrer%22%3A%22https%3A%2F%2Fhelpx.adobe.com%2F%22%2C%22AMCV_D6FAAFAD54CA9F560A4C98A5%2540AdobeOrg%22%3A%22870038026%257CMCMID%257C80873655155223673852670279815058766993%257CvVersion%257C5.0.0%22%2C%22mid%22%3A%2209147132003933883351319444832905857026%22%2C%22aid%22%3A%22%22%2C%22AppMeasurementVersion%22%3A%222.20.0%22%2C%22kaizenTrialDuration%22%3A7%7D&wamFeature=nuj-live&environment=prod&api_key=CCHomeWeb1'

    $URL32Enterprise = ((Invoke-WebRequest -Uri 'https://helpx.adobe.com/ca/download-install/kb/creative-cloud-desktop-app-download.html' -UseBasicParsing).Links | Where-Object href -Like '*win32*')[0].href
    $Version32Enterprise = ($URL32Enterprise | Select-String -Pattern 'ACCCx((?:\d+_)+(?:\d+)).zip$').Matches.Groups[1] -replace ("_", ".")

    $URLARM64Enterprise = ((Invoke-WebRequest -Uri 'https://helpx.adobe.com/ca/download-install/kb/creative-cloud-desktop-app-download.html' -UseBasicParsing).Links | Where-Object href -Like '*winarm64*')[0].href
    $VersionARM64Enterprise = ($URLARM64Enterprise | Select-String -Pattern 'ACCCx((?:\d+_)+(?:\d+)).zip$').Matches.Groups[1] -replace ("_", ".")

    if ($VersionDesktop -and $URLDesktop)
    {
        [PSCustomObject]@{
            Version      = $Version64Enterprise
            Architecture = 'x64'
            Edition      = 'Desktop'
            Type         = 'Exe'
            URI          = $URLDesktop
        }
    }

    if ($Version64Enterprise -and $URL64Enterprise)
    {
        [PSCustomObject]@{
            Version      = $Version64Enterprise
            Architecture = 'x64'
            Edition      = 'Enterprise'
            Type         = 'Exe'
            URI          = $URL64Enterprise
        }
    }

    if ($Version64Enterprise -and $URL64ZipEnterprise)
    {
        [PSCustomObject]@{
            Version      = $Version64Enterprise
            Architecture = 'x64'
            Edition      = 'Enterprise'
            Type         = 'Zip'
            URI          = $URL64ZipEnterprise
        }
    }

    if ($Version32Enterprise -and $URL32Enterprise)
    {
        [PSCustomObject]@{
            Version      = $Version32Enterprise
            Architecture = 'x86'
            Edition      = 'Enterprise'
            Type         = 'Zip'
            URI          = $URL32Enterprise
        }
    }

    if ($VersionARM64Enterprise -and $URLARM64Enterprise)
    {
        [PSCustomObject]@{
            Version      = $VersionARM64Enterprise
            Architecture = 'ARM64'
            Edition      = 'Enterprise'
            Type         = 'Zip'
            URI          = $URLARM64Enterprise
        }
    }
}

$appVendor = "Adobe"
$appName = "Creative Cloud"
$appSetup = "Creative_Cloud_Set-Up.exe"
$appProcesses = @("ccxprocess", "Creative Cloud", "Creative Cloud Helper", "CRWindowsClientService", "AdobeNotificationHelper", "Adobe Application Updater", "adobe_licensing_helper", "AdobeExtensionsService",
    "HDHelper", "AdobeUpdateService", "Adobe Update Helper", "Adobe Desktop Service", "AdobeIPCBroker", "ACToolMain", "AdobeGCClient", "AGMService", "AGSService", "AGCInvokerUtility")
$appServices = @("AdobeUpdateService", "AGMService", "AGSService")
$appInstallParameters = "--silent" #--INSTALLLANGUAGE=<ProductInstallLanguage>
# How to use the Creative Cloud Cleaner tool - https://helpx.adobe.com/ca/creative-cloud/kb/cc-cleaner-tool-installation-problems.html
$appURLCleanerTool = "https://swupmf.adobe.com/webfeed/CleanerTool/win/AdobeCreativeCloudCleanerTool.exe"
$appCleanerTool = Split-Path -Path $appURLCleanerTool -Leaf
$appCleanerToolParameters = "--cleanupXML=$appScriptDirectory\cleanup.xml"
$Nevergreen = Get-AdobeCreativeCloud | Where-Object {$_.Architecture -eq "x64" -and $_.Edition -eq 'Enterprise' -and $_.Type -eq 'Exe'}
$appVersion = $Nevergreen.Version
$appURL = $Nevergreen.URI
$appDestination = "${env:ProgramFiles(x86)}\Adobe\Adobe Creative Cloud\Utils"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName")
$appInstalledVersion = (Get-InstalledApplication -Name "$appVendor $appName").DisplayVersion
##*===============================================

If ([version]$appVersion -gt [version]$appInstalledVersion)
{
    Set-Location -Path $appScriptDirectory
    If (-Not(Test-Path -Path $appVersion)) {New-Folder -Path $appVersion}
    Set-Location -Path $appVersion

    # Download latest cleaner tool
    If (-Not(Test-Path -Path $appScriptDirectory\$appVersion\$appCleanerTool))
    {
        Write-Log -Message "Downloading $appVendor $appName Cleaner Tool..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURLCleanerTool -OutFile $appCleanerTool
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Uninstall previous versions
    Get-Process -Name $appProcesses | Stop-Process -Force
    If ($IsAppInstalled)
    {
        Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
        #Execute-Process -Path .\$appCleanerTool -Parameters "$appCleanerToolParameters"
        Execute-Process -Path "$appDestination\Creative Cloud Uninstaller.exe" -Parameters "-uninstall"
        Wait-Process -Name "Creative Cloud Uninstaller"
    }

    # Download latest file installer
    If (-Not(Test-Path -Path $appScriptDirectory\$appVersion\$appSetup))
    {
        Write-Log -Message "Downloading $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURL -OutFile $appSetup
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Install latest version
    If (Test-Path -Path $appScriptDirectory\$appVersion\$appSetup)
    {
        Write-Log -Message "Installing $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Copy-File -Path .\$appSetup -Destination $envSystemDrive\ -ContinueOnError $True
        Execute-Process -Path $envSystemDrive\$appSetup -Parameters $appInstallParameters
        Get-Process -Name $appProcesses | Stop-Process -Force
    }
    Else
    {
        Write-Log -Message "Setup file(s) are missing." -Severity 1 -LogType CMTrace -WriteHost $True
        Exit-Script
    }

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

    # Stop and disable unneeded scheduled tasks
    Get-ScheduledTask -TaskName "$($appVendor)GCInvoker-1.0" | Stop-ScheduledTask
    Get-ScheduledTask -TaskName "$($appVendor)GCInvoker-1.0" | Disable-ScheduledTask

    # Stop and disable unneeded services
    Stop-ServiceAndDependencies -Name $appServices[0]
    Stop-ServiceAndDependencies -Name $appServices[1]
    Stop-ServiceAndDependencies -Name $appServices[2]
    Set-ServiceStartMode -Name $appServices[0] -StartMode "Disabled"
    Set-ServiceStartMode -Name $appServices[1] -StartMode "Disabled"
    Set-ServiceStartMode -Name $appServices[2] -StartMode "Disabled"

    # Remove unneeded applications from running at start-up
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" -Name "Adobe Creative Cloud" -ContinueOnError $True
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" -Name "Adobe CCXProcess" -ContinueOnError $True
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "AdobeGCInvoker-1.0" -ContinueOnError $True

    # Fix application Start Menu shorcut
    Remove-File -Path "$envCommonDesktop\$appVendor $appName.lnk" -ContinueOnError $True

    # Go back to the parent folder
    Set-Location ..

    Write-Log -Message "$appVendor $appName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
}
Else
{
    Write-Log -Message "$appVendor $appName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}