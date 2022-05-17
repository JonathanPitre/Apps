# Standalone application install script for VDI environment - (C)2021 Jonathan Pitre & Owen Reynolds, inspired by xenappblog.com

#Requires -Version 5.1
#Requires -RunAsAdministrator

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"
$env:SEE_MASK_NOZONECHECKS = 1
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

Function Get-AdobeCreativeCloud
{
    [OutputType([System.Management.Automation.PSObject])]
    [CmdletBinding()]
    Param()

    $URLDesktop = 'https://prod-rel-ffc-ccm.oobesaas.adobe.com/adobe-ffc-external/core/v1/wam/download?sapCode=KCCC&productName=Creative%20Cloud&os=win&environment=prod&api_key=CCHomeWeb1'
    $VersionDesktop = ((Invoke-WebRequest 'https://helpx.adobe.com/creative-cloud/release-note/cc-release-notes.html' -UseBasicParsing).Content | Select-String -Pattern '((?:\d+\.)+\d+).+mandatory release').Matches.Groups[1].Value

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
            Version      = $VersionDesktop
            Architecture = 'x64'
            Edition      = 'Desktop'
            Type         = 'Exe'
            URI          = $URLDesktop
        }
    }

    if ($Version64Enterprise -and $URL64Enterprise)
    {
        [PSCustomObject]@{
            Version      = $VersionDesktop
            Architecture = 'x64'
            Edition      = 'Enterprise'
            Type         = 'Exe'
            URI          = $URL64Enterprise
        }
    }

    if ($Version64Enterprise -and $URL64ZipEnterprise)
    {
        [PSCustomObject]@{
            Version      = $VersionDesktop
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
            Version      = $VersionDesktop
            Architecture = 'ARM64'
            Edition      = 'Enterprise'
            Type         = 'Zip'
            URI          = $URLARM64Enterprise
        }
    }
}

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$appVendor = "Adobe"
$appName = "Creative Cloud"
$appProcesses = @("ccxprocess", "Creative Cloud", "Creative Cloud Helper", "CRWindowsClientService", "AdobeNotificationHelper", "Adobe Application Updater", "adobe_licensing_helper", "AdobeExtensionsService",
    "HDHelper", "AdobeUpdateService", "Adobe Update Helper", "Adobe Desktop Service", "AdobeIPCBroker", "ACToolMain", "AdobeGCClient", "AGMService", "AGSService", "AGCInvokerUtility")
$appServices = @("AdobeUpdateService", "AGMService", "AGSService")
$appInstallParameters = "--silent" #--INSTALLLANGUAGE=<ProductInstallLanguage>
# How to use the Creative Cloud Cleaner tool - https://helpx.adobe.com/ca/creative-cloud/kb/cc-cleaner-tool-installation-problems.html
$appURLCleanerTool = "https://swupmf.adobe.com/webfeed/CleanerTool/win/AdobeCreativeCloudCleanerTool.exe"
$appCleanerTool = Split-Path -Path $appURLCleanerTool -Leaf
$appCleanerToolParameters = "--cleanupXML=$appScriptDirectory\cleanup.xml"
$Nevergreen = Get-AdobeCreativeCloud | Where-Object { $_.Architecture -eq "x64" -and $_.Edition -eq 'Enterprise' -and $_.Type -eq 'Zip' }
$appVersion = $Nevergreen.Version
$appURL = $Nevergreen.URI
$appZip = Split-Path -Path $appURL -Leaf
$appSetup = "Set-up.exe"
$appDestination = "${env:ProgramFiles(x86)}\Adobe\Adobe Creative Cloud\Utils"
$appConfigURL = "https://raw.githubusercontent.com/JonathanPitre/Apps/master/Adobe/Creative%20Cloud/com.adobe.acc.container.default.prefs"
$appConfigURL2 = "https://raw.githubusercontent.com/JonathanPitre/Apps/master/Adobe/Creative%20Cloud/com.adobe.acc.default.prefs"
$appConfig = Split-Path -Path $appConfigURL -Leaf
$appConfig2 = Split-Path -Path $appConfigURL2 -Leaf
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName")
$appInstalledVersion = (Get-InstalledApplication -Name "$appVendor $appName").DisplayVersion

#-----------------------------------------------------------[Execution]------------------------------------------------------------


If ([version]$appVersion -gt [version]$appInstalledVersion)
{
    Set-Location -Path $appScriptDirectory
    If (-Not(Test-Path -Path $appVersion)) { New-Folder -Path $appVersion }
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

    # Download latest version
    If (-Not(Test-Path -Path $appScriptDirectory\$appVersion\$appSetup))
    {
        Write-Log -Message "Downloading $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURL -OutFile $appZip
        Expand-Archive -Path $appZip -DestinationPath $appScriptDirectory\$appVersion
        Remove-File -Path $appZip
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
    Get-Service -Name $appServices[0] | Stop-Service -Force
    Get-Service -Name $appServices[1] | Stop-Service -Force
    Get-Service -Name $appServices[2] | Stop-Service -Force
    Set-ServiceStartMode -Name $appServices[0] -StartMode "Disabled" -ContinueOnError $True
    Set-ServiceStartMode -Name $appServices[1] -StartMode "Disabled" -ContinueOnError $True
    Set-ServiceStartMode -Name $appServices[2] -StartMode "Disabled" -ContinueOnError $True

    # Remove unneeded applications from running at start-up
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" -Name "Adobe Creative Cloud" -ContinueOnError $True
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" -Name "Adobe CCXProcess" -ContinueOnError $True
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "AdobeGCInvoker-1.0" -ContinueOnError $True
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "AdobeAAMUpdater-1.0" -ContinueOnError $True

    # Fix application Start Menu shorcut
    Remove-File -Path "$envCommonDesktop\$appVendor $appName.lnk" -ContinueOnError $True

    # Configure application settings - https://techlabs.blog/categories/how-to-guides/install-adobe-creative-cloud-on-citrix-virtual-desktop
    # Download required config file
    If (-Not(Test-Path -Path $appScriptDirectory\$appConfig) -or (-Not(Test-Path -Path $appScriptDirectory\$appConfig)))
    {
        Write-Log -Message "Downloading $appVendor $appName config file..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appConfigURL -OutFile $appScriptDirectory\$appConfig
        Invoke-WebRequest -UseBasicParsing -Uri $appConfigURL2 -OutFile $appScriptDirectory\$appConfig2
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    New-Folder -Path "$envSystemDrive\Users\Default\AppData\Local\Adobe\OOBE"
    Copy-File -Path "$appScriptDirectory\com.adobe.acc.container.default.prefs" -Destination "$envSystemDrive\Users\Default\AppData\Local\Adobe\OOBE\com.adobe.acc.container.default.prefs"
    Copy-File -Path "$appScriptDirectory\com.adobe.acc.default.prefs" -Destination "$envSystemDrive\Users\Default\AppData\Local\Adobe\OOBE\com.adobe.acc.default.prefs"

    # Go back to the parent folder
    Set-Location ..

    Write-Log -Message "$appVendor $appName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
}
Else
{
    Write-Log -Message "$appVendor $appName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}