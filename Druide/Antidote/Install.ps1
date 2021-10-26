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
Function Get-DruideAntidote
{
    [OutputType([System.Management.Automation.PSObject])]
    [CmdletBinding()]
    Param ()
    $DownloadURL = "https://www.antidote.info/fr/assistance/mises-a-jour/installation/antidote-10/windows"

    Try
    {
        $DownloadText = (Invoke-WebRequest -Uri $DownloadURL -DisableKeepAlive -UseBasicParsing).Links
    }
    Catch
    {
        Throw "Failed to connect to URL: $DownloadURL with error $_."
        Break
    }
    Finally
    {
        $RegExAntidote = "href\=(https.+\/Diff_Antidote_10_C_((?:\d+\.)+(?:\d+))\.msp)"
        $VersionAntidote = ($DownloadText | Select-String -Pattern $RegExAntidote).Matches.Groups[2].Value
        $URLAntidote = ($DownloadText | Select-String -Pattern $RegExAntidote).Matches.Groups[1].Value

        $RegExAntidoteF = "href\=(https.+\/Diff_Antidote_10_Module_F_((?:\d+\.)+(?:\d+))\.msp)"
        $VersionAntidoteF = ($DownloadText | Select-String -Pattern $RegExAntidoteF).Matches.Groups[2].Value
        $URLAntidoteF = ($DownloadText | Select-String -Pattern $RegExAntidoteF).Matches.Groups[1].Value

        $RegExAntidoteE = "href\=(https.+\/Diff_Antidote_10_Module_E_((?:\d+\.)+(?:\d+))\.msp)"
        $VersionAntidoteE = ($DownloadText | Select-String -Pattern $RegExAntidoteE).Matches.Groups[2].Value
        $URLAntidoteE = ($DownloadText | Select-String -Pattern $RegExAntidoteE).Matches.Groups[1].Value

        $RegExConnectix = "href\=(https.+\/Diff_Connectix_10_C_((?:\d+\.)+(?:\d+))\.msp)"
        $VersionConnectix = ($DownloadText | Select-String -Pattern $RegExConnectix).Matches.Groups[2].Value
        $URLConnectix = ($DownloadText | Select-String -Pattern $RegExConnectix).Matches.Groups[1].Value

        $URLGestionnaire = "https://telechargement.druide.com/telecharger/Reseau/antidote_10/GestionnaireMultiposte_Antidote10.exe"

        if ($VersionAntidote -and $URLAntidote)
        {
            [PSCustomObject]@{
                Name         = 'Antidote'
                Architecture = 'x86'
                Type         = 'Msp'
                Version      = $VersionAntidote
                Uri          = $URLAntidote
            }
        }

        if ($VersionAntidoteF -and $URLAntidoteF)
        {
            [PSCustomObject]@{
                Name         = 'Antidote French Module'
                Architecture = 'x86'
                Type         = 'Msp'
                Version      = $VersionAntidoteF
                Uri          = $URLAntidoteF
            }
        }

        if ($VersionAntidoteE -and $URLAntidoteE)
        {
            [PSCustomObject]@{
                Name         = 'Antidote English Module'
                Architecture = 'x86'
                Type         = 'Msp'
                Version      = $VersionAntidoteE
                Uri          = $URLAntidoteE
            }
        }

        if ($VersionConnectix -and $URLConnectix)
        {
            [PSCustomObject]@{
                Name         = 'Connectix'
                Architecture = 'x86'
                Type         = 'Msp'
                Version      = $VersionConnectix
                Uri          = $URLConnectix
            }
        }

        if ($URLGestionnaire)
        {
            [PSCustomObject]@{
                Name         = 'Gestionnaire Multiposte'
                Architecture = 'x86'
                Type         = 'Exe'
                Uri          = $URLGestionnaire
            }
        }
    }
}

$appVendor = "Druide"
$appName = "Antidote"
$appProcesses = @("Antidote", "AgentAntidote", "Connectix", "AgentConnectix", "OUTLOOK", "WINWORD", "EXCEL", "POWERPNT")
$appTransformAntidote = "ReseauAntidote.mst"
$appTransformConnectix = "ReseauConnectix.mst"
$appShortVersion = "10"
$DownloadText = (Invoke-WebRequest -Uri "https://www.antidote.info/fr/assistance/mises-a-jour/installation/antidote-10/windows" -DisableKeepAlive -UseBasicParsing).Content
$appVersion = ($DownloadText | Select-String -Pattern "MSI ((?:\d+\.)+(?:\d+))").Matches.Groups[1].Value
$Nevergreen = Get-DruideAntidote
$appPatchVersion = ($Nevergreen | Where-Object { $_.Name -eq $appName }).Version
$appUrlPatchAntidote = ($Nevergreen | Where-Object { $_.Name -eq $appName }).Uri
$appUrlPatchAntidoteF = ($Nevergreen | Where-Object { $_.Name -eq "$appName French Module" }).Uri
$appUrlPatchAntidoteE = ($Nevergreen | Where-Object { $_.Name -eq "$appName English Module" }).Uri
$appUrlPatchConnectix = ($Nevergreen | Where-Object { $_.Name -eq "Connectix" }).Uri
$appUrlGestionnaire = ($Nevergreen | Where-Object { $_.Name -eq "Gestionnaire Multiposte" }).Uri
$appPatchAntidote = Split-Path -Path $appUrlPatchAntidote -Leaf
$appPatchAntidoteF = Split-Path -Path $appUrlPatchAntidoteF -Leaf
$appPatchAntidoteE = Split-Path -Path $appUrlPatchAntidoteE -Leaf
$appPatchConnectix = Split-Path -Path $appUrlPatchConnectix -Leaf
$appGestionnaire = Split-Path -Path $appUrlGestionnaire -Leaf
$appSetupAntidote = "Antidote$appShortVersion.msi"
$appSetupAntidoteF = "Antidote$appShortVersion-Module-francais.msi"
$appSetupAntidoteE = "Antidote$appShortVersion-English-module.msi"
$appSetupConnectix = "Antidote-Connectix$appShortVersion.msi"
$appInstallParameters = "/QB"
$appDestination = "${env:ProgramFiles(x86)}\$appVendor\$appName $appShortVersion\Application\Bin64"
[boolean]$isAppInstalled = [boolean](Get-InstalledApplication -Name "$appName \d{2}" -RegEx -Exact) | Select-Object -First 1
$appInstalledVersion = (Get-InstalledApplication -Name "$appName \d{2}" -RegEx -Exact).DisplayVersion | Select-Object -First 1
##*===============================================

If ([version]$appVersion -gt [version]$appInstalledVersion)
{
    Set-Location -Path $appScriptDirectory
    If (-Not(Test-Path -Path $appPatchVersion)) { New-Folder -Path $appPatchVersion }

    # Uninstall previous versions
    #Get-Process -Name $appProcesses | Stop-Process -Force
    #If ($IsAppInstalled) {
    #    Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
    #    Remove-MSIApplications -Name $appName -Parameters $appInstallParameters
    #}

    # Download latest Gestionnaire Multipostes setup
    Write-Log -Message "Downloading $appVendor $appName $appShortVersion Gestionnaire Multipostes..." -Severity 1 -LogType CMTrace -WriteHost $True
    Invoke-WebRequest -UseBasicParsing -Uri $appUrlGestionnaire -OutFile $appScriptDirectory\$appGestionnaire

    # Download latest setup file(s)
    If (-Not(Test-Path -Path $appScriptDirectory\$appPatchVersion\$appPatchAntidote))
    {
        Write-Log -Message "Downloading $appVendor $appName $appPatchVersion patch..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appUrlPatchAntidote -OutFile $appScriptDirectory\$appPatchVersion\$appPatchAntidote
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    If (-Not(Test-Path -Path $appScriptDirectory\$appPatchVersion\$appPatchAntidoteF))
    {
        Write-Log -Message "Downloading $appVendor $appName $appPatchVersion French module patch..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appUrlPatchAntidoteF -OutFile $appScriptDirectory\$appPatchVersion\$appPatchAntidoteF
    }

    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }
    If (-Not(Test-Path -Path $appScriptDirectory\$appPatchVersion\$appPatchAntidoteE))
    {
        Write-Log -Message "Downloading $appVendor $appName $appPatchVersion English module patch..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appUrlPatchAntidoteE -OutFile $appScriptDirectory\$appPatchVersion\$appPatchAntidoteE
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    If (-Not(Test-Path -Path $appScriptDirectory\$appPatchVersion\$appPatchConnectix))
    {
        Write-Log -Message "Downloading $appVendor $appName $appPatchVersion Connectix patch..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appUrlPatchConnectix -OutFile $appScriptDirectory\$appPatchVersion\$appPatchConnectix
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Antidote setup
    If ((Test-Path -Path $appScriptDirectory\$appSetupAntidote) -and (Test-Path -Path $appScriptDirectory\$appTransformAntidote))
    {
        Write-Log -Message "Installing $appVendor $appName $appPatchVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        # Install latest Antidote version
        Execute-MSI -Action Install -Path $appSetupAntidote -Parameters $appInstallParameters -Transform $appTransformAntidote -Patch "$appScriptDirectory\$appPatchVersion\$appPatchAntidote"
    }
    ElseIf (($isAppInstalled) -and (Test-Path -Path "$appScriptDirectory\$appPatchVersion\$appPatchAntidote"))
    {
        # Install latest Antidote patch
        Write-Log -Message "Setup file(s) are missing, MSP file(s) will be installed instead." -Severity 2 -LogType CMTrace -WriteHost $True
        Write-Log -Message "Installing  $appVendor $appName $appPatchVersion patch..." -Severity 1 -LogType CMTrace -WriteHost $True
        Execute-MSP -Path "$appScriptDirectory\$appPatchVersion\$appPatchAntidote"
    }
    Else
    {
        Write-Log -Message "Setup file(s) are missing." -Severity 2 -LogType CMTrace -WriteHost $True
        Exit-Script
    }

    # Antidote French module setup
    If ((Test-Path -Path $appScriptDirectory\$appSetupAntidoteF) -and (Test-Path -Path $appScriptDirectory\$appTransformAntidote))
    {
        Write-Log -Message "Installing $appVendor $appName $appPatchVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        # Install latest Antidote French module version
        Execute-MSI -Action Install -Path $appSetupAntidoteF -Parameters $appInstallParameters -Transform $appTransformAntidote -Patch "$appScriptDirectory\$appPatchVersion\$appPatchAntidoteF"
    }
    ElseIf (($isAppInstalled) -and (Test-Path -Path "$appScriptDirectory\$appPatchVersion\$appPatchAntidoteF"))
    {
        # Install latest Antidote French module patch
        Write-Log -Message "Setup file(s) are missing, MSP file(s) will be installed instead." -Severity 2 -LogType CMTrace -WriteHost $True
        Write-Log -Message "Installing  $appVendor $appName $appPatchVersion French module patch..." -Severity 1 -LogType CMTrace -WriteHost $True
        Execute-MSP -Path "$appScriptDirectory\$appPatchVersion\$appPatchAntidoteF"
    }
    Else
    {
        Write-Log -Message "Setup file(s) are missing." -Severity 2 -LogType CMTrace -WriteHost $True
        Exit-Script
    }

    # Antidote English module setup
    If ((Test-Path -Path $appScriptDirectory\$appSetupAntidoteE) -and (Test-Path -Path $appScriptDirectory\$appTransformAntidote))
    {
        Write-Log -Message "Installing $appVendor $appName $appPatchVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        # Install latest Antidote English module version
        Execute-MSI -Action Install -Path $appSetupAntidoteE -Parameters $appInstallParameters -Transform $appTransformAntidote -Patch "$appScriptDirectory\$appPatchVersion\$appPatchAntidoteE"
    }
    ElseIf (($isAppInstalled) -and (Test-Path -Path "$appScriptDirectory\$appPatchVersion\$appPatchAntidoteE"))
    {
        # Install latest Antidote English module patch
        Write-Log -Message "Setup file(s) are missing, MSP file(s) will be installed instead." -Severity 2 -LogType CMTrace -WriteHost $True
        Write-Log -Message "Installing  $appVendor $appName $appPatchVersion English module patch..." -Severity 1 -LogType CMTrace -WriteHost $True
        Execute-MSP -Path "$appScriptDirectory\$appPatchVersion\$appPatchAntidoteE"
    }
    Else
    {
        Write-Log -Message "Setup file(s) are missing." -Severity 3 -LogType CMTrace -WriteHost $True
        Exit-Script
    }

    # Connectix setup
    If ((Test-Path -Path $appScriptDirectory\$appSetupConnectix) -and (Test-Path -Path $appScriptDirectory\$appTransformConnectix))
    {
        Write-Log -Message "Installing $appVendor $appName $appPatchVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        # Install latest Connectix version
        Execute-MSI -Action Install -Path $appSetupConnectix -Parameters $appInstallParameters -Transform $appTransformConnectix -Patch "$appScriptDirectory\$appPatchVersion\$apspPatchConnectix"
    }
    ElseIf (($isAppInstalled) -and (Test-Path -Path "$appScriptDirectory\$appPatchVersion\$apspPatchConnectix"))
    {
        # Install latest Connectix patch
        Write-Log -Message "Setup file(s) are missing, MSP file(s) will be installed instead." -Severity 2 -LogType CMTrace -WriteHost $True
        Write-Log -Message "Installing  $appVendor $appName $appPatchVersion Connectix patch..." -Severity 1 -LogType CMTrace -WriteHost $True
        Execute-MSP -Path "$appScriptDirectory\$appPatchVersion\$apspPatchConnectix"
    }
    Else
    {
        Write-Log -Message "Setup file(s) are missing." -Severity 2 -LogType CMTrace -WriteHost $True
        Exit-Script
    }

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

    # Go back to the parent folder
    Set-Location ..

    Write-Log -Message "$appVendor $appName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
}
Else
{
    Write-Log -Message "$appVendor $appName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}