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

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$appVendor = "Microsoft"
$URL = "https://docs.microsoft.com/en-us/azure/virtual-desktop/language-packs"
$currentYear = $currentDate.Split("-")[2]
$envOSDisplayVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").DisplayVersion
$Language = "fr-ca"

#-----------------------------------------------------------[Execution]------------------------------------------------------------

Set-Location -Path $appScriptDirectory
$WebResponse = (Invoke-WebRequest -Uri $URL -DisableKeepAlive -UseBasicParsing).RawContent

# Language Pack ISO
$regEx = "(https.+.iso).+(Windows \d{2}\, version \d{4} or later Language Pack ISO)"
$langISOurl = ($WebResponse | Select-String -Pattern $RegEx).Matches.Groups[1].Value
$langISO = Split-Path -Path $langISOurl -Leaf

# FOD Disk 1 ISO
$regEx = "(https.+.iso).+(Windows \d{2}\, version \d{4} or later FOD Disk 1 ISO)"
$FODisoUrl = ($WebResponse | Select-String -Pattern $RegEx).Matches.Groups[1].Value
$FODiso = Split-Path -Path $FODisoUrl -Leaf

# Inbox Apps ISO
$RegEx = "(https.+.iso).+(Windows \d{2}\, version \d{2}H\d or \d{2}H\d Inbox Apps ISO)"
$DownloadCount = ($WebResponse | Select-String -Pattern $RegEx -AllMatches).Matches.Count
$DownloadCount = $DownloadCount - 1
$inboxAppsIsoUrl = ($WebResponse | Select-String -Pattern $RegEx).Matches.Groups[1].Value
$inboxAppsIso = Split-Path -Path $inboxAppsIsoUrl -Leaf

# Local Experience Pack (LXP) ISO
$RegEx = "(https.+.iso).+(Windows \d{2}\, version \d{4} or later \d{2}C $currentYear LXP ISO)"
$DownloadCount = ($WebResponse | Select-String -Pattern $RegEx -AllMatches).Matches.Count
$DownloadCount = $DownloadCount - 1
$LXPisoUrl = ($WebResponse | Select-String -Pattern $RegEx -AllMatches).Matches[$DownloadCount].Groups[1].Value
$LXPiso = Split-Path -Path $LXPisoUrl -Leaf

# Download ISOs
# Download latest Language Pack ISO
If (-Not(Test-Path -Path $appScriptDirectory\$langISO))
{
    Write-Log -Message "Downloading $appVendor Language Pack ISO..." -Severity 1 -LogType CMTrace -WriteHost $True
    Invoke-WebRequest -UseBasicParsing -Uri $langISOurl -OutFile $langISO
}
Else
{
    Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
}

# Download latest FOD Disk 1 ISO
If (-Not(Test-Path -Path $appScriptDirectory\$FODiso))
{
    Write-Log -Message "Downloading $appVendor FOD Disk 1 ISO..." -Severity 1 -LogType CMTrace -WriteHost $True
    Invoke-WebRequest -UseBasicParsing -Uri $FODisoUrl -OutFile $FODiso
}
Else
{
    Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
}

# Download latest Inbox Apps ISO
If (-Not(Test-Path -Path $appScriptDirectory\$inboxAppsIso))
{
    Write-Log -Message "Downloading $appVendor Inbox Apps ISO..." -Severity 1 -LogType CMTrace -WriteHost $True
    Invoke-WebRequest -UseBasicParsing -Uri $inboxAppsIsoUrl -OutFile $inboxAppsIso
}
Else
{
    Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
}

# Download latest Local Experience Pack (LXP) ISO
If (-Not(Test-Path -Path $appScriptDirectory\$LXPiso))
{
    Write-Log -Message "Downloading $appVendor Local Experience Pack (LXP) ISO..." -Severity 1 -LogType CMTrace -WriteHost $True
    Invoke-WebRequest -UseBasicParsing -Uri $LXPisoUrl -OutFile $LXPiso
}
Else
{
    Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
}

# Copy Language Pack ISO files
$mountResult = Mount-DiskImage -ImagePath "$appScriptDirectory\$langISO" -PassThru
$driveLetter = ($mountResult | Get-Volume).DriveLetter
Write-Log -Message "Copying Language Pack files..." -Severity 1 -LogType CMTrace -WriteHost $True
Copy-File -Path "$($driveLetter):\LocalExperiencePack\$Language\*" -Destination "$appScriptDirectory"
Copy-File -Path "$($driveLetter):\x64\langpacks\Microsoft-Windows-Client-Language-Pack_x64_$($Language).cab" -Destination "$appScriptDirectory"
Start-Sleep -Seconds 5
Dismount-DiskImage -ImagePath "$appScriptDirectory\$langISO"

# Copy Inbox Apps ISO files
$mountResult = Mount-DiskImage -ImagePath "$appScriptDirectory\$FODiso" -PassThru
$driveLetter = ($mountResult | Get-Volume).DriveLetter
Write-Log -Message "Copying Inbox Apps files..." -Severity 1 -LogType CMTrace -WriteHost $True
Copy-File -Path "$($driveLetter):\Microsoft-Windows-InternetExplorer-Optional-Package~31bf3856ad364e35~amd64~$Language~.cab" -Destination "$appScriptDirectory"
Copy-File -Path "$($driveLetter):\Microsoft-Windows-LanguageFeatures-Basic-$Language-Package~31bf3856ad364e35~amd64~~.cab" -Destination "$appScriptDirectory"
#Copy-File -Path "$($driveLetter):\Microsoft-Windows-LanguageFeatures-Handwriting-$Language-Package~31bf3856ad364e35~amd64~~.cab" -Destination "$appScriptDirectory"
Copy-File -Path "$($driveLetter):\Microsoft-Windows-LanguageFeatures-OCR-$Language-Package~31bf3856ad364e35~amd64~~.cab" -Destination "$appScriptDirectory"
Copy-File -Path "$($driveLetter):\Microsoft-Windows-LanguageFeatures-Speech-$Language-Package~31bf3856ad364e35~amd64~~.cab" -Destination "$appScriptDirectory"
Copy-File -Path "$($driveLetter):\Microsoft-Windows-LanguageFeatures-TextToSpeech-$Language-Package~31bf3856ad364e35~amd64~~.cab" -Destination "$appScriptDirectory"
Copy-File -Path "$($driveLetter):\Microsoft-Windows-MSPaint-FoD-Package~31bf3856ad364e35~amd64~$Language~.cab" -Destination "$appScriptDirectory"
Copy-File -Path "$($driveLetter):\Microsoft-Windows-NetFx3-OnDemand-Package~31bf3856ad364e35~amd64~$Language~.cab" -Destination "$appScriptDirectory"
Copy-File -Path "$($driveLetter):\Microsoft-Windows-Notepad-FoD-Package~31bf3856ad364e35~amd64~$Language~.cab" -Destination "$appScriptDirectory"
Copy-File -Path "$($driveLetter):\Microsoft-Windows-PowerShell-ISE-FOD-Package~31bf3856ad364e35~amd64~$Language~.cab" -Destination "$appScriptDirectory"
Copy-File -Path "$($driveLetter):\Microsoft-Windows-Printing-WFS-FoD-Package~31bf3856ad364e35~amd64~$Language~.cab" -Destination "$appScriptDirectory"
Copy-File -Path "$($driveLetter):\Microsoft-Windows-StepsRecorder-Package~31bf3856ad364e35~amd64~$Language~.cab" -Destination "$appScriptDirectory"
Copy-File -Path "$($driveLetter):\Microsoft-Windows-WordPad-FoD-Package~31bf3856ad364e35~amd64~$Language~.cab" -Destination "$appScriptDirectory"
Start-Sleep -Seconds 5
Dismount-DiskImage -ImagePath "$appScriptDirectory\$FODiso"

# Copy FOD Disk 1 ISO files
$mountResult = Mount-DiskImage -ImagePath "$appScriptDirectory\$inboxAppsIso" -PassThru
$driveLetter = ($mountResult | Get-Volume).DriveLetter
Write-Log -Message "Copying FOD Disk 1 files..." -Severity 1 -LogType CMTrace -WriteHost $True
Copy-File -Path "$($driveLetter):\amd64fre\*" -Destination "$appScriptDirectory"
Start-Sleep -Seconds 5
Dismount-DiskImage -ImagePath "$appScriptDirectory\$inboxAppsIso"

# Copy Local Experience Pack (LXP) ISO files
$mountResult = Mount-DiskImage -ImagePath "$appScriptDirectory\$LXPiso" -PassThru
$driveLetter = ($mountResult | Get-Volume).DriveLetter
Write-Log -Message "Copying Local Experience Pack (LXP) files..." -Severity 1 -LogType CMTrace -WriteHost $True
Copy-File -Path "$($driveLetter):\LocalExperiencePack\$Language\*" -Destination "$appScriptDirectory"
Start-Sleep -Seconds 5
Dismount-DiskImage -ImagePath "$appScriptDirectory\$LXPiso"

########################################################
## Add Languages to running Windows Image for Capture ##
########################################################

# Disable Language Pack Cleanup
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\AppxDeploymentClient\" -TaskName "Pre-staged app cleanup"

# Add Language Files
Write-Log -Message "Adding language files..." -Severity 1 -LogType CMTrace -WriteHost $True
Add-AppProvisionedPackage -Online -PackagePath $appScriptDirectory\$Language\LanguageExperiencePack.$Language.Neutral.appx -LicensePath $appScriptDirectory\$Language\License.xml
Add-WindowsPackage -Online -PackagePath $appScriptDirectory\Microsoft-Windows-Client-Language-Pack_x64_$Language.cab
Add-WindowsPackage -Online -PackagePath $appScriptDirectory\Microsoft-Windows-InternetExplorer-Optional-Package~31bf3856ad364e35~amd64~$Language~.cab
Add-WindowsPackage -Online -PackagePath $appScriptDirectory\Microsoft-Windows-LanguageFeatures-Basic-$Language-Package~31bf3856ad364e35~amd64~~.cab
Add-WindowsPackage -Online -PackagePath $appScriptDirectory\Microsoft-Windows-LanguageFeatures-Handwriting-$Language-Package~31bf3856ad364e35~amd64~~.cab
Add-WindowsPackage -Online -PackagePath $appScriptDirectory\Microsoft-Windows-LanguageFeatures-OCR-$Language-Package~31bf3856ad364e35~amd64~~.cab
Add-WindowsPackage -Online -PackagePath $appScriptDirectory\Microsoft-Windows-LanguageFeatures-Speech-$Language-Package~31bf3856ad364e35~amd64~~.cab
Add-WindowsPackage -Online -PackagePath $appScriptDirectory\Microsoft-Windows-LanguageFeatures-TextToSpeech-$Language-Package~31bf3856ad364e35~amd64~~.cab
Add-WindowsPackage -Online -PackagePath $appScriptDirectory\Microsoft-Windows-MSPaint-FoD-Package~31bf3856ad364e35~amd64~$Language~.cab
Add-WindowsPackage -Online -PackagePath $appScriptDirectory\Microsoft-Windows-NetFx3-OnDemand-Package~31bf3856ad364e35~amd64~$Language~.cab
Add-WindowsPackage -Online -PackagePath $appScriptDirectory\Microsoft-Windows-Notepad-FoD-Package~31bf3856ad364e35~amd64~$Language~.cab
Add-WindowsPackage -Online -PackagePath $appScriptDirectory\Microsoft-Windows-PowerShell-ISE-FOD-Package~31bf3856ad364e35~amd64~$Language~.cab
Add-WindowsPackage -Online -PackagePath $appScriptDirectory\Microsoft-Windows-Printing-WFS-FoD-Package~31bf3856ad364e35~amd64~$Language~.cab
Add-WindowsPackage -Online -PackagePath $appScriptDirectory\Microsoft-Windows-StepsRecorder-Package~31bf3856ad364e35~amd64~$Language~.cab
Add-WindowsPackage -Online -PackagePath $appScriptDirectory\Microsoft-Windows-WordPad-FoD-Package~31bf3856ad364e35~amd64~$Language~.cab

$LanguageList = Get-WinUserLanguageList
$LanguageList.Add("$Language")
Set-WinUserLanguageList $LanguageList -Force
Start-Sleep -Seconds 20

#########################################
## Update Inbox Apps for Multi Language##
#########################################

# Update installed Inbox Store App
Write-Log -Message "Updating Inbox Store App files..." -Severity 1 -LogType CMTrace -WriteHost $True
foreach ($App in (Get-AppxProvisionedPackage -Online))
{
    $AppPath = $appScriptDirectory + $App.DisplayName + '_' + $App.PublisherId
    Write-Host "Handling $AppPath"
    $licFile = Get-Item $AppPath*.xml
    if ($licFile.Count)
    {
        $lic = $true
        $licFilePath = $licFile.FullName
    }
    else
    {
        $lic = $false
    }
    $appxFile = Get-Item $AppPath*.appx*
    if ($appxFile.Count)
    {
        $appxFilePath = $appxFile.FullName
        if ($lic)
        {
            Add-AppxProvisionedPackage -Online -PackagePath $appxFilePath -LicensePath $licFilePath
        }
        else
        {
            Add-AppxProvisionedPackage -Online -PackagePath $appxFilePath -SkipLicense
        }
    }
}

Write-Log -Message "$Language Language Pack was sucesfully installed!" -Severity 1 -LogType CMTrace -WriteHost $True

# Cleanup
Remove-File -Path $appScriptDirectory\*.iso