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

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$appVendor = "Adobe"
$appName = "Acrobat"
$appProduct = "Reader"
$appTrack = "DC"
$appLanguage = "MUI"
$appArchitecture = "x64"
$appProcesses = @("Acrobat", "AdobeCollabSync", "AcroCEF", "acrobat_sl")
$appTransformURL = "https://github.com/JonathanPitre/Apps/raw/master/Adobe/Acrobat%20Reader%20DC/AcroProx64.mst"
$appTransform = Split-Path -Path $appTransformURL -Leaf
$appInstallParameters = "/QB"
$appAddParameters = "EULA_ACCEPT=YES DISABLE_CACHE=1 DISABLE_PDFMAKER=YES DISABLEDESKTOPSHORTCUT=0 UPDATE_MODE=0 DISABLE_ARM_SERVICE_INSTALL=1 LANG_LIST=All DISABLE_FIU_CHECK=1"
$Evergreen = Get-EvergreenApp -Name AdobeAcrobatReaderDC | Where-Object { $_.Language -eq $appLanguage -and $_.Architecture -eq $appArchitecture }
$appVersion = $Evergreen.Version
$appSetupURL = $Evergreen.URI
$appSetup = Split-Path -Path $appSetupURL -Leaf
$appMsiSetup = "AcroPro.msi"
$EvergreenPatch = Get-EvergreenApp -Name AdobeAcrobat | Where-Object { $_.Product -eq $appProduct -and $_.Track -eq $appTrack -and $_.Language -eq "Multi" -and $_.Architecture -eq $appArchitecture }
$appPatchVersion = $EvergreenPatch.Version
$appPatchURL = $EvergreenPatch.URI
$appPatch = Split-Path -Path $appPatchURL -Leaf
$appDestination = "$env:ProgramFiles\$appVendor\$appName $appTrack\$appName"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName.*" -RegEx)
$appInstalledVersion = (Get-InstalledApplication -Name "$appVendor $appName.* (.*-bit)" -RegEx).DisplayVersion

#-----------------------------------------------------------[Execution]------------------------------------------------------------

If ([version]$appPatchVersion -gt [version]$appInstalledVersion)
{
    Set-Location -Path $appScriptDirectory

    # Download latest setup file(s)
    If (-Not(Test-Path -Path $appScriptDirectory\$appMsiSetup))
    {
        Write-Log -Message "Downloading $appVendor $appName $appProduct $appTrack $appLanguage $appArchitecture $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appSetupURL -OutFile $appSetup
        Write-Log -Message "Extracting $appVendor $appName $appProduct $appTrack $appLanguage $appArchitecture $appVersion MSI..." -Severity 1 -LogType CMTrace -WriteHost $True
        New-Folder -Path "$appScriptDirectory\MSI"
        # Extract MSI
        Execute-Process -Path .\$appSetup -Parameters "-sfx_o`"$appScriptDirectory\MSI`" -sfx_ne"
        Copy-File -Path "$appScriptDirectory\MSI\*" -Destination $appScriptDirectory -Recurse
        Remove-Folder -Path "$appScriptDirectory\MSI"
        Remove-File -Path "$appScriptDirectory\$appSetup"
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Download latest patch
    If (-Not(Test-Path -Path $appScriptDirectory\$appPatch))
    {
        Write-Log -Message "Downloading $appVendor $appName $appProduct $appTrack $appArchitecture $appPatchVersion patch..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appPatchURL -OutFile $appPatch
        # Modify setup.ini according to latest patch
        If ((Test-Path -Path $appScriptDirectory\$appPatch) -and (Test-Path -Path $appScriptDirectory\$appPatch\setup.ini))
        {
            Set-IniValue -FilePath $appScriptDirectory\setup.ini -Section "Startup" -Key "CmdLine" -Value "/sPB /rs /msi $appAddParameters"
            Set-IniValue -FilePath $appScriptDirectory\setup.ini -Section "Product" -Key "CmdLine" -Value "TRANSFORMS=`"$appTransform`""
            Set-IniValue -FilePath $appScriptDirectory\setup.ini -Section "Product" -Key "PATCH" -Value $appPatch
        }
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Uninstall previous versions
    Get-Process -Name $appProcesses | Stop-Process -Force
    If (($IsAppInstalled) -and (Test-Path -Path $appScriptDirectory\$appMsiSetup))
    {
        Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
        Remove-MSIApplications -Name "$appVendor $appName* $appTrack*" -WildCard -Exact
    }

    If ((Test-Path -Path "$appScriptDirectory\$appMsiSetup") -and (Test-Path -Path $appScriptDirectory\$appPatch))
    {
        # Download required transform file
        If (-Not(Test-Path -Path $appScriptDirectory\$appTransform))
        {
            Write-Log -Message "Downloading $appVendor $appName $appProduct $appTrack $appArchitecture transform..." -Severity 1 -LogType CMTrace -WriteHost $True
            Invoke-WebRequest -UseBasicParsing -Uri $appTransformURL -OutFile $appScriptDirectory\$appTransform
        }
        Else
        {
            Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
        }

        # Install latest version
        Write-Log -Message "Installing $appVendor $appName $appProduct $appTrack $appLanguage $appArchitecture $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Execute-MSI -Action Install -Path $appMsiSetup -Transform $appTransform -Parameters $appInstallParameters -AddParameters $appAddParameters -SkipMSIAlreadyInstalledCheck
        $appInstalledVersion = (Get-InstalledApplication -Name "$appVendor $appName $appTrack (64-bit)" -Exact).DisplayVersion
    }

    If (([version]$appPatchVersion -gt [version]$appInstalledVersion) -and (Test-Path -Path $appScriptDirectory\$appPatch))
    {
        # Install latest patch
        Write-Log -Message "Setup file(s) are missing, MSP file(s) will be installed instead." -Severity 2 -LogType CMTrace -WriteHost $True
        Write-Log -Message "Installing $appVendor $appName $appProduct $appTrack $appArchitecture $appPatchVersion patch..." -Severity 1 -LogType CMTrace -WriteHost $True
        Execute-MSP -Path $appPatch
    }
    Else
    {
        Write-Log -Message "Setup file(s) are missing." -Severity 3 -LogType CMTrace -WriteHost $True
        Exit-Script
    }

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

    # Stop and disable unneeded scheduled tasks
    Get-ScheduledTask -TaskName "$appVendor $appName Update Task" | Stop-ScheduledTask
    Get-ScheduledTask -TaskName "$appVendor $appName Update Task" | Disable-ScheduledTask

    # Remove Active Setup
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components\{AC76BA86-0000-0000-7760-7E8A45000000}" -Name "StubPath"

    # Fix for Z@xxx.tmp files left behind in Temp folder after printing
    # https://pathandy.com/adobe-temp-files/
    # https://community.adobe.com/t5/acrobat-discussions/what-is-meaning-of-the-setting-tttosysprintdisabled-1-amp-t1tottdisabled-1-when-printing-from/m-p/11670068
    New-Item -Path "$envWinDir" -Name "acroct.ini" -Force
    Set-IniValue -FilePath $envWinDir\acroct.ini -Section "WinFntSvr" -Key "TTToSysPrintDisabled" -Value "1"
    Set-IniValue -FilePath $envWinDir\acroct.ini -Section "WinFntSvr" -Key "T1ToTTDisabled" -Value "1"

    # Configure application shortcut
    Remove-File -Path "$envCommonDesktop\$appVendor $appName.lnk" -ContinueOnError $True

    # Go back to the parent folder
    Set-Location ..

    Write-Log -Message "$appVendor $appName $appProduct $appTrack $appLanguage $appArchitecture $appPatchVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
}
Else
{
    Write-Log -Message "$appVendor $appName $appProduct $appTrack $appLanguage $appArchitecture $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}