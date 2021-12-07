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
$appName = "ImageGlass"
$appProcesses = @("ImageGlass")
$appInstallParameters = "/QB"
$appArchitecture = "x64"
$Evergreen = Get-EvergreenApp $appName | Where-Object { $_.Architecture -eq $appArchitecture }
$appVersion = $Evergreen.Version
$appURL = $Evergreen.URI
$appSetup = Split-Path -Path $appURL -Leaf
$appDestination = "$env:ProgramFiles\ImageGlass"
$appURLLang = "https://api.crowdin.com/api/project/imageglass/download/fr.zip?key=0b08634573c456476345efa8bad174f2"
$appLangZip = (Split-Path -Path $appURLLang -Leaf).Substring(0, 6)
$appURLConfigAdmin = "https://raw.githubusercontent.com/JonathanPitre/Apps/master/Image%20Glass/igconfig.admin.xml"
$appConfigAdmin = Split-Path -Path $appURLConfigAdmin -Leaf
$appURLConfigDefault = "https://raw.githubusercontent.com/JonathanPitre/Apps/master/Image%20Glass/igconfig.default.xml"
$appConfigDefault = Split-Path -Path $appURLConfigDefault -Leaf
$appURLTheme = "https://github.com/ImageGlass/theme/releases/download/8.2/Colibre-24.Amir-H-Jahangard.igtheme"
$appTheme = Split-Path -Path $appURLTheme -Leaf
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appName" -Exact)
$appInstalledVersion = (Get-InstalledApplication -Name "$appName" -Exact).DisplayVersion
##*===============================================

If ([version]$appVersion -gt [version]$appInstalledVersion)
{
    Set-Location -Path $appScriptDirectory
    If (-Not(Test-Path -Path $appVersion)) {New-Folder -Path $appVersion}
    Set-Location -Path $appVersion

    Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
    Remove-MSIApplications -Name $appName -Parameters $appInstallParameters -ContinueOnError
    Get-Process -Name $appProcesses | Stop-Process -Force

    # Download latest setup file(s)
    If (-Not(Test-Path -Path $appScriptDirectory\$appVersion\$appSetup))
    {
        Write-Log -Message "Downloading $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURL -OutFile $appSetup
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Download required configuration files
    If (-Not(Test-Path -Path $appScriptDirectory\$appConfigAdmin) -or (-Not(Test-Path -Path $appScriptDirectory\$appConfigDefault)))
    {
        Write-Log -Message "Downloading $appName configuration files.." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURLConfigAdmin -OutFile $appScriptDirectory\$appConfigAdmin
        Invoke-WebRequest -UseBasicParsing -Uri $appURLConfigDefault -OutFile $appScriptDirectory\$appConfigDefault
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

     If (-Not(Test-Path -Path $appScriptDirectory\*.iglang)) {
        Write-Log -Message "Downloading $appName language file..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURLLang -OutFile "$appScriptDirectory\$appLangZip"
        Expand-Archive -Path $appScriptDirectory\$appLangZip -DestinationPath $appScriptDirectory
        Remove-File -Path $appScriptDirectory\$appLangZip
    }
    Else {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    If (-Not(Test-Path -Path $appScriptDirectory\*.igtheme))
    {
        Write-Log -Message "Downloading $appName theme file..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURLTheme -OutFile "$appScriptDirectory\$appTheme"
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    Write-Log -Message "Installing $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    Execute-MSI -Action Install -Path $appSetup

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

    # Prevent the open with dialog after adding new applications
    # https://kolbi.cz/blog/2017/10/25/setuserfta-userchoice-hash-defeated-set-file-type-associations-per-user
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -Type DWord -Value "1"

    # Register file associations for images - https://imageglass.org/docs/command-line-utilities
    Execute-Process -Path "$appDestination\igtasks.exe" -Parameters "regassociations *.b64;*.bay;*.bmp;*.cap;*.cr2;*.crw;*.cur;*.cut;*.dcr;*.dcs;*.dds;*.dib;*.dng;*.drf;*.eip;*.emf;*.erf;*.exif;*.exr;*.fff;*.gif;*.gpr;*.hdr;*.heic;*.ico;*.iiq;*.jfif;*.jpe;*.jpeg;*.jpg;*.jxr;*.k25;*.kdc;*.mdc;*.mef;*.mos;*.mrw;*.nef;*.nrw;*.orf;*.pbm;*.pcx;*.pef;*.pgm;*.png;*.ppm;*.psb;*.psd;*.ptx;*.pxn;*.r3d;*.raf;*.raw;*.rw2;*.rwl;*.rwz;*.sr2;*.srf;*.srw;*.svg;*.tga;*.tif;*.tiff;*.wdp;*.webp;*.wpg;*.x3f;*.xbm" -IgnoreExitCodes

    # Install language pack - https://imageglass.org/docs/command-line-utilities
    Copy-File -Path $appScriptDirectory\*.iglang -Destination $appDestination\Languages

    # Copy admin configs - https://imageglass.org/docs/app-configs
    Copy-File -Path $appScriptDirectory\*.xml -Destination $appDestination

    # Copy themes files - https://github.com/d2phap/ImageGlass/issues/1112
    Copy-File -Path $appScriptDirectory\*.igtheme -Destination $appDestination\Themes

    # Remove desktop shortcut
    Remove-File -Path $envCommonDesktop\$appName.lnk -ContinueOnError

    # Go back to the parent folder
    Set-Location ..

    Write-Log -Message "$appName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
}
Else
{
    Write-Log -Message "$appName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}