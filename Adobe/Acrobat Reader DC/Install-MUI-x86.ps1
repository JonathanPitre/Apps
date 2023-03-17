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
$Modules = @("PSADT", "Evergreen") # Modules list

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

Function Initialize-Module
{
    <#
    .SYNOPSIS
        Initialize-Module install and import modules from PowerShell Galllery.
    .OUTPUTS
        System.String
    #>
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
#endregion

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$appVendor = "Adobe"
$appName = "Acrobat Reader"
$appProduct = "Reader"
$appTrack = "DC"
$appLanguage = "MUI"
$appArchitecture = "x86"
$appProcesses = @("AcroRd32", "AdobeCollabSync", "ReaderCEF", "reader_sl")
$appTransformURL = "https://github.com/JonathanPitre/Apps/raw/master/Adobe/Acrobat%20Reader%20DC/AcroRead.mst"
$appTransform = Split-Path -Path $appTransformURL -Leaf
$appInstallParameters = "/QB"
$appAddParameters = "EULA_ACCEPT=YES DISABLE_CACHE=1 DISABLE_PDFMAKER=YES DISABLEDESKTOPSHORTCUT=0 UPDATE_MODE=0 DISABLE_ARM_SERVICE_INSTALL=1 LANG_LIST=All"
$appAddParameters2 = "ALLUSERS=1"
$Evergreen = Get-EvergreenApp -Name AdobeAcrobatReaderDC | Where-Object { $_.Language -eq $appLanguage -and $_.Architecture -eq $appArchitecture }
$appVersion = $Evergreen.Version
$appSetupURL = $Evergreen.URI
$appSetup = Split-Path -Path $appSetupURL -Leaf
$appMsiSetup = "AcroRead.msi"
$EvergreenPatch = Get-EvergreenApp -Name AdobeAcrobatDC | Where-Object { $_.Type -eq "ReaderMUI" -and $_.Architecture -eq $appArchitecture }
$appPatchVersion = $EvergreenPatch.Version
$appPatchURL = $EvergreenPatch.URI
$appPatch = Split-Path -Path $appPatchURL -Leaf
$appFontURL = "https://ardownload2.adobe.com/pub/adobe/reader/win/AcrobatDC/misc/FontPack2100120135_XtdAlf_Lang_DC.msi"
$appFont = Split-Path -Path $appFontURL -Leaf
$appDicURL = "https://ardownload2.adobe.com/pub/adobe/reader/win/AcrobatDC/misc/AcroRdrSD1900820071_all_DC.msi"
$appDic = Split-Path -Path $appDicURL -Leaf
$appDestination = "${env:ProgramFiles(x86)}\$appVendor\$appName $appShortVersion\$appName2"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName.* $appShortVersion .*" -RegEx)
$appInstalledVersion = (Get-InstalledApplication -Name "$appVendor $appName $appShortVersion MUI" -Exact).DisplayVersion

#-----------------------------------------------------------[Execution]------------------------------------------------------------

If ([version]$appPatchVersion -gt [version]$appInstalledVersion)
{
    Set-Location -Path $appScriptPath

    # Download latest setup file(s)
    If (-Not(Test-Path -Path $appScriptPath\$appMsiSetup))
    {
        Write-Log -Message "Downloading $appVendor $appName $appProduct $appTrack $appLanguage $appArchitecture $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appSetupURL -OutFile $appSetup
        Write-Log -Message "Extracting $appVendor $appName $appProduct $appTrack $appLanguage $appArchitecture $appVersion MSI..." -Severity 1 -LogType CMTrace -WriteHost $True
        New-Folder -Path "$appScriptPath\MSI"
        # Extract MSI
        Execute-Process -Path .\$appSetup -Parameters "-sfx_o`"$appScriptPath\MSI`" -sfx_ne"
        Copy-File -Path "$appScriptPath\MSI\*" -Destination $appScriptPath -Recurse
        Remove-Folder -Path "$appScriptPath\MSI"
        Remove-File -Path "$appScriptPath\$appSetup"
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Download latest patch
    If (-Not(Test-Path -Path $appScriptPath\$appPatch))
    {
        Write-Log -Message "Downloading $appVendor $appName $appProduct $appTrack $appArchitecture $appPatchVersion patch..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appPatchURL -OutFile $appPatch
        # Modify setup.ini according to latest patch
        If ((Test-Path -Path $appScriptPath\$appPatch) -and (Test-Path -Path $appScriptPath\$appPatch\setup.ini))
        {
            Set-IniValue -FilePath $appScriptPath\setup.ini -Section "Startup" -Key "CmdLine" -Value "/sPB /rs /msi $appAddParameters"
            Set-IniValue -FilePath $appScriptPath\setup.ini -Section "Product" -Key "CmdLine" -Value "TRANSFORMS=`"$appTransform`""
            Set-IniValue -FilePath $appScriptPath\setup.ini -Section "Product" -Key "PATCH" -Value $appPatch
        }
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Uninstall previous versions
    Get-Process -Name $appProcesses | Stop-Process -Force
    If (($IsAppInstalled) -and (Test-Path -Path $appScriptPath\$appMsiSetup))
    {
        Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
        Remove-MSIApplications -Name "$appVendor $appName*" -WildCard
    }

    If ((Test-Path -Path "$appScriptPath\$appMsiSetup") -and (Test-Path -Path $appScriptPath\$appPatch))
    {
        # Download required transform file
        If (-Not(Test-Path -Path $appScriptPath\$appTransform))
        {
            Write-Log -Message "Downloading $appVendor $appName $appProduct $appTrack $appArchitecture transform..." -Severity 1 -LogType CMTrace -WriteHost $True
            Invoke-WebRequest -UseBasicParsing -Uri $appTransformURL -OutFile $appScriptPath\$appTransform
        }
        Else
        {
            Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
        }

        # Install latest version
        Write-Log -Message "Installing $appVendor $appName $appProduct $appTrack $appLanguage $appArchitecture $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Execute-MSI -Action Install -Path $appMsiSetup -Transform $appTransform -Parameters $appInstallParameters -AddParameters $appAddParameters -SkipMSIAlreadyInstalledCheck
	$appInstalledVersion = (Get-InstalledApplication -Name "$appVendor $appName" -Exact).DisplayVersion
    }
    If (([version]$appPatchVersion -gt [version]$appInstalledVersion) -and (Test-Path -Path $appScriptPath\$appPatch))
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

    # Install Extended Asian Language Font Pack
    If (-Not(Test-Path -Path $appScriptPath\$appFont))
    {
        Write-Log -Message "Downloading $appVendor $appName $appShortVersion Extended Asian Language Font Pack..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appFontURL -OutFile $appFont
        Write-Log -Message "Installing $appVendor $appName $appShortVersion Extended Asian Language Font Pack..." -Severity 1 -LogType CMTrace -WriteHost $True
        Execute-MSI -Action Install -Path $appFont -Parameters $appInstallParameters -AddParameters $appAddParameters2
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
        Write-Log -Message "Installing $appVendor $appName $appShortVersion Extended Asian Language Font Pack..." -Severity 1 -LogType CMTrace -WriteHost $True
        Execute-MSI -Action Install -Path $appFont -Parameters $appInstallParameters -AddParameters $appAddParameters2
    }

    # Install Spelling Dictionaries
    If (-Not(Test-Path -Path $appScriptPath\$appDIC))
    {
        Write-Log -Message "Downloading $appVendor $appName $appShortVersion Spelling Dictionaries..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appDicURL -OutFile $appDic
        Write-Log -Message "Installing $appVendor $appName $appShortVersion Spelling Dictionaries..." -Severity 1 -LogType CMTrace -WriteHost $True
        Execute-MSI -Action Install -Path $appDic -Parameters $appInstallParameters -AddParameters $appAddParameters2
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
        Write-Log -Message "Installing $appVendor $appName $appShortVersion Spelling Dictionaries..." -Severity 1 -LogType CMTrace -WriteHost $True
        Execute-MSI -Action Install -Path $appDic -Parameters $appInstallParameters -AddParameters $appAddParameters2
    }

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

    # Stop and disable unneeded scheduled tasks
    Get-ScheduledTask -TaskName "$appVendor Acrobat Update Task" | Stop-ScheduledTask
    Get-ScheduledTask -TaskName "$appVendor Acrobat Update Task" | Disable-ScheduledTask

    # Configure application shortcut
    Copy-File -Path "$envCommonStartMenuPrograms\$appName $appShortVersion.lnk" -Destination "$envCommonStartMenuPrograms\$appVendor $appName $appShortVersion.lnk" -ContinueFileCopyOnError $True
    Remove-File -Path "$envCommonStartMenuPrograms\$appName $appShortVersion.lnk" -ContinueOnError $True

    # Remove Active Setup
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components\{A6EADE66-0000-0000-484E-7E8A45000000}" -Name "StubPath"

    # Fix for Z@xxx.tmp files left behind in Temp folder after printing
    # https://pathandy.com/adobe-temp-files/
    # https://community.adobe.com/t5/acrobat-discussions/what-is-meaning-of-the-setting-tttosysprintdisabled-1-amp-t1tottdisabled-1-when-printing-from/m-p/11670068
    New-Item -Path "$envWinDir" -Name "acroct.ini" -Force
    Set-IniValue -FilePath $envWinDir\acroct.ini -Section "WinFntSvr" -Key "TTToSysPrintDisabled" -Value "1"
    Set-IniValue -FilePath $envWinDir\acroct.ini -Section "WinFntSvr" -Key "T1ToTTDisabled" -Value "1"

    # Go back to the parent folder
    Set-Location ..

    Write-Log -Message "$appVendor $appName $appProduct $appTrack $appLanguage $appArchitecture $appPatchVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
}
Else
{
    Write-Log -Message "$appVendor $appName $appProduct $appTrack $appLanguage $appArchitecture $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}