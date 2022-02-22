# Standalone application install script for VDI environment - (C)2021 Jonathan Pitre & Owen Reynolds, inspired by xenappblog.com

#Requires -Version 5.1
#Requires -RunAsAdministrator

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"
$env:SEE_MASK_NOZONECHECKS = 1
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
    Write-Host -Object  "Importing $Module module..." -ForegroundColor Green

    # If module is imported say that and do nothing
    If (Get-Module | Where-Object {$_.Name -eq $Module})
    {
        Write-Host -Object  "Module $Module is already imported." -ForegroundColor Green
    }
    Else
    {
        # If module is not imported, but available on disk then import
        If (Get-Module -ListAvailable | Where-Object {$_.Name -eq $Module})
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
            If (Find-Module -Name $Module | Where-Object {$_.Name -eq $Module})
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

# https://www.winhelponline.com/blog/view-winhelp-hlp-files-windows-10-with-winhlp32-exe
$appVendor = "Microsoft"
$appName = "WinHlp32 Legacy"
$appProcesses = @("Winhlp32_legacy")
$appDestination = "${env:ProgramFiles(x86)}\WinHlp32 Legacy"
$appUrl = "https://download.microsoft.com/download/3/8/C/38C68F7C-1769-4089-BF21-3F5D8A556CBC/Windows8.1-KB917607-x86.msu"
$appSetup = Split-Path -Path $appURL -Leaf
$TempInstall = "$env:TEMP\WinHlp32 Legacy"
$TempLang = "$TempInstall\x86_microsoft-windows-winhstb.resources_31bf3856ad364e35_6.3.9600.20470"
$TempMain = "$TempInstall\x86_microsoft-windows-winhstb_31bf3856ad364e35_6.3.9600.20470_none_be363e6f3e19858c"
[boolean]$IsAppInstalled = [boolean](Test-Path -Path "$appDestination\winhlp32_legacy.exe")

#-----------------------------------------------------------[Execution]------------------------------------------------------------


If ($IsAppInstalled -eq $false)
{
    Set-Location -Path $appScriptDirectory
    Get-Process -Name $appProcesses | Stop-Process -Force

    # Download latest setup file(s)
    If (-Not(Test-Path -Path $appDestination\winhlp32_legacy.exe))
    {
        Write-Log -Message "Downloading $appVendor $appName..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURL -OutFile $appScriptDirectory\$appSetup
        
        Write-Log -Message "Installing $appVendor $appName..." -Severity 1 -LogType CMTrace -WriteHost $True
        New-Folder -Path $TempInstall
        Expand "$appScriptDirectory\$appSetup" -F:* "$TempInstall"
        Expand "$TempInstall\Windowx86.cab" -F:ftlx041*.dll "$TempInstall"
        Expand "$TempInstall\Windows8.1-KB917607-x86.cab" -F:winhlp32.ex* "$TempInstall"
        Expand "$TempInstall\Windows8.1-KB917607-x86.cab" -F:ftsrch.dl* "$TempInstalls8.1-KB917607-"

        Copy-File -Path "$($TempLang)_ar-sa_*\winhlp32.exe.mui" -Destination "$appDestination\ar-SA"
        Copy-File -Path "$($TempLang)_ar-sa_*\ftsrch.dll.mui" -Destination "$appDestination\ar-SA"
        Copy-File -Path "$($TempLang)_cs-cz_*\winhlp32.exe.mui" -Destination "$appDestination\cs-CZ"
        Copy-File -Path "$($TempLang)_cs-cz_*\ftsrch.dll.mui"  -Destination "$appDestination\cs-CZ"
        Copy-File -Path "$($TempLang)_da-dk_*\winhlp32.exe.mui" -Destination "$appDestination\da-DK"
        Copy-File -Path "$($TempLang)_da-dk_*\ftsrch.dll.mui" -Destination "$appDestination\da-DK"
        Copy-File -Path "$($TempLang)_de-de_*\winhlp32.exe.mui" -Destination "$appDestination\de-DE"
        Copy-File -Path "$($TempLang)_de-de_*\ftsrch.dll.mui" -Destination "$appDestination\de-DE"
        Copy-File -Path "$($TempLang)_el-gr_*\winhlp32.exe.mui" -Destination "$appDestination\el-GR"
        Copy-File -Path "$($TempLang)_el-gr_*\ftsrch.dll.mui" -Destination "$appDestination\el-GR"
        Copy-File -Path "$($TempLang)_en-us_*\winhlp32.exe.mui" -Destination "$appDestination\en-US"
        Copy-File -Path "$($TempLang)_en-us_*\ftsrch.dll.mui" -Destination "$appDestination\en-US"
        Copy-File -Path "$($TempLang)_es-es_*\winhlp32.exe.mui" -Destination "$appDestination\es-ES"
        Copy-File -Path "$($TempLang)_es-es_*\ftsrch.dll.mui" -Destination "$appDestination\es-ES"
        Copy-File -Path "$($TempLang)_fi-fi_*\winhlp32.exe.mui" -Destination "$appDestination\fi-FI"
        Copy-File -Path "$($TempLang)_fi-fi_*\ftsrch.dll.mui" -Destination "$appDestination\fi-FI"
        Copy-File -Path "$($TempLang)_fr-fr_*\winhlp32.exe.mui" -Destination "$appDestination\fr-FR"
        Copy-File -Path "$($TempLang)_fr-fr_*\ftsrch.dll.mui" -Destination "$appDestination\fr-FR"
        Copy-File -Path "$appDestination\fr-FR\*" -Destination "$appDestination\fr-CA"
        Copy-File -Path "$($TempLang)_he-il_*\winhlp32.exe.mui" -Destination "$appDestination\he-IL"
        Copy-File -Path "$($TempLang)_he-il_*\ftsrch.dll.mui" -Destination "$appDestination\he-IL"
        Copy-File -Path "$($TempLang)_hu-hu_*\winhlp32.exe.mui" -Destination "$appDestination\hu-HU"
        Copy-File -Path "$($TempLang)_hu-hu_*\ftsrch.dll.mui" -Destination "$appDestination\hu-HU"
        Copy-File -Path "$($TempLang)_it-it_*\winhlp32.exe.mui" -Destination "$appDestination\it-IT"
        Copy-File -Path "$($TempLang)_it-it_*\ftsrch.dll.mui" -Destination "$appDestination\it-IT"
        Copy-File -Path "$($TempLang)_ja-jp_*\winhlp32.exe.mui" -Destination "$appDestination\ja-JP"
        Copy-File -Path "$($TempLang)_ja-jp_*\ftsrch.dll.mui" -Destination "$appDestination\ja-JP"
        Copy-File -Path "$($TempLang)_ko-kr_*\winhlp32.exe.mui" -Destination "$appDestination\ko-KR"
        Copy-File -Path "$($TempLang)_ko-kr_*\ftsrch.dll.mui" -Destination "$appDestination\ko-KR"
        Copy-File -Path "$($TempLang)_nb-no_*\winhlp32.exe.mui" -Destination "$appDestination\nb-NO"
        Copy-File -Path "$($TempLang)_nb-no_*\ftsrch.dll.mui" -Destination "$appDestination\nb-NO"
        Copy-File -Path "$($TempLang)_nl-nl_*\winhlp32.exe.mui" -Destination "$appDestination\nl-NL"
        Copy-File -Path "$($TempLang)_nl-nl_*\ftsrch.dll.mui" -Destination "$appDestination\nl-NL"
        Copy-File -Path "$($TempLang)_pl-pl_*\winhlp32.exe.mui" -Destination "$appDestination\pl-PL"
        Copy-File -Path "$($TempLang)_pl-pl_*\ftsrch.dll.mui" -Destination "$appDestination\pl-PL"
        Copy-File -Path "$($TempLang)_pt-br_*\winhlp32.exe.mui" -Destination "$appDestination\pt-BR"
        Copy-File -Path "$($TempLang)_pt-br_*\ftsrch.dll.mui" -Destination "$appDestination\pt-BR"
        Copy-File -Path "$($TempLang)_pt-pt_*\winhlp32.exe.mui" -Destination "$appDestination\pt-PT"
        Copy-File -Path "$($TempLang)_pt-pt_*\ftsrch.dll.mui" -Destination "$appDestination\pt-PT"
        Copy-File -Path "$($TempLang)_ru-ru_*\winhlp32.exe.mui" -Destination "$appDestination\ru-RU"
        Copy-File -Path "$($TempLang)_ru-ru_*\ftsrch.dll.mui" -Destination "$appDestination\ru-RU"
        Copy-File -Path "$($TempLang)_sv-se_*\winhlp32.exe.mui" -Destination "$appDestination\sv-SE"
        Copy-File -Path "$($TempLang)_sv-se_*\ftsrch.dll.mui" -Destination "$appDestination\sv-SE"
        Copy-File -Path "$($TempLang)_tr-tr_*\winhlp32.exe.mui" -Destination "$appDestination\tr-TR"
        Copy-File -Path "$($TempLang)_tr-tr_*\ftsrch.dll.mui" -Destination "$appDestination\tr-TR"
        Copy-File -Path "$($TempLang)_zh-cn_*\winhlp32.exe.mui" -Destination "$appDestination\zh-CN"
        Copy-File -Path "$($TempLang)_zh-cn_*\ftsrch.dll.mui" -Destination "$appDestination\zh-CN"
        Copy-File -Path "$($TempLang)_zh-tw_*\winhlp32.exe.mui" -Destination "$appDestination\zh-TW"
        Copy-File -Path "$($TempLang)_zh-tw_*\ftsrch.dll.mui" -Destination "$appDestination\zh-TW"
        Get-ChildItem -Path $appDestination -File -Recurse -Include *.exe.mui | Rename-Item -NewName { $_.Name.replace(".exe.mui","_legacy.exe.mui") }
   
        Copy-File -Path "$TempMain\winhlp32.exe" -Destination "$appDestination\winhlp32_legacy.exe"
        Copy-File -Path "$TempMain\ftsrch.dll" -Destination "$appDestination"

        # Wordbreakers for Japanese and Thai when doing search indexes? https://docs.microsoft.com/en-us/windows/win32/search/understanding-language-resource-components
        Copy-File -Path "$TempMain\ftlx041e.dll" -Destination "$appDestination"
        Copy-File -Path "$TempMain\ftlx0411.dll" -Destination "$appDestination"

        # Cleanup
        Remove-File -Path $appScriptDirectory\$appSetup
        Remove-Folder -Path $TempInstall
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

    # Associate .hlp files
    #Execute-Process -Path "$envWinDir\System32\cmd.exe" -Parameters '/c assoc .hlp="$appDestination\$appSetup"'

    # Replace winhlp32 by winhlp32_legacy
    Set-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\winhlp32.exe" -Name "Debugger" -Value "`"$appDestination\winhlp32_legacy.exe`"" -Type "String"
    Set-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\winhlp32.exe" -Name "UseFilter" -Value "0" -Type "Dword"

    # https://support.microsoft.com/en-us/topic/error-opening-help-in-windows-based-programs-feature-not-included-or-help-not-supported-3c841463-d67c-6062-0ee7-1a149da3973b
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Wow6432Node\Microsoft\WinHelp" -Name "AllowProgrammaticMacros" -Value "1" -Type "Dword"
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Wow6432Node\Microsoft\WinHelp" -Name "AllowIntranetAccess" -Value "1" -Type "Dword"

    Set-RegistryKey -Key "HKLM:\SOFTWARE\Classes\.hlp" -Name '(Default)' -Value "hlpfile" -Type "String"
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Classes\Applications\winhlp32_legacy.exe\shell\open\command" -Name '(Default)' -Value "`"$appDestination\winhlp32_legacy.exe`" `"%1`"" -Type "String"

    # Go back to the parent folder
    Set-Location ..

    Write-Log -Message "$appVendor $appName was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
}
Else
{
    Write-Log -Message "$appVendor $appName is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}