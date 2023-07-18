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
$appName = "Acrobat"
$appShortVersion = "DC"
$appArchitecture = "x64"
$appProcesses = @("Acrobat", "AdobeCollabSync", "AcroCEF", "acrobat_sl", "acrodist", "AcroServicesUpdater", "acrotray", "AGSService", "outlook", "chrome", "iexplore")
$appServices = @("AdobeUpdateService")
$appTransformURL = "https://github.com/JonathanPitre/Apps/raw/master/Adobe/Acrobat DC/AcroProx64.mst"
$appTransform = Split-Path -Path $appTransformURL -Leaf
$appInstallParameters = "/QB"
$appAddParameters = "IGNOREVCRT64=1 EULA_ACCEPT=YES UPDATE_MODE=0 DISABLE_ARM_SERVICE_INSTALL=1 ROAMIDENTITY=1 ROAMLICENSING=1 DISABLE_FIU_CHECK=1 TRANSITION_INSTALL_MODE=3"
$Evergreen = Get-EvergreenApp -Name AdobeAcrobatDC | Where-Object { $_.Type -eq $appName -and $_.Architecture -eq $appArchitecture }
$appVersion = $Evergreen.Version
$appSetupURL = "https://trials.adobe.com/AdobeProducts/APRO/Acrobat_HelpX/win32/Acrobat_DC_Web_x64_WWMUI.zip"
$appSetup = Split-Path -Path $appSetupURL -Leaf
$appMsiSetup = "AcroPro.msi"
$appPatchURL = $Evergreen.URI
$appPatch = Split-Path -Path $appPatchURL -Leaf
$appDestination = "$env:ProgramFiles\$appVendor\$appName $appShortVersion\$appName"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName.*" -RegEx)
$appInstalledVersion = (Get-InstalledApplication -Name "$appVendor $appName (.*-bit)" -RegEx).DisplayVersion

#-----------------------------------------------------------[Execution]------------------------------------------------------------

If ([version]$appVersion -gt [version]$appInstalledVersion)
{
    Set-Location -Path $appScriptPath

    # Download latest setup file(s)
    If (-Not(Test-Path -Path $appScriptPath\$appMsiSetup))
    {
        Write-Log -Message "Downloading $appVendor $appName $appShortVersion $appArchitecture $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appSetupURL -OutFile $appSetup
        Write-Log -Message "Extracting $appVendor $appName $appShortVersion $appArchitecture $appVersion ZIP..." -Severity 1 -LogType CMTrace -WriteHost $True
        # Extract ZIP
        Expand-Archive -Path $appScriptPath\$appSetup -DestinationPath $appScriptPath -Force
        Copy-File -Path "$appScriptPath\$appVendor $appName\*" -Destination $appScriptPath -Recurse
        Remove-Folder -Path "$appScriptPath\$appVendor $appName"
        Remove-File -Path "$appScriptPath\$appSetup"
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Download latest patch
    If (-Not(Test-Path -Path $appScriptPath\$appPatch))
    {
        Write-Log -Message "Downloading $appVendor $appName $appShortVersion $appArchitecture $appVersion patch..." -Severity 1 -LogType CMTrace -WriteHost $True
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

    # Detect if Citrix Virtual Delivery Agent is installed
    [boolean]$isCitrixVdaInstalled = [boolean](Get-InstalledApplication -Name "Citrix .*Virtual Delivery Agent.*" -RegEx)
    $ctxHookExcludedProcesses = ""
    If ($isCitrixVdaInstalled)
    {
        # Get the excluded processes list from CtxHook
        $ctxHookExcludedProcesses = (Get-RegistryKey -Key "HKLM:\SOFTWARE\Citrix\CtxHook" -Value "ExcludedImageNames")
    }

    # Uninstall previous versions
    Get-Process -Name $appProcesses | Stop-Process -Force
    If (($IsAppInstalled) -and (Test-Path -Path $appScriptPath\$appMsiSetup))
    {
        Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
        Remove-MSIApplications -Name "$appVendor $appName* $appShortVersion*" -WildCard -Exact
    }

    If ((Test-Path -Path "$appScriptPath\$appMsiSetup") -and (Test-Path -Path $appScriptPath\$appPatch))
    {
        # Download required transform file
        If (-Not(Test-Path -Path $appScriptPath\$appTransform))
        {
            Write-Log -Message "Downloading $appVendor $appName $appShortVersion $appArchitecture transform..." -Severity 1 -LogType CMTrace -WriteHost $True
            Invoke-WebRequest -UseBasicParsing -Uri $appTransformURL -OutFile $appScriptPath\$appTransform
        }
        Else
        {
            Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
        }

        # Install latest version
        Write-Log -Message "Installing $appVendor $appName $appShortVersion $appArchitecture $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Execute-MSI -Action Install -Path $appMsiSetup -Transform $appTransform -Parameters $appInstallParameters -AddParameters $appAddParameters -Patch $appPatch -SkipMSIAlreadyInstalledCheck
    }
    ElseIf (($IsAppInstalled) -and (Test-Path -Path $appScriptPath\$appPatch))
    {
        # Install latest patch
        Write-Log -Message "Setup file(s) are missing, MSP file(s) will be installed instead." -Severity 2 -LogType CMTrace -WriteHost $True
        Write-Log -Message "Installing $appVendor $appName $appShortVersion $appArchitecture $appVersion patch..." -Severity 1 -LogType CMTrace -WriteHost $True
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

    # Stop and disable unneeded services
    Stop-ServiceAndDependencies -Name $appServices[0] -SkipServiceExistsTest -ContinueOnError $True
    Set-ServiceStartMode -Name $appServices[0] -StartMode "Disabled" -ContinueOnError $True

    # Remove unneeded applications from running at start-up
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Acrobat Assistant 8.0" -ContinueOnError $True
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "AdobeAAMUpdater-1.0" -ContinueOnError $True
    #Remove-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "AdobeGCInvoker-1.0" -ContinueOnError $True

    # Remove Active Setup
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components\{AC76BA86-0000-0000-7760-7E8A45000000}" -Name "StubPath"

    # Fix for Z@xxx.tmp files left behind in Temp folder after printing
    # https://pathandy.com/adobe-temp-files/
    # https://community.adobe.com/t5/acrobat-discussions/what-is-meaning-of-the-setting-tttosysprintdisabled-1-amp-t1tottdisabled-1-when-printing-from/m-p/11670068
    New-Item -Path "$envWinDir" -Name "acroct.ini" -Force
    Set-IniValue -FilePath $envWinDir\acroct.ini -Section "WinFntSvr" -Key "TTToSysPrintDisabled" -Value "1"
    Set-IniValue -FilePath $envWinDir\acroct.ini -Section "WinFntSvr" -Key "T1ToTTDisabled" -Value "1"

    If (-Not(Get-InstalledApplication -Name "Adobe Creative Cloud"))
    {
        Write-Log -Message "Adobe Creative Cloud must be installed in order for $appVendor $appName $appShortVersion licensing to work!" -Severity 2 -LogType CMTrace -WriteHost $True
    }

    # Fix an issue with Citrix Virtual Delivery Agent installed, excluded process from CtxHook gets overwritten by Adobe Acrobat installation
    If ($isCitrixVdaInstalled)
    {
        $ctxHookProcessesToAdd = @("Acrobat.exe", "AcroCEF.exe")
        If (-Not([String]::IsNullOrEmpty($ctxHookExcludedProcesses)))
        {
            ForEach ($ctxHookProcessToAdd in $ctxHookProcessesToAdd)
            {
                If ($ctxHookExcludedProcesses -like "*$ctxHookProcessToAdd*")
                {

                    Write-Log -Message "The $ctxHookProcessToAdd processes have already been added." -Severity 2 -LogType CMTrace -WriteHost $True
                }
                Else
                {
                    $ctxHookExcludedProcesses = $ctxHookExcludedProcesses + "," + $ctxHookProcessToAdd
                }

            }
        }
        Else
        {
            $ctxHookExcludedProcesses = "Acrobat.exe,AcroCEF.exe"
        }
        Set-RegistryKey -Key "HKLM:\SOFTWARE\Citrix\CtxHook" -Name "ExcludedImageNames" -Value $ctxHookExcludedProcesses -Type String
        Write-Log -Message "$appVendor $appName $appLongName fix for Citrix Virtual Delivery Agent was applied successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Go back to the parent folder
    Set-Location ..

    Write-Log -Message "$appVendor $appName $appShortVersion $appArchitecture $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
}
Else
{
    Write-Log -Message "$appVendor $appName $appShortVersion $appArchitecture $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}