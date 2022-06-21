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

$appVendor = "Foxit"
$appName = "PDF Editor"
$appProcesses = @("FoxitPDFEditor", "FoxitPDFEditorUpdateService", "FoxitPDFCEF64")
$appServices = @("FoxitPhantomPDFUpdateService")
$appInstallParameters = "/QB"
# https://kb.foxitsoftware.com/hc/en-us/articles/360040660271--Command-line-Deployments-of-Foxit-PDF-Editor
$appAddParameters = "DESKTOP_SHORTCUT=0 LAUNCHCHECKDEFAULT=0 AUTO_UPDATE=0 LAUNCHCHECKDEFAULT=0 NOTINSTALLUPDATE=1 KEYPATH=`"$appScriptDirectory\fpmkey.txt`""
$appUninstallParameters = "/QB CLEAN=1"
$appLanguage = "Multi-Language"
$Evergreen = Get-EvergreenApp -Name FoxitPDFEditor | Where-Object { $_.Language -eq $appLanguage }
$appVersion = $Evergreen.Version
$appURL = $Evergreen.URI
$appSetup = Split-Path -Path $appURL -Leaf
$appTransformURL = "https://github.com/JonathanPitre/Apps/raw/master/Apps/Foxit/PDF%20Editor/FoxitPDFEditor.mst"
$appTransform = Split-Path -Path $appTransformURL -Leaf
$appDestination = "${env:ProgramFiles(x86)}\Foxit Software\Foxit PDF Editor"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName")
$appInstalledVersion = ((Get-InstalledApplication -Name "$appVendor $appName").DisplayVersion)

#-----------------------------------------------------------[Execution]------------------------------------------------------------

If ([version]$appVersion -gt [version]$appInstalledVersion)
{
    Set-Location -Path $appScriptDirectory
    If (-Not(Test-Path -Path $appVersion)) { New-Folder -Path $appVersion }
    Set-Location -Path $appVersion

    # Download latest setup file(s)
    If (-Not(Test-Path -Path $appScriptDirectory\$appVersion\$appSetup))
    {
        Write-Log -Message "Downloading $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURL -OutFile $appSetup
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Download required transform file
    If (-Not(Test-Path -Path $appScriptDirectory\$appTransform))
    {
        Write-Log -Message "Downloading $appVendor $appName Transform.." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appTransformURL -OutFile $appScriptDirectory\$appTransform
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
        #Get-Process explorer | Stop-Process -Force
        Remove-MSIApplications -Name "$appVendor $appName" -Parameters $appInstallParameters -AddParameters $appUninstallParameters
    }

    # Install latest version
    Write-Log -Message "Installing $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    Execute-MSI -Action Install -Path $appSetup -Parameters $appInstallParameters -AddParameters $appAddParameters -Transform "$appScriptDirectory\$appTransform"

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

    # Stop and disable unneeded services
    Stop-ServiceAndDependencies -Name $appServices[0]
    Set-ServiceStartMode -Name $appServices[0] -StartMode "Disabled"

    # Configure application shortcut
    Copy-File -Path "$envCommonStartMenuPrograms\$appVendor $appName\$appVendor $appName.lnk" -Destination "$envCommonStartMenuPrograms" -ContinueFileCopyOnError $True
    Copy-File -Path "$envCommonStartMenuPrograms\$appVendor $appName\Activation.lnk" -Destination "$envCommonStartMenuPrograms\Administrative Tools\Foxit PDF Editor Activation.lnk" -ContinueFileCopyOnError $True
    Remove-Folder -Path "$envCommonStartMenuPrograms\$appVendor $appName" -ContinueOnError $True

    # Go back to the parent folder
    Set-Location ..

    Write-Log -Message "$appVendor $appName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
}
Else
{
    Write-Log -Message "$appVendor $appName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}