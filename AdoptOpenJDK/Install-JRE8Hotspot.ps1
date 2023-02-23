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
$Modules = @("PSADT", "Nevergreen") # Modules list

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

$appVendor = "AdoptOpenJDK"
$appName = "JRE"
$appMajorVersion = "8"
$appPlatform = "HotSpot Normal JRE"
$appArchitecture = "x64"
$appProcesses = @("java", "javaw", "javaws")
$appInstallParameters = "/QB"
$appAddParameters = "ADDLOCAL=FeatureMain,FeatureEnvironment,FeatureJarFileRunWith,FeatureJavaHome,FeatureIcedTeaWeb,FeatureJNLPFileRunWith"
$Nevergreen = Get-NevergreenApp AdoptOpenJDK | Where-Object { $_.Name -like "$appVendor$appMajorVersion" -and $_.Platform -eq $appPlatform -and $_.Architecture -eq $appArchitecture -and $_.Type -eq "Msi" }
$appVersion = $Nevergreen.Version
$appURL = $Nevergreen.URI
$appSetup = Split-Path -Path $appURL -Leaf
$appMinorVersion = $appVersion.Split(".")[2].Substring(0, 3)
$appDestination = "$env:ProgramFiles\$appVendor\jre-$appMajorVersion.0.$appMinorVersion.1-hotspot\bin"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName")
$appInstalledVersion = (Get-InstalledApplication -Name "$appVendor $appName").DisplayVersion

#-----------------------------------------------------------[Execution]------------------------------------------------------------

{
    Set-Location -Path $appScriptPath
    If (-Not(Test-Path -Path $appVersion)) { New-Folder -Path $appVersion }
    Set-Location -Path $appVersion

    # Uninstall previous versions
    Get-Process -Name $appProcesses | Stop-Process -Force
    # Uninstall java
    Remove-MSIApplications -Name "Java"
    If ($IsAppInstalled)
    {
        Remove-MSIApplications -Name "$appVendor $appName"
    }

    # Download latest setup file(s)
    If (-Not(Test-Path -Path $appScriptPath\$appVersion\$appSetup))
    {
        Write-Log -Message "Downloading $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURL -OutFile $appSetup
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Install latest version
    Write-Log -Message "Installing $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    Execute-MSI -Action Install -Path $appSetup -Parameters $appInstallParameters -AddParameters $appAddParameters

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

    # Associate .jar file extension - https://github.com/AdoptOpenJDK/IcedTea-Web/issues/268
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Classes\.jar" -Name "(Default)" -Value "AdoptOpenJDK.jarfile" -Type String
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Classes\.jar" -Name "Content Type" -Value "application/jar" -Type String
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Classes\AdoptOpenJDK.jarfile\shell\open\command" -Name "(Default)" -Value "`"C:\Program Files\AdoptOpenJDK\jre-$appMajorVersion.0.$appMinorVersion.1-hotspot\bin\javaw.exe`" -jar `"%1`" %*" -Type String
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Classes\MIME\Database\Content Type\application/jar" -Name "Extension" -Value ".jar" -Type String

    # Associate .jnlp file extension- https://github.com/AdoptOpenJDK/IcedTea-Web/issues/268
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Classes\.jnlp" -Name "(Default)" -Value "JNLPFile" -Type String
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Classes\.jnlp" -Name "Content Type" -Value "application/x-java-jnlp-file" -Type String
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Classes\jnlp" -Name "(Default)" -Value "URL:jnlp Protocol" -Type String
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Classes\jnlp" -Name "URL Protocol" -Value "" -Type String
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Classes\jnlp\shell\open\command" -Name "(Default)" -Value "`"C:\Program Files\AdoptOpenJDK\jre-$appMajorVersion.0.$appMinorVersion.1-hotspot\bin\javaws.exe`" `"%1`"" -Type String
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Classes\JNLPFile" -Name "(Default)" -Value "JNLP File" -Type String
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Classes\JNLPFile" -Name "EditFlags" -Value "65536" -Type DWord
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Classes\JNLPFile\DefaultIcon" -Name "(Default)" -Value "`"C:\Program Files\AdoptOpenJDK\jre-$appMajorVersion.0.$appMinorVersion.1-hotspot\share\pixmaps\javaws.ico`"" -Type String
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Classes\JNLPFile\shell\open\command" -Name "(Default)" -Value "`"C:\Program Files\AdoptOpenJDK\jre-$appMajorVersion.0.$appMinorVersion.1-hotspot\bin\javaws.exe`" `"%1`"" -Type String
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Classes\jnlps" -Name "(Default)" -Value "URL:jnlp Protocol" -Type String
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Classes\jnlps" -Name "URL Protocol" -Value "" -Type String
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Classes\jnlps\shell\open\command" -Name "(Default)" -Value "`"C:\Program Files\AdoptOpenJDK\jre-$appMajorVersion.0.$appMinorVersion.1-hotspot\bin\javaws.exe`" `"%1`"" -Type String
    #Set-RegistryKey -Key "HKLM:\SOFTWARE\Classes\Database\Content Type\application/x-java-jnlp-file" -Name "Extension" -Value ".jnlp" -Type String
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Classes\MIME\Database\Content Type\application/x-java-jnlp-file" -Name "Extension" -Value ".jnlp" -Type String

    # Go back to the parent folder
    Set-Location ..

    Write-Log -Message "$appVendor $appName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
}
Else
{
    Write-Log -Message "$appVendor $appName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}