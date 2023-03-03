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

$appVendor = "Oracle"
$appName = "Java"
$appMajorVersion = "8"
$appArchitecture = "x86"
$appProcesses = @("java", "javaw", "javaws", "javacpl", "jp2launcher")
$appInstallParameters = "INSTALL_SILENT=1 STATIC=0 AUTO_UPDATE=0 WEB_JAVA=1 WEB_JAVA_SECURITY_LEVEL=H WEB_ANALYTICS=0 EULA=0 REBOOT=0 REMOVEOUTOFDATEJRES=1 NOSTARTMENU=1 SPONSORS=0"
$Evergreen = Get-EvergreenApp -Name $appVendor$appName$appMajorVersion | Where-Object { $_.Architecture -eq $appArchitecture }
$appVersion = $Evergreen.Version.Replace("-b", "0.").Replace("_", ".").Substring(2)
$appMinorVersion = $appVersion.Split(".")[2].Substring(0, 3)
$appURL = $Evergreen.URI
$appSetup = Split-Path -Path $appURL -Leaf
If ($appArchitecture -eq "x64") { $appDestination = "$env:ProgramFiles\$appName\jre1.$appMajorVersion.0_$appMinorVersion\bin" }
If ($appArchitecture -eq "x86") { $appDestination = "${env:ProgramFiles(x86)}\$appName\jre1.$appMajorVersion.0_$appMinorVersion\bin" }
$appURLDeploymentConfig = "https://raw.githubusercontent.com/JonathanPitre/Apps/master/Oracle/Java/deployment.config"
$appDeploymentConfig = Split-Path -Path $appURLDeploymentConfig -Leaf
$appURLDeploymentProperties = "https://raw.githubusercontent.com/JonathanPitre/Apps/master/Oracle/Java/deployment.properties"
$appDeploymentProperties = Split-Path -Path $appURLDeploymentProperties -Leaf
$appExceptionSites = "exception.sites"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appName \d Update \d{3}" -RegEx)
$appInstalledVersion = (Get-InstalledApplication -Name "$appName \d Update \d{3}" -RegEx).DisplayVersion | Select-Object -First 1

#-----------------------------------------------------------[Execution]------------------------------------------------------------

{
    Set-Location -Path $appScriptPath
    If (-Not(Test-Path -Path $appVersion))
    {
        New-Folder -Path $appVersion
    }
    Set-Location -Path $appVersion

    # Uninstall previous versions
    Get-Process -Name $appProcesses | Stop-Process -Force
    If ($IsAppInstalled)
    {
        Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
        Remove-MSIApplications -Name $appName -Parameters "/QB"
    }

    # Download latest setup file(s)
    If (-Not(Test-Path -Path "$appScriptPath\$appVersion\$appSetup"))
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
    Execute-Process -Path ".\$appSetup" -Parameters $appInstallParameters -WaitForMsiExec

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

    # Remove unneeded applications from running at start-up
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run" -Name "SunJavaUpdateSched" -ContinueOnError $True

    # Associate .jnlp file extension
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Classes\.jnlp" -Name "(Default)" -Value "JNLPFile" -Type String
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Classes\.jnlp" -Name "Content Type" -Value "application/x-java-jnlp-file" -Type String
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Classes\jnlp\shell\open\Command" -Name "Content Type" -Value "`"$appDestination\jp2launcher.exe`" -securejws `"%1`"" -Type String
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Classes\JNLPFile\shell\open\Command" -Name "(Default)" -Value "`"$appDestination\javaws.exe`" `"%1`"" -Type String
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Classes\Database\Content Type\application/x-java-jnlp-file" -Name "Extension" -Value ".jnlp" -Type String
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Classes\MIME\Database\Content Type\application/x-java-jnlp-file" -Name "Extension" -Value ".jnlp" -Type String

    # Download required configuration files and copy to approprite location
    If ((-Not(Test-Path -Path "$envSystemRoot\Sun\Java\Deployment\$appDeploymentConfig")) -and (-Not(Test-Path -Path "$appScriptPath\$appDeploymentConfig")))
    {
        Write-Log -Message "Downloading $appVendor $appName configuration files.." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURLDeploymentConfig -OutFile "$appScriptPath\$appDeploymentConfig"
        Invoke-WebRequest -UseBasicParsing -Uri $appURLDeploymentProperties -OutFile "$appScriptPath\$appDeploymentProperties"
        Copy-File -Path "$appScriptPath\$appDeploymentConfig" -Destination "$envSystemRoot\Sun\Java\Deployment" -ContinueFileCopyOnError $True
        Copy-File -Path "$appScriptPath\$appDeploymentProperties" -Destination "$envSystemRoot\Sun\Java\Deployment" -ContinueFileCopyOnError $True
    }
    # Update deployment.properties if already exist
    ElseIf (Test-Path -Path "$appScriptPath\$appDeploymentProperties")
    {
        Copy-File -Path "$appScriptPath\$appDeploymentProperties" -Destination "$envSystemRoot\Sun\Java\Deployment" -ContinueFileCopyOnError $True
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Create exception.sites files if missing
    If ((-Not (Test-Path -Path "$envSystemRoot\Sun\Java\Deployment\$appExceptionSites")) -and (-Not(Test-Path -Path "$appScriptPath\$appExceptionSites")))
    {
        New-Item -Path "$appScriptPath\$appExceptionSites"
        Set-Content "$appScriptPath\$appExceptionSites" 'http://example.com'
        Copy-File -Path "$appScriptPath\$appExceptionSites" -Destination "$envSystemRoot\Sun\Java\Deployment" -ContinueFileCopyOnError $True
    }
    # Update exception.sites if already exist
    ElseIf (Test-Path -Path "$appScriptPath\$appExceptionSites")
    {
        Copy-File -Path "$appScriptPath\$appExceptionSites" -Destination "$envSystemRoot\Sun\Java\Deployment" -ContinueFileCopyOnError $True
    }

    # Copy trusted certs to system wide location
    If ((-Not (Test-Path -Path "$envSystemRoot\Sun\Java\Deployment\trusted.certs")) -and (Test-Path -Path "$appScriptPath\trusted.certs"))
    {
        Copy-File -Path "$appScriptPath\trusted.certs" -Destination "$envSystemRoot\Sun\Java\Deployment" -ContinueFileCopyOnError $True
    }
    ElseIf ((-Not (Test-Path -Path "$envSystemRoot\Sun\Java\Deployment\trusted.certs")) -and (Test-Path -Path "$($envLocalAppData)Low\Sun\Java\Deployment\security\trusted.certs"))
    {
        Copy-File -Path "$($envLocalAppData)Low\Sun\Java\Deployment\security\trusted.certs" -Destination "$envSystemRoot\Sun\Java\Deployment" -ContinueFileCopyOnError $True
    }

    # Delete user configs so system wide configs can take over
    Remove-Folder "$($envLocalAppData)Low\Sun"

    # Fix javaws.exe performance over RDP/HDX https://communities.bmc.com/thread/111844?start=0&tstart=0 https://www.rgagnon.com/javadetails/java-set-java-properties-system-wide.html
    [System.Environment]::SetEnvironmentVariable('JAVAWS_VM_ARGS', '-Dsun.java2d.noddraw=true', [System.EnvironmentVariableTarget]::Machine)

    # Disable "Java version is out of date" message https://www.wincert.net/microsoft-windows/disable-java-version-is-out-of-date-message
    [System.Environment]::SetEnvironmentVariable('deployment.expiration.check.enabled', 'false', [System.EnvironmentVariableTarget]::Machine)

    # Go back to the parent folder
    Set-Location ..

    Write-Log -Message "$appVendor $appName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
}
Else
{
    Write-Log -Message "$appVendor $appName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}