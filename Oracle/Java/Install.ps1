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
    If (-not(Get-PackageProvider -ListAvailable -Name $PackageProvider -ErrorAction SilentlyContinue))
    {
        Install-PackageProvider -Name $PackageProvider -Force
    }
}

# Add the Powershell Gallery as trusted repository
Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted

# Update PowerShellGet
$InstalledPSGetVersion = (Get-PackageProvider -Name PowerShellGet).Version
$PSGetVersion = [version](Find-PackageProvider -Name PowerShellGet).Version
If ($PSGetVersion -gt $InstalledPSGetVersion)
{
    Install-PackageProvider -Name PowerShellGet -Force
}

# Install and import custom modules list
Foreach ($Module in $Modules)
{
    If (-not(Get-Module -ListAvailable -Name $Module))
    {
        Install-Module -Name $Module -AllowClobber -Force | Import-Module -Name $Module -Force
    }
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

Function Get-ScriptDirectory
{
    If ($PSScriptRoot)
    {
        $PSScriptRoot
    } # Windows PowerShell 3.0-5.1
    ElseIf ($psISE)
    {
        Split-Path $psISE.CurrentFile.FullPath
    } # Windows PowerShell ISE Host
    ElseIf ($psEditor)
    {
        Split-Path $psEditor.GetEditorContext().CurrentFile.Path
    } # Visual Studio Code Host
}

# Variables Declaration
# Generic
$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"
$env:SEE_MASK_NOZONECHECKS = 1
$appScriptDirectory = Get-ScriptDirectory

# Application related
##*===============================================
$appVendor = "Oracle"
$appName = "Java"
$appProcesses = @("java", "javaw", "javaws", "javacpl", "jp2launcher")
$appInstallParameters = "INSTALL_SILENT=1 STATIC=0 AUTO_UPDATE=0 WEB_JAVA=1 WEB_JAVA_SECURITY_LEVEL=H WEB_ANALYTICS=0 EULA=0 REBOOT=0 REMOVEOUTOFDATEJRES=1 NOSTARTMENU=1 SPONSORS=0"
$Evergreen = Get-EvergreenApp -Name OracleJava8 | Where-Object { $_.Architecture -eq "x64" }
$appVersion = $Evergreen.Version.Replace("-b", "0.").Replace("_", ".").Substring(2)
$appMajorVersion = $appVersion.Split(".")[0]
$appMinorVersion = $appVersion.Split(".")[2].Substring(0, 3)
$appURL = $Evergreen.URI
$appSetup = Split-Path -Path $appURL -Leaf
$appDestination = "$env:ProgramFiles\$appName\jre1.$appMajorVersion.0_$appMinorVersion\bin"
$appURLDeploymentConfig = "https://raw.githubusercontent.com/JonathanPitre/Apps/master/Oracle/Java/deployment.config"
$appDeploymentConfig = Split-Path -Path $appURLDeploymentConfig -Leaf
$appURLDeploymentProperties = "https://raw.githubusercontent.com/JonathanPitre/Apps/master/Oracle/Java/deployment.properties"
$appDeploymentProperties = Split-Path -Path $appURLDeploymentProperties -Leaf
$appExceptionSites = "exception.sites"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appName \d Update \d{3}" -RegEx)
$appInstalledVersion = (Get-InstalledApplication -Name "$appName \d Update \d{3}" -RegEx).DisplayVersion | Select-Object -First 1
##*================================================

If ([version]$appVersion -gt [version]$appInstalledVersion)
{
    Set-Location -Path $appScriptDirectory
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
    If (-Not(Test-Path -Path "$appScriptDirectory\$appVersion\$appSetup"))
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
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Classes\jnlp\shell\open\Command" -Name "Content Type" -Value "`"C:\Program Files\Java\jre1.$appMajorVersion.0_$appMinorVersion\bin\jp2launcher.exe`" -securejws `"%1`"" -Type String
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Classes\JNLPFile\shell\open\Command" -Name "(Default)" -Value "`"C:\Program Files\Java\jre1.$appMajorVersion.0_$appMinorVersion\bin\javaws.exe`" `"%1`"" -Type String
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Classes\Database\Content Type\application/x-java-jnlp-file" -Name "Extension" -Value ".jnlp" -Type String
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Classes\MIME\Database\Content Type\application/x-java-jnlp-file" -Name "Extension" -Value ".jnlp" -Type String

    # Copy configs to system wide location
    Copy-File -Path $appScriptDirectory\Config\* -Destination "$envSystemRoot\Sun\Java\Deployment" -Recurse

    # Download required configuration files and copy to approprite location
    If ((-Not(Test-Path -Path "$envSystemRoot\Sun\Java\Deployment\$appDeploymentConfig")) -and (-Not(Test-Path -Path "$appScriptDirectory\$appDeploymentConfig")))
    {
        Write-Log -Message "Downloading $appVendor $appName configuration files.." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURLDeploymentConfig -OutFile "$appScriptDirectory\$appDeploymentConfig"
        Invoke-WebRequest -UseBasicParsing -Uri $appURLDeploymentProperties -OutFile "$appScriptDirectory\$appDeploymentProperties"
        Copy-File -Path "$appScriptDirectory\$appDeploymentConfig" -Destination "$envSystemRoot\Sun\Java\Deployment" -ContinueFileCopyOnError $True
        Copy-File -Path "$appScriptDirectory\$appDeploymentProperties" -Destination "$envSystemRoot\Sun\Java\Deployment" -ContinueFileCopyOnError $True
    }
    # Update deployment.properties if already exist
    ElseIf (Test-Path -Path "$appScriptDirectory\$appDeploymentProperties")
    {
        Copy-File -Path "$appScriptDirectory\$appDeploymentProperties" -Destination "$envSystemRoot\Sun\Java\Deployment" -ContinueFileCopyOnError $True
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Create exception.sites files if missing
    If ((-Not (Test-Path -Path "$envSystemRoot\Sun\Java\Deployment\$appExceptionSites")) -and (-Not(Test-Path -Path "$appScriptDirectory\$appExceptionSites")))
    {
        New-Item -Path "$appScriptDirectory\$appExceptionSites"
        Set-Content "$appScriptDirectory\$appExceptionSites" 'http://example.com'
        Copy-File -Path "$appScriptDirectory\$appExceptionSites" -Destination "$envSystemRoot\Sun\Java\Deployment" -ContinueFileCopyOnError $True
    }
    # Update exception.sites if already exist
    ElseIf (Test-Path -Path "$appScriptDirectory\$appExceptionSites")
    {
        Copy-File -Path "$appScriptDirectory\$appExceptionSites" -Destination "$envSystemRoot\Sun\Java\Deployment" -ContinueFileCopyOnError $True
    }

    # Copy trusted certs to system wide location
    If ((-Not (Test-Path -Path "$envSystemRoot\Sun\Java\Deployment\trusted.certs")) -and (Test-Path -Path "$appScriptDirectory\trusted.certs"))
    {
        Copy-File -Path "$appScriptDirectory\trusted.certs" -Destination "$envSystemRoot\Sun\Java\Deployment" -ContinueFileCopyOnError $True
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