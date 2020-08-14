# PowerShell Wrapper for MDT, Standalone and Chocolatey Installation - (C)2020 Jonathan Pitre, inspired by xenappblog.com
# Example 1 Install EXE:
# Execute-Process -Path .\appName.exe -Parameters "/silent"
# Example 2 Install MSI:
# Execute-MSI -Action Install -Path appName.msi -Parameters "/QB" -AddParameters "ALLUSERS=1"
# Example 3 Uninstall MSI:
# Remove-MSIApplications -Name "appName" -Parameters "/QB"

# Custom package providers list
$PackageProviders = @("Nuget")

# Custom modules list
$Modules = @("PSADT", "Evergreen")

Set-ExecutionPolicy -ExecutionPolicy Bypass -Force

# Checking for elevated permissions...
If (-not([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning -Message "Insufficient permissions to continue! PowerShell must be run with admin rights."
    Break
}
Else {
    Write-Verbose -Message "Importing custom modules..." -Verbose

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials

    # Install custom package providers list
    Foreach ($PackageProvider in $PackageProviders) {
        If (-not(Get-PackageProvider -ListAvailable -Name $PackageProvider -ErrorAction SilentlyContinue)) {Install-PackageProvider -Name $PackageProvider -Force}
    }

    # Add the Powershell Gallery as trusted repository
    Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted

    # Update PowerShellGet
    $InstalledPSGetVersion = (Get-PackageProvider -Name PowerShellGet).Version
    $PSGetVersion = [version](Find-PackageProvider -Name PowerShellGet).Version
    If ($PSGetVersion -gt $InstalledPSGetVersion) {Install-PackageProvider -Name PowerShellGet -Force}

    # Install and import custom modules list
    Foreach ($Module in $Modules) {
        If (-not(Get-Module -ListAvailable -Name $Module)) {Install-Module -Name $Module -AllowClobber -Force | Import-Module -Name $Module -Force}
        Else {
            $InstalledModuleVersion = (Get-InstalledModule -Name $Module).Version
            $ModuleVersion = (Find-Module -Name $Module).Version
            $ModulePath = (Get-InstalledModule -Name $Module).InstalledLocation
            $ModulePath = (Get-Item -Path $ModulePath).Parent.FullName
            If ([version]$ModuleVersion -gt [version]$InstalledModuleVersion) {
                Update-Module -Name $Module -Force
                Remove-Item -Path $ModulePath\$InstalledModuleVersion -Force -Recurse
            }
        }
    }

    Write-Verbose -Message "Custom modules were successfully imported!" -Verbose
}

Function Get-ScriptDirectory {
    If ($psISE) {Split-Path $psISE.CurrentFile.FullPath}
    Else {$Global:PSScriptRoot}
}

# Variables Declaration
# Generic
$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"
$appScriptDirectory = Get-ScriptDirectory
$env:SEE_MASK_NOZONECHECKS = 1
# Application related
##*===============================================
$appVendor = "Oracle"
$appName = "Java"
$appMajorVersion = "8"
$appProcess = @("java", "javaw", "javaws", "javacpl", "jp2launcher")
$appInstallParameters = "INSTALL_SILENT=1 STATIC=0 AUTO_UPDATE=0 WEB_JAVA=1 WEB_JAVA_SECURITY_LEVEL=H WEB_ANALYTICS=0 EULA=0 REBOOT=0 NOSTARTMENU=1 SPONSORS=0"
$Evergreen = Get-OracleJava8 | Where-Object { $_.Architecture -eq "x64" }
$appVersion = $Evergreen.Version.Replace("-b", "0.").Replace("_", ".").Substring(2)
$appMajorVersion = $appVersion.Split(".")[0]
$appMinorVersion = $appVersion.Split(".")[2].Substring(3, 3)
$appURL = $Evergreen.URI
$appSetup = $appUrl.split("/")[9]
$appSource = $appVersion
$appDestination = "$envProgramFiles\$appName\jre1.$appMajorVersion.0_$appMinorVersion\bin"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appName \d Update \d{3}" -RegEx)
$appInstalledVersion = (Get-InstalledApplication -Name "$appName \d Update \d{3}" -RegEx).DisplayVersion | Select-Object -First 1
##*================================================

If ([version]$appVersion -gt [version]$appInstalledVersion) {
    Set-Location -Path $appScriptDirectory
    If (-Not(Test-Path -Path $appSource)) {New-Folder -Path $appSource}
    Set-Location -Path $appSource

    Write-Log -Message "Downloading $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    If (-Not(Test-Path -Path $appScriptDirectory\$appSource\$appSetup)) {
        Invoke-WebRequest -UseBasicParsing -Uri $appURL -OutFile $appSetup
    }
    Else {
        Write-Log -Message "File already exists. Skipping Download" -Severity 1 -LogType CMTrace -WriteHost $True
    }

    Get-Process -Name $appProcess | Stop-Process -Force
    If ($IsAppInstalled) {
        Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
        Remove-MSIApplications -Name $appName -Parameters $appInstallParameters
    }

    Write-Log -Message "Installing $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    Execute-Process -Path ".\$appSetup" -Parameters $appInstallParameters -WaitForMsiExec

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run" -Name "SunJavaUpdateSched" -ContinueOnError $True
    # Associate .jnlp file extension
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Classes\.jnlp" -Name "(Default)" -Value "JNLPFile" -Type String
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Classes\.jnlp" -Name "Content Type" -Value "application/x-java-jnlp-file" -Type String
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Classes\jnlp\Shell\Open\Command" -Name "Content Type" -Value "`"C:\Program Files\Java\jre1.$appMajorVersion.0_$appMinorVersion\bin\jp2launcher.exe`" -securejws `"%1`"" -Type String
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Classes\JNLPFile\Shell\Open\Command" -Name "(Default)" -Value "`"C:\Program Files\Java\jre1.$appMajorVersion.0_$appMinorVersion\bin\javaws.exe`" `"%1`"" -Type String
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Classes\Database\Content Type\application/x-java-jnlp-file" -Name "Extension" -Value ".jnlp" -Type String
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Classes\MIME\Database\Content Type\application/x-java-jnlp-file" -Name "Extension" -Value ".jnlp" -Type String
    # Copy configs to system wide location
    Copy-File -Path $appScriptDirectory\Config\* -Destination "$envSystemRoot\Sun\Java\Deployment" -Recurse
    # Copy trusted cert to system wide location
    Copy-File -Path "$($envLocalAppData)Low\Sun\Java\Deployment\security\trusted.certs" -Destination "$envSystemRoot\Sun\Java\Deployment" -ContinueFileCopyOnError $True
    # Delete user configs so system wide configs can take over
    Remove-Folder "$($envLocalAppData)Low\Sun"
    # Fix javaws.exe performance over RDP/HDX https://communities.bmc.com/thread/111844?start=0&tstart=0 https://www.rgagnon.com/javadetails/java-set-java-properties-system-wide.html
    [System.Environment]::SetEnvironmentVariable('JAVAWS_VM_ARGS', '-Dsun.java2d.noddraw=true', [System.EnvironmentVariableTarget]::Machine)
    # Disable "Java version is out of date" message https://www.wincert.net/microsoft-windows/disable-java-version-is-out-of-date-message
    [System.Environment]::SetEnvironmentVariable('deployment.expiration.check.enabled', 'false', [System.EnvironmentVariableTarget]::Machine)
    Write-Log -Message "$appVendor $appName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True

}
Else {
    Write-Log -Message "$appVendor $appName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}

<#
Write-Verbose -Message "Uninstalling custom modules..." -Verbose
Foreach ($Module in $Modules) {
    If ((Get-Module -ListAvailable -Name $Module)) {Uninstall-Module -Name $Module -Force}
}
Write-Verbose -Message "Custom modules were succesfully uninstalled!" -Verbose
#>