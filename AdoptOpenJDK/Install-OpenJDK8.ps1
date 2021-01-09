# PowerShell Wrapper for MDT, Standalone and Chocolatey Installation - (C)2020 Jonathan Pitre, inspired by xenappblog.com
# Example 1 Install EXE:
# Execute-Process -Path .\appName.exe -Parameters "/silent"
# Example 2 Install MSI:
# Execute-MSI -Action Install -Path appName.msi -Parameters "/QB" -AddParameters "ALLUSERS=1"
# Example 3 Uninstall MSI:
# Remove-MSIApplications -Name "appName" -Parameters "/QB"

#Requires -Version 5.1

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
        If (-not(Get-PackageProvider -ListAvailable -Name $PackageProvider -ErrorAction SilentlyContinue)) { Install-PackageProvider -Name $PackageProvider -Force }
    }

    # Add the Powershell Gallery as trusted repository
    Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted

    # Update PowerShellGet
    $InstalledPSGetVersion = (Get-PackageProvider -Name PowerShellGet).Version
    $PSGetVersion = [version](Find-PackageProvider -Name PowerShellGet).Version
    If ($PSGetVersion -gt $InstalledPSGetVersion) { Install-PackageProvider -Name PowerShellGet -Force }

    # Install and import custom modules list
    Foreach ($Module in $Modules) {
        If (-not(Get-Module -ListAvailable -Name $Module)) { Install-Module -Name $Module -AllowClobber -Force | Import-Module -Name $Module -Force }
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

# Get the current script directory
Function Get-ScriptDirectory {
    Remove-Variable appScriptDirectory
    Try {
        If ($psEditor) { Split-Path $psEditor.GetEditorContext().CurrentFile.Path } # Visual Studio Code Host
        ElseIf ($psISE) { Split-Path $psISE.CurrentFile.FullPath } # Windows PowerShell ISE Host
        ElseIf ($PSScriptRoot) { $PSScriptRoot } # Windows PowerShell 3.0-5.1
        Else {
            Write-Host -ForegroundColor Red "Cannot resolve script file's path"
            Exit 1
        }
    }
    Catch {
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
$appVendor = "AdoptOpenJDK"
$appName = "JRE"
$appMajorVersion = "8"
$appProcesses = @("java", "javaw", "javaws")
$appInstallParameters = "/QB"
$appAddParameters = "ADDLOCAL=FeatureMain,FeatureEnvironment,FeatureJarFileRunWith,FeatureJavaHome,FeatureIcedTeaWeb,FeatureJNLPFileRunWith"
$webResponse = Invoke-WebRequest -UseBasicParsing -Uri ("https://github.com/AdoptOpenJDK/openjdk$appMajorVersion-binaries/releases") -SessionVariable websession
$regex = "\/AdoptOpenJDK\/openjdk$appMajorVersion-binaries\/releases\/download\/jdk\du\d{3}-b\d+.+\/OpenJDK$($appMajorVersion)U-jre_x64_windows_hotspot_$($appMajorVersion)u\d{3}b\d+\.msi"
$appURL = "https://github.com" + ($webResponse.RawContent | Select-String -Pattern $regex -AllMatches | ForEach-Object { $_.Matches.Value } | Select-Object -First 1)
$appSetup = $appURL.Split("/")[8]
[string]$webVersion = [regex]::matches($appSetup, "\du\d{3}b\d+")
$appVersion = $webVersion.Replace("u", ".0.").Replace("b", ".")
$appMinorVersion = $appVersion.Split(".")[2].Substring(0, 3)
$appDestination = "$env:ProgramFiles\$appVendor\jre-$appMajorVersion.0.$appMinorVersion.1-hotspot\bin"
$appSource = $appVersion
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName")
$appInstalledVersion = (Get-InstalledApplication -Name "$appVendor $appName").DisplayVersion
##*================================================

If ([version]$appVersion -gt [version]$appInstalledVersion) {
    Set-Location -Path $appScriptDirectory
    If (-Not(Test-Path -Path $appSource)) {New-Folder -Path $appSource}
    Set-Location -Path $appSource

    # Uninstall previous versions
    Get-Process -Name $appProcesses | Stop-Process -Force
    # Uninstall java
    Remove-MSIApplications -Name "Java"
    If ($IsAppInstalled) {
        Remove-MSIApplications -Name "$appVendor $appName"
    }

    # Download latest setup file(s)
    If (-Not(Test-Path -Path $appScriptDirectory\$appSource\$appSetup)) {
        Write-Log -Message "Downloading $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURL -OutFile $appSetup
    }
    Else {
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