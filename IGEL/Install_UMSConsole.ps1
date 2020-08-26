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

Function Get-ScriptDirectory {
    If ($PSScriptRoot) { $PSScriptRoot } # Windows PowerShell 3.0-5.1
    ElseIf ($psISE) { Split-Path $psISE.CurrentFile.FullPath } # Windows PowerShell ISE Host
    ElseIf ($psEditor) { Split-Path $psEditor.GetEditorContext().CurrentFile.Path } # Visual Studio Code Host
}

# Variables Declaration
# Generic
$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"
$env:SEE_MASK_NOZONECHECKS = 1
$appScriptDirectory = Get-ScriptDirectory

# Application related
##*===============================================
$appVendor = "IGEL"
$appName = "Universal Management Suite"
$appProcess = @("RMClient")
$appInstallParameters = "/LOADINF=$appScriptDirectory\ums.inf /SILENT"
$webRequest = Invoke-WebRequest -UseBasicParsing -Uri ("https://www.igel.com/software-downloads/workspace-edition") -SessionVariable websession
$regex = "https\:\/\/.+\/files\/IGEL_UNIVERSAL_MANAGEMENT_SUITE\/WINDOWS\/setup-igel-ums-windows_\d.\d{2}.\d{3}.exe"
$webResponse = $webRequest.RawContent | Select-String -Pattern $regex -AllMatches | ForEach-Object { $_.Matches.Value } | Select-Object -First 1
$appURL = $webResponse
$appSetup = $appURL.Split("/")[6]
$appVersion = $appSetup.Trim("setup-igel-ums-windows_").Trim(".exe")
$appMajorVersion = $appVersion.Substring(0, 1)
$appSource = $appVersion
$appDestination = "$envProgramFiles\IGEL\RemoteManager"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appName")
$appInstalledVersion = (Get-InstalledApplication -Name "$appName").DisplayVersion
##*===============================================

If ([version]$appVersion -gt [version]$appInstalledVersion) {
    Set-Location -Path $appScriptDirectory
    If (-Not(Test-Path -Path $appSource)) { New-Folder -Path $appSource }
    Set-Location -Path $appSource

    If (-Not(Test-Path -Path $appScriptDirectory\$appSource\$appSetup)) {
        Write-Log -Message "Downloading $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $appURL -OutFile $appSetup
    }
    Else {
        Write-Log -Message "File already exists. Skipping Download" -Severity 1 -LogType CMTrace -WriteHost $True
    }

    Get-Process -Name $appProcess | Stop-Process -Force
    If ($IsAppInstalled) {
        Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
        Execute-Process -Path "$appDestination\unins000.exe" -Parameters "/SILENT" -PassThru
    }
    Remove-Folder -Path "$envProgramFiles\IGEL" -ContinueOnError $True

    Write-Log -Message "Installing $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    #Execute-Process -Path .\$appSetup -Parameters $appInstallParameters

    Execute-Process -Path .\$appSetup -NoWait
    Start-Sleep -Seconds 2
    Send-Keys -WindowTitle "Setup - Universal Management Suite 6" -Keys {ENTER}
    Send-Keys -WindowTitle "Setup - Universal Management Suite 6" -Keys {%(a)}
    Send-Keys -WindowTitle "Setup - Universal Management Suite 6" -Keys {ENTER}
    Send-Keys -WindowTitle "Setup - Universal Management Suite 6" -Keys {%(n)}
    Send-Keys -WindowTitle "Setup - Universal Management Suite 6" -Keys {%(n)}
    Send-Keys -WindowTitle "Setup - Universal Management Suite 6" -Keys {UP}
    Send-Keys -WindowTitle "Setup - Universal Management Suite 6" -Keys {%(n)}
    Send-Keys -WindowTitle "Setup - Universal Management Suite 6" -Keys {%(n)}
    Send-Keys -WindowTitle "Setup - Universal Management Suite 6" -Keys {%(n)}
    Send-Keys -WindowTitle "Setup - Universal Management Suite 6" -Keys {%(n)}
    Send-Keys -WindowTitle "Setup - Universal Management Suite 6" -Keys {%(i)}
    Start-Sleep -Seconds 30 # Adjust if needed
    Send-Keys -WindowTitle "Setup - Universal Management Suite 6" -Keys {%(f)}

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True
    Remove-File -Path "$envCommonStartMenuPrograms\$appName $appMajorVersion\Uninstall $appName.lnk" -ContinueOnError $True
    Rename-Item -Path "$envCommonStartMenuPrograms\$appName $appMajorVersion" -NewName "$envCommonStartMenuPrograms\$appVendor" -Force
    Rename-Item -Path "$envCommonStartMenuPrograms\$appVendor\UMS Console.lnk" -NewName "$envCommonStartMenuPrograms\$appVendor\$appVendor UMS Console.lnk" -Force

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