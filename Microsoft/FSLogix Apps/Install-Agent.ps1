# PowerShell Wrapper for MDT, Standalone and Chocolatey Installation - (C)2020 Jonathan Pitre, inspired by xenappblog.com 
# Example 1 Install EXE:
# Execute-Process -Path .\appName.exe -Parameters "/silent"
# Example 2 Install MSI:
# Execute-MSI -Action Install -Path appName.msi -Parameters "/QB" -AddParameters "ALLUSERS=1"
# Example 3 Uninstall MSI:
# Remove-MSIApplications -Name "appName" -Parameters "/QB"

Clear-Host
Set-ExecutionPolicy -ExecutionPolicy Bypass -Force -Scope Process

# Custom package providers list
$PackageProviders = @("PowerShellGet","Nuget")
# Custom modules list
$Modules = @("Evergreen","InstallModuleFromGitHub")

# Checking for elevated permissions...
If (-not([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
	Write-Warning -Message "Insufficient permissions to continue! PowerShell must be run with admin rights."
	Break
}
Else {
	Write-Verbose -Message "Importing custom modules..." -Verbose

	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    [System.Net.WebRequest]::DefaultWebProxy.Credentials =  [System.Net.CredentialCache]::DefaultCredentials
	Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted

	# Install custom package providers list
	Foreach ($PackageProvider in $PackageProviders) {
		If (-not(Get-PackageProvider -Name $PackageProvider)) {Find-PackageProvider -Name $PackageProvider -ForceBootstrap -IncludeDependencies | Install-PackageProvider -Force -Confirm:$False}
    }

	# Install and import custom modules list
	Foreach ($Module in $Modules) {
		If (-not(Get-Module -ListAvailable -Name $Module)) {Install-Module -Name $Module -Force | Import-Module -Name $Module}
        ElseIf (Get-Module -ListAvailable -Name $Module) {Update-Module -Name $Module -Force}
    }

    # Install custom PSAppDeployToolkit module from a GitHub repo
	$GitHubUser = "JonathanPitre"
	$GitHubRepo = "PSAppDeployToolkit"
	If (-not(Test-Path -Path $env:ProgramFiles\WindowsPowerShell\Modules\$GitHubRepo)) {Install-ModuleFromGitHub -GitHubRepo $GitHubUser/$GitHubRepo | Import-Module -Name $GitHubRepo}
	Else {Import-Module -Name $env:ProgramFiles\WindowsPowerShell\Modules\$GitHubRepo}
    
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
$appVendor = "Microsoft"
$appName = "FSLogix Apps"
$appSetup = "FSLogixAppsSetup.exe"
$appProcess = @("frxsvc", "frxtray", "frxshell", "frxccds")
$appInstallParameters = "/install /quiet /norestart"
$Evergreen = Get-MicrosoftFSLogixApps
$appVersion = $Evergreen.Version
$appURL = $Evergreen.uri
$appZip = "FSLogix Apps.zip" 
$appSource = "$appVersion\x64\Release"
$appDesination = "$envProgramFiles\FSLogix\Apps"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName" -Exact)
$appInstalledVersion = (Get-InstalledApplication -Name "$appVendor $appName" -Exact).DisplayVersion | Select-Object -First 1
##*===============================================

If ([version]$appVersion -gt [version]$appInstalledVersion) {
    Set-Location -Path $appScriptDirectory
    If (-Not(Test-Path -Path $appSource)) {New-Folder -Path $appSource}
    Set-Location -Path $appSource

    Write-Log -Message "Downloading $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    If (-Not(Test-Path -Path $appScriptDirectory\$appSource\$appSetup)) {
        Invoke-WebRequest -UseBasicParsing -Uri $appURL -OutFile $appZip
        Expand-Archive -Path $appZip -DestinationPath $appScriptDirectory\$appSource
        Remove-File -Path $appZip
    }
    Else {
        Write-Log -Message "File already exists. Skipping Download" -Severity 1 -LogType CMTrace -WriteHost $True
    }

    Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
    Get-Process -Name $appProcess | Stop-Process -Force

    Write-Log -Message "Installing $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    Execute-Process -Path .\$appSetup -Parameters $appInstallParameters
    
	Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True
    Register-ScheduledTask -Xml (Get-Content $appScriptDirectory\WSearch.xml | Out-String) -TaskName "Reset Windows Search at Logoff" -Force
    New-Folder -Path "$envCommonStartMenuPrograms\Troubleshooting Tools" -ContinueOnError $True
    New-Shortcut -Path "$envCommonStartMenuPrograms\Troubleshooting Tools\FSLogix Tray Icon.lnk" -TargetPath "$appDestination\frxtray.exe" -IconLocation "$appDestination\frxtray.exe" -Description "FSLogix Tray Icon" -WorkingDirectory "$appDestination"
    #Write-Log -Message "Adjusting altitude settings for FSLogix to play nice to CVAD UPL filter driver" -Severity 1 -LogType $LogType -WriteHost $True
    #If ((Get-ItemProperty HKLM:\System\CurrentControlSet\Services\frxdrvvt\Instances\frxdrvvt -name Altitude) -ne 138010) {
    #Set-RegistryKey -Key "HKLM:\System\CurrentControlSet\Services\frxdrvvt\Instances\frxdrvvt" -Name "Altitude" -Value "138010" -Type "String"
    #}

    Write-Log -Message "$appVendor $appName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
    
}
Else {
    Write-Log -Message "$appVendor $appName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}

#Write-Verbose -Message "Uninstalling custom modules..." -Verbose
#Foreach ($Module in $Modules) {
#    If ((Get-InstalledModule -Name $Module)) {Uninstall-Module -Name $Module -Force}
#    Write-Verbose -Message "Custom modules were uninstalled!" -Verbose
#}
