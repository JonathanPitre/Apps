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

function Get-CitrixDownload
{
    <#
.SYNOPSIS
  Downloads a Citrix binary or ISO from Citrix.com utilizing authentication
.DESCRIPTION
  Downloads a Citrix binary or ISO from Citrix.com utilizing authentication
  Ryan Butler & Jonathan Pitre 6/10/2022
.PARAMETER CitrixProductName
  Get Citrix Product Name from https://raw.githubusercontent.com/ryancbutler/Citrix_DL_Scrapper/main/ctx_dls.json. Default to "Multi-session OS Virtual Delivery Agent"
.PARAMETER CitrixUserName
  Citrix.com username
.PARAMETER CitrixPassword
  Citrix.com password
.PARAMETER EvergreenMode
  Get latest version and download url of given Citrix Product Name. When set to $False, the download will be initiated. Default value is set to $True.
.PARAMETER DownloadPath
  Path to store downloaded file. Default path is "$env:Temp\Citrix"
.PARAMETER VerboseMode
  Enable verbose logging
.EXAMPLE
  Get-CitrixDownload -CitrixDownload $CitrixDownload -CitrixUserName "MyCitrixUsername" -CitrixPassword "MyCitrixPassword" -DownloadPath "C:\Temp\"
#>

    [cmdletbinding()]
    Param (
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateSet('Citrix Virtual Apps and Desktops', 'Multi-session OS Virtual Delivery Agent', 'Single-session OS Virtual Delivery Agent', 'Single-session OS Core Services Virtual Delivery Agent', 'License Server', 'Profile Management', 'StoreFront', 'Session Recording', 'Citrix Provisioning', 'Citrix ADC Upgrade Package')]
        [ValidateNotNullOrEmpty()]
        $CitrixProductName = "Multi-session OS Virtual Delivery Agent",
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$CitrixUsername,
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$CitrixPassword,
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [boolean]$EvergreenMode = $True,
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string]$DownloadPath = "$env:Temp\Citrix",
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [boolean]$VerboseMode = $False
    )

    Process
    {

        # Speed up downloads
        $ProgressPreference = 'SilentlyContinue'

        # Convert password to SecureString
        [securestring]$SecurePassword = ConvertTo-SecureString $CitrixPassword -AsPlainText -Force

        # Initialize Session
        Invoke-WebRequest -Uri "https://identity.citrix.com/Utility/STS/Sign-In?ReturnUrl=%2fUtility%2fSTS%2fsaml20%2fpost-binding-response" -SessionVariable websession -UseBasicParsing | Out-Null

        # Set Form
        $Form = @{
            "persistent" = "on"
            "userName"   = $CitrixUsername
            "password"   = $CitrixPassword
        }

        # Authenticate
        Try
        {
            Invoke-WebRequest -Uri ("https://identity.citrix.com/Utility/STS/Sign-In?ReturnUrl=%2fUtility%2fSTS%2fsaml20%2fpost-binding-response") -WebSession $WebSession -Method POST -Body $Form -ContentType "application/x-www-form-urlencoded" -UseBasicParsing -ErrorAction Stop | Out-Null
        }
        Catch
        {
            If ($_.Exception.Response.StatusCode.Value__ -eq 500)
            {
                Write-Verbose -Message "500 returned on auth. Ignoring"
                Write-Verbose -Message $_.Exception.Response
                Write-Verbose -Message $_.Exception.Message
            }
            Else
            {
                Throw $_
            }

        }

        if ($VerboseMode) { Write-Verbose -Message "Product Name: $CitrixProductName" -Verbose }

        # Get Citrix Product Family from Citrix Product Name
        switch ( $CitrixProductName )
        {
            { ($_ -eq "Citrix Virtual Apps and Desktops") -or ($_ -eq "Multi-session OS Virtual Delivery Agent") } { [string]$CitrixProductFamily = "cvad" }
            'Citrix Virtual Apps and Desktops' { [string]$CitrixProductFamily = "cvad" }
            'Multi-session OS Virtual Delivery Agent' { [string]$CitrixProductFamily = "cvad" }
            'Single-session OS Virtual Delivery Agent' { [string]$CitrixProductFamily = "cvad" }
            'Single-session OS Core Services Virtual Delivery Agent*' { [string]$CitrixProductFamily = "cvad" }
            'License Server' { [string]$CitrixProductFamily = "cvad" }
            'Profile Management' { [string]$CitrixProductFamily = "cvad" }
            'StoreFront' { [string]$CitrixProductFamily = "cvad" }
            'Session Recording' { [string]$CitrixProductFamily = "cvad" }
            'Citrix WEM' { [string]$CitrixProductFamily = "wem" }
            'Citrix Provisioning' { [string]$CitrixProductFamily = "pvs" }
            'Citrix ADC Upgrade Package' { [string]$CitrixProductFamily = "adc" }
            default { Throw "No such Citrix Product Family was found for $CitrixProductName" }
        }

        if ($VerboseMode) { Write-Verbose -Message "Product Family: $CitrixProductFamily" -Verbose }

        # Get Citrix downloads list
        $CitrixDownloadsList = Invoke-RestMethod -Uri "https://raw.githubusercontent.com/ryancbutler/Citrix_DL_Scrapper/main/ctx_dls.json"

        # Get latest Citrix Product Name
        [pscustomobject]$CitrixDownload = $CitrixDownloadsList | Where-Object { $_.product -like "*$CitrixProductName*" -and $_.version -notlike "7*" -and $_.family -eq $CitrixProductFamily } | `
            Sort-Object -Property @{ Expression = { $_.version }; Descending = $true } | Select-Object -First 1

        # Get Citrix Product Download Number
        [string]$CitrixDownloadNumber = $CitrixDownload.dlnumber
        if ($VerboseMode) { Write-Verbose -Message "Download number: $CitrixDownloadNumber" -Verbose }

        # Get Citrix Product Filename
        [string]$CitrixFilename = $CitrixDownload.filename
        if ($VerboseMode) { Write-Verbose -Message "Filename: $CitrixFilename" -Verbose }

        # Get Citrix Product Version
        [string]$CitrixVersion = $CitrixDownload.version
        if ($VerboseMode) { Write-Verbose -Message "Version: $CitrixVersion" -Verbose }

        # Get Citrix Download URL
        $CitrixDownloadURL = "https://secureportal.citrix.com/Licensing/Downloads/UnrestrictedDL.aspx?DLID=${CitrixDownloadNumber}&URL=https://downloads.citrix.com/${CitrixDownloadNumber}/${CitrixFilename}"
        if ($VerboseMode) { Write-Verbose -Message "Download URL: $CitrixDownloadURL" -Verbose }

        # Get Download web form
        $Download = Invoke-WebRequest -Uri $CitrixDownloadURL -WebSession $WebSession -UseBasicParsing -Method GET
        $WebForm = @{
            "chkAccept"            = "on"
            "clbAccept"            = "Accept"
            "__VIEWSTATEGENERATOR" = ($Download.InputFields | Where-Object { $_.id -eq "__VIEWSTATEGENERATOR" }).value
            "__VIEWSTATE"          = ($Download.InputFields | Where-Object { $_.id -eq "__VIEWSTATE" }).value
            "__EVENTVALIDATION"    = ($Download.InputFields | Where-Object { $_.id -eq "__EVENTVALIDATION" }).value
        }

        # Check if EvergreenMode is enabled
        if ($EvergreenMode)
        {
            # Return Citrixproduct Version and Download URL
            if ($CitrixVersion -and $CitrixDownloadURL)
            {
                [PSCustomObject]@{
                    Version = $CitrixVersion
                    URI     = $CitrixDownloadURL
                }
            }
        }
        else
        {
            # Create download path
            If (-Not(Test-Path $DownloadPath)) { New-Item -ItemType Directory -Path $DownloadPath }
            $CitrixFile = ($DownloadPath + "\" + $CitrixFilename)
            if ($VerboseMode) { Write-Verbose -Message "Download path: $CitrixFile" -Verbose }

            # Download Citrix Product
            if ($VerboseMode) { Write-Verbose -Message "Downloading Citrix $CitrixProductName $CitrixVersion..." -Verbose }
            Invoke-WebRequest -Uri $CitrixDownloadURL -WebSession $WebSession -Method POST -Body $WebForm -ContentType "application/x-www-form-urlencoded" -UseBasicParsing -OutFile $CitrixFile

            # Get Citrix File hash
            $FileHash = (Get-FileHash -Path $CitrixFile -Algorithm SHA256).Hash

            # Checksum check
            $Hash = $CitrixDownload.checksum.Split(" ")[-1].ToUpper()
            If ($FileHash -ne $Hash)
            {
                Throw "Checksum failed! for $CitrixFile. Got $FileHash, expected $Hash)"
            }
            Else
            {
                if ($VerboseMode) { Write-Verbose -Message "Checksum passed!" -Verbose }
            }

            return $CitrixFile
        }
    } # End process
} # End of function

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$appVendor = "Citrix"
$appName = "Virtual Apps and Desktops"
$appName2 = "Virtual Delivery Agent"
$appProcesses = @("BrokerAgent", "picaSessionAgent")
$appServices = @("CitrixTelemetryService")
# https://docs.citrix.com/en-us/citrix-virtual-apps-desktops-service/install-configure/install-command.html
# https://docs.citrix.com/en-us/citrix-virtual-apps-desktops/install-configure/install-vdas-sccm.html
$appInstallParameters = '/components vda /disableexperiencemetrics /enable_hdx_ports /enable_hdx_udp_ports /enable_real_time_transport /enable_remote_assistance /enable_ss_ports /exclude "Citrix Personalization for App-V - VDA","Citrix Supportability Tools","Citrix WEM Agent","Citrix VDA Upgrade Agent" /includeadditional "Machine Identity Service","Citrix Profile Management","Citrix Profile Management WMI Plug-in","Citrix MCS IODriver","Citrix Rendezvous V2" /mastermcsimage /noreboot /noresume /quiet /remove_appdisk_ack /remove_pvd_ack'

#
$CitrixProductName = "Multi-session OS Virtual Delivery Agent"
Write-Log -Message "Citrix credentials for downloading the $appVendor $appName2" -Severity 1 -LogType CMTrace -WriteHost $True
$CitrixUserName = Read-Host -Prompt "Please supply your Citrix.com username"
$CitrixPassword1 = Read-Host -Prompt "Please supply your Citrix.com password" -AsSecureString
$CitrixPassword2 = Read-Host -Prompt "Please supply your Citrix.com password once more" -AsSecureString
$CitrixPassword1Temp = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($CitrixPassword1))
$CitrixPassword2Temp = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($CitrixPassword2))

If ($CitrixPassword1Temp -ne $CitrixPassword2Temp)
{
    Write-Log -Message "The supplied Citrix passwords missmatch!" -Severity 3 -LogType CMTrace -WriteHost $True
    Exit-Script -ExitCode 1
}

Remove-Variable -Name CitrixPassword1Temp, CitrixPassword2Temp
$CitrixCredentials = New-Object System.Management.Automation.PSCredential ($CitrixUserName, $CitrixPassword1)

# Verify Citrix credentials
$CitrixUserName = $CitrixCredentials.UserName
$CitrixPassword = $CitrixCredentials.GetNetworkCredential().Password
#

$Evergreen = Get-CitrixDownload -CitrixProductName $CitrixProductName -CitrixUsername $CitrixUsername -CitrixPassword $CitrixPassword -VerboseMode $True
$appVersion = $Evergreen.Version
$appURL = $Evergreen.URI
$appSetup = Split-Path -Path $appURL -Leaf
$appDestination = "$env:ProgramFiles\$appVendor\Virtual Delivery Agent"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor .*$appName2.*" -RegEx)
$appInstalledVersion = (((Get-InstalledApplication -Name "$appVendor .*$appName2.*" -RegEx).DisplayVersion)).Substring(0, 4)

#-----------------------------------------------------------[Execution]------------------------------------------------------------

If ($appVersion -gt $appInstalledVersion)
{
    Set-Location -Path $appScriptDirectory
    If (-Not(Test-Path -Path $appVersion)) {New-Folder -Path $appVersion}
    Set-Location -Path $appVersion

    # Installing Microsoft Windows prerequisites
    If ($envOSName -like "*Windows Server 2008*" -or $envOSName -like "*Windows Server 2012*")
    {
        # Install Windows Server Desktop Experience
        Write-Log -Message "Installing Windows Server Desktop Experience..." -Severity 1 -LogType CMTrace -WriteHost $True
        If (-Not(Get-WindowsFeature -Name Desktop-Experience))
        {
            Install-WindowsFeature -Name Desktop-Experience
        }
        Else
        {
            Write-Log -Message "Windows Server Desktop Experience is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
        }
    }
    ElseIf ($envOSName -like "*Windows Server*")
    {
        # Install Microsoft .NET Framework
        Write-Log -Message "Installing Microsoft .NET Framework 4.7..." -Severity 1 -LogType CMTrace -WriteHost $True
        If (-Not(Get-WindowsFeature -Name NET-Framework-45-Features))
        {
            Install-WindowsFeature -Name NET-Framework-45-Features
        }
        Else
        {
            Write-Log -Message "Microsoft .NET Framework 4.7 is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
        }

        # Install Microsoft Remote Assistance
        Write-Log -Message "Installing Microsoft Remote Assistance..." -Severity 1 -LogType CMTrace -WriteHost $True
        If (-Not(Get-WindowsFeature -Name RDS-RD-Server))
        {
            Install-WindowsFeature -Name Remote-Assistance
        }
        Else
        {
            Write-Log -Message "Microsoft Remote Assistance is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
        }

        # Install Windows Server Media Foundation
        Write-Log -Message "Installing Windows Search Service..." -Severity 1 -LogType CMTrace -WriteHost $True
        If (-Not(Get-WindowsFeature -Name Server-Media-Foundation))
        {
            Install-WindowsFeature -Name Server-Media-Foundation
        }
        Else
        {
            Write-Log -Message "Windows Search Service is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
        }

        # Install Microsoft Remote Desktop Session Host
        Write-Log -Message "Installing Microsoft Remote Desktop Session Host..." -Severity 1 -LogType CMTrace -WriteHost $True
        If (-Not(Get-WindowsFeature -Name RDS-RD-Server))
        {
            Install-WindowsFeature -Name RDS-RD-Server -IncludeManagementTools
        }
        Else
        {
            Write-Log -Message "Microsoft Remote Desktop Session Host is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
        }
    }

    # Fix VDA install error - https://www.thewindowsclub.com/computer-missing-media-features-icloud-windows-error
    If (Test-Path -Path "$envProgramFiles\Windows Media Player\wmplayer.exe")
    {
        $WindowsMediaPlayerVersion = (Get-FileVersion -File "$envProgramFiles\Windows Media Player\setup_wm.exe" -ProductVersion)
        If ((Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\WindowsFeatures\WindowsMediaVersion") -and (Get-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\WindowsFeatures\WindowsMediaVersion" -Value "(Default)") -eq "")
        {
            Write-Log -Message "Windows Media Player version is empty" -Severity 1 -LogType CMTrace -WriteHost $True
            Set-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\WindowsFeatures\WindowsMediaVersion" -Name "(Default)" -Value $WindowsMediaPlayerVersion -Type "DWord"
        }
    }

    If (-Not(Test-Path -Path $appScriptDirectory\$appVersion\$appSetup))
    {
        # Download latest version
        Write-Log -Message "Downloading $appVendor $appName2 $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
        Get-CitrixDownload -CitrixProductName $CitrixProductName -CitrixUserName $CitrixUserName -CitrixPassword $CitrixPassword -EvergreenMode $False -DownloadPath "$appScriptDirectory\$appVersion" -VerboseMode $False
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Copy $appSetup to $envTemp\Install to avoid install issue
    Copy-File -Path ".\$appSetup" -Destination "$envTemp\Install" -Recurse
    Set-Location -Path "$envTemp\Install"

    # Uninstall previous versions
    Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
    Get-Process -Name $appProcesses | Stop-Process -Force

    # Install latest version
    Write-Log -Message "Installing $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    Execute-Process -Path .\$appSetup -Parameters $appInstallParameters -WaitForMsiExec -IgnoreExitCodes "3"

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

    # Stop and disable unneeded services
    Stop-ServiceAndDependencies -Name $appServices[0] -SkipServiceExistsTest
    Set-ServiceStartMode -Name $appServices[0] -StartMode "Disabled" -ContinueOnError $True

    # Add Windows Defender exclusion(s) - https://docs.citrix.com/en-us/tech-zone/build/tech-papers/antivirus-best-practices.html
    Add-MpPreference -ExclusionProcess "%ProgramFiles%\Citrix\User Profile Manager\UserProfileManager.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles%\Citrix\Virtual Desktop Agent\BrokerAgent.exe" -Force
    Add-MpPreference -ExclusionProcess "%SystemRoot%\System32\spoolsv.exe" -Force
    Add-MpPreference -ExclusionProcess "%SystemRoot%\System32\winlogon.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Citrix\HDX\bin\WebSocketService.exe" -Force
    Add-MpPreference -ExclusionPath "%SystemRoot%\System32\drivers\CtxUvi.sys" -Force

    # Registry optimizations
    # Enable EDT MTU Discovery on the VDA - https://docs.citrix.com/en-us/citrix-virtual-apps-desktops/technical-overview/hdx/adaptive-transport.html
    # Now enabled by default
    #Set-RegistryKey -Key "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\icawd" -Name "MtuDiscovery" -Type "DWord" -Value "1"

    # Enable Rendezvous - https://docs.citrix.com/en-us/citrix-daas/hdx/rendezvous-protocol/rendezvous-v2.html
    If ((Get-RegistryKey -Key "HKLM:\SOFTWARE\Citrix\XenDesktopSetup" -Value "Rendezvous V2 Component") -eq "1")
    {
        Set-RegistryKey -Key "HKLM:\SOFTWARE\Citrix\VirtualDesktopAgent" -Name "GctRegistration" -Type "DWord" -Value "1"
    }

    # Go back to the parent folder
    Set-Location ..
    Remove-Folder -Path "$envTemp\Install"

    Write-Log -Message "$appVendor $appName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True

    Write-Log -Message "$appVendor $appName2" -Text "A reboot required after $appVendor $appName2 $appVersion installation. The computer $envComputerName will reboot in 30 seconds!" -Severity 2 -LogType CMTrace -WriteHost $True
    Show-InstallationRestartPrompt -Countdownseconds 30 -CountdownNoHideSeconds 30
}
Else
{
    Write-Log -Message "$appVendor $appName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}