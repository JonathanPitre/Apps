# Standalone application install script for VDI environment - (C)2021 Jonathan Pitre & Owen Reynolds, inspired by xenappblog.com

#Requires -Version 5.1
#Requires -RunAsAdministrator

# Custom package providers list
$PackageProviders = @("Nuget")

# Custom modules list
$Modules = @("PSADT", "Nevergreen")

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

# Get the current script directory
Function Get-ScriptDirectory
{
    Remove-Variable appScriptDirectory
    Try
    {
        If ($psEditor)
        {
            Split-Path $psEditor.GetEditorContext().CurrentFile.Path
        } # Visual Studio Code Host
        ElseIf ($psISE)
        {
            Split-Path $psISE.CurrentFile.FullPath
        } # Windows PowerShell ISE Host
        ElseIf ($PSScriptRoot)
        {
            $PSScriptRoot
        } # Windows PowerShell 3.0-5.1
        Else
        {
            Write-Host -ForegroundColor Red "Cannot resolve script file's path"
            Exit 1
        }
    }
    Catch
    {
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

Function Get-MicrosoftTeams
{
    <#
    .NOTES
        Author: Jonathan Pitre
        Twitter: @PitreJonathan
    #>
    [OutputType([System.Management.Automation.PSObject])]
    [CmdletBinding()]
    Param()
    $appURLVersion = "https://github.com/ItzLevvie/MicrosoftTeams-msinternal/blob/master/defconfig"
    Try
    {
        $webRequest = Invoke-WebRequest -Uri $appURLVersion -UseBasicParsing
    }
    Catch
    {
        Throw "Failed to connect to URL: $appURLVersion with error $_."
        Break
    }
    Finally
    {
        # Continuous deployment/Development ring
        $regexDev64EXE = 'continuous deployment(.*?|\n)*?((?:\d+\.)+(?:\d+)).+win-x64.+(https.+(?:\d+\.)+(?:\d+).+.exe)'
        $versionDev64EXE = ($webRequest.Content | Select-String -Pattern $regexDev64EXE).Matches.Groups[2].Value
        $urlDev64EXE = ($webRequest.Content | Select-String -Pattern $regexDev64EXE).Matches.Groups[3].Value

        $regexDev64MSI = 'continuous deployment(.*?|\n)*?((?:\d+\.)+(?:\d+)).+win-x64.+(https.+(?:\d+\.)+(?:\d+).+.msi)'
        $versionDev64MSI = ($webRequest.Content | Select-String -Pattern $regexDev64MSI).Matches.Groups[2].Value
        $urlDev64MSI = ($webRequest.Content | Select-String -Pattern $regexDev64MSI).Matches.Groups[3].Value

        $regexDev32EXE = 'continuous deployment(.*?|\n)*?((?:\d+\.)+(?:\d+)).+win-x86.+(https.+(?:\d+\.)+(?:\d+).+.exe)'
        $versionDev32EXE = ($webRequest.Content | Select-String -Pattern $regexDev32EXE).Matches.Groups[2].Value
        $urlDev32EXE = ($webRequest.Content | Select-String -Pattern $regexDev32EXE).Matches.Groups[3].Value

        $regexDev32MSI = 'continuous deployment(.*?|\n)*?((?:\d+\.)+(?:\d+)).+win-x86.+(https.+(?:\d+\.)+(?:\d+).+.msi)'
        $versionDev32MSI = ($webRequest.Content | Select-String -Pattern $regexDev32MSI).Matches.Groups[2].Value
        $urlDev32MSI = ($webRequest.Content | Select-String -Pattern $regexDev32MSI).Matches.Groups[3].Value

        $regexDevArm64EXE = 'continuous deployment(.*?|\n)*?((?:\d+\.)+(?:\d+)).+win-arm64.+(https.+(?:\d+\.)+(?:\d+).+.exe)'
        $versionDevArm64EXE = ($webRequest.Content | Select-String -Pattern $regexDevArm64EXE).Matches.Groups[2].Value
        $urlDevArm64EXE = ($webRequest.Content | Select-String -Pattern $regexDevArm64EXE).Matches.Groups[3].Value

        $regexDevArm64MSI = 'continuous deployment(.*?|\n)*?((?:\d+\.)+(?:\d+)).+win-arm64.+(https.+(?:\d+\.)+(?:\d+).+.msi)'
        $versionDevArm64MSI = ($webRequest.Content | Select-String -Pattern $regexDevArm64MSI).Matches.Groups[2].Value
        $urlDevArm64MSI = ($webRequest.Content | Select-String -Pattern $regexDevArm64MSI).Matches.Groups[3].Value

        # Exploration/Beta ring
        $regexBeta64EXE = 'exploration(.*?|\n)*?((?:\d+\.)+(?:\d+)).+win-x64.+(https.+(?:\d+\.)+(?:\d+).+.exe)'
        $versionBeta64EXE = ($webRequest.Content | Select-String -Pattern $regexBeta64EXE).Matches.Groups[2].Value
        $urlBeta64EXE = ($webRequest.Content | Select-String -Pattern $regexBeta64EXE).Matches.Groups[3].Value

        $regexBeta64MSI = 'exploration(.*?|\n)*?((?:\d+\.)+(?:\d+)).+win-x64.+(https.+(?:\d+\.)+(?:\d+).+.msi)'
        $versionBeta64MSI = ($webRequest.Content | Select-String -Pattern $regexBeta64MSI).Matches.Groups[2].Value
        $urlBeta64MSI = ($webRequest.Content | Select-String -Pattern $regexBeta64MSI).Matches.Groups[3].Value

        $regexBeta32EXE = 'exploration(.*?|\n)*?((?:\d+\.)+(?:\d+)).+win-x86.+(https.+(?:\d+\.)+(?:\d+).+.exe)'
        $versionBeta32EXE = ($webRequest.Content | Select-String -Pattern $regexBeta32EXE).Matches.Groups[2].Value
        $urlBeta32EXE = ($webRequest.Content | Select-String -Pattern $regexBeta32EXE).Matches.Groups[3].Value

        $regexBeta32MSI = 'exploration(.*?|\n)*?((?:\d+\.)+(?:\d+)).+win-x86.+(https.+(?:\d+\.)+(?:\d+).+.msi)'
        $versionBeta32MSI = ($webRequest.Content | Select-String -Pattern $regexBeta32MSI).Matches.Groups[2].Value
        $urlBeta32MSI = ($webRequest.Content | Select-String -Pattern $regexBeta32MSI).Matches.Groups[3].Value

        $regexBetaArm64EXE = 'exploration(.*?|\n)*?((?:\d+\.)+(?:\d+)).+win-arm64.+(https.+(?:\d+\.)+(?:\d+).+.exe)'
        $versionBetaArm64EXE = ($webRequest.Content | Select-String -Pattern $regexBetaArm64EXE).Matches.Groups[2].Value
        $urlBetaArm64EXE = ($webRequest.Content | Select-String -Pattern $regexBetaArm64EXE).Matches.Groups[3].Value

        $regexBetaArm64MSI = 'exploration(.*?|\n)*?((?:\d+\.)+(?:\d+)).+win-arm64.+(https.+(?:\d+\.)+(?:\d+).+.msi)'
        $versionBetaArm64MSI = ($webRequest.Content | Select-String -Pattern $regexBetaArm64MSI).Matches.Groups[2].Value
        $urlBetaArm64MSI = ($webRequest.Content | Select-String -Pattern $regexBetaArm64MSI).Matches.Groups[3].Value

        # Preview ring
        $regexPreview64EXE = 'preview(.*?|\n)*?((?:\d+\.)+(?:\d+)).+win-x64.+(https.+(?:\d+\.)+(?:\d+).+.exe)'
        $versionPreview64EXE = ($webRequest.Content | Select-String -Pattern $regexPreview64EXE).Matches.Groups[2].Value
        $urlPreview64EXE = ($webRequest.Content | Select-String -Pattern $regexPreview64EXE).Matches.Groups[3].Value

        $regexPreview64MSI = 'preview(.*?|\n)*?((?:\d+\.)+(?:\d+)).+win-x64.+(https.+(?:\d+\.)+(?:\d+).+.msi)'
        $versionPreview64MSI = ($webRequest.Content | Select-String -Pattern $regexPreview64MSI).Matches.Groups[2].Value
        $urlPreview64MSI = ($webRequest.Content | Select-String -Pattern $regexPreview64MSI).Matches.Groups[3].Value

        $regexPreview32EXE = 'preview(.*?|\n)*?((?:\d+\.)+(?:\d+)).+win-x86.+(https.+(?:\d+\.)+(?:\d+).+.exe)'
        $versionPreview32EXE = ($webRequest.Content | Select-String -Pattern $regexPreview32EXE).Matches.Groups[2].Value
        $urlPreview32EXE = ($webRequest.Content | Select-String -Pattern $regexPreview32EXE).Matches.Groups[3].Value

        $regexPreview32MSI = 'preview(.*?|\n)*?((?:\d+\.)+(?:\d+)).+win-x86.+(https.+(?:\d+\.)+(?:\d+).+.msi)'
        $versionPreview32MSI = ($webRequest.Content | Select-String -Pattern $regexPreview32MSI).Matches.Groups[2].Value
        $urlPreview32MSI = ($webRequest.Content | Select-String -Pattern $regexPreview32MSI).Matches.Groups[3].Value

        $regexPreviewArm64EXE = 'preview(.*?|\n)*?((?:\d+\.)+(?:\d+)).+win-arm64.+(https.+(?:\d+\.)+(?:\d+).+.exe)'
        $versionPreviewArm64EXE = ($webRequest.Content | Select-String -Pattern $regexPreviewArm64EXE).Matches.Groups[2].Value
        $urlPreviewArm64EXE = ($webRequest.Content | Select-String -Pattern $regexPreviewArm64EXE).Matches.Groups[3].Value

        $regexPreviewArm64MSI = 'preview(.*?|\n)*?((?:\d+\.)+(?:\d+)).+win-arm64.+(https.+(?:\d+\.)+(?:\d+).+.msi)'
        $versionPreviewArm64MSI = ($webRequest.Content | Select-String -Pattern $regexPreviewArm64MSI).Matches.Groups[2].Value
        $urlPreviewArm64MSI = ($webRequest.Content | Select-String -Pattern $regexPreviewArm64MSI).Matches.Groups[3].Value

        # Production/General ring
        $regexProd64EXE = 'production build(.*?|\n)*?((?:\d+\.)+(?:\d+)).+win-x64.+(https.+(?:\d+\.)+(?:\d+).+.exe)'
        $versionProd64EXE = ($webRequest.Content | Select-String -Pattern $regexProd64EXE).Matches.Groups[2].Value
        $urlProd64EXE = ($webRequest.Content | Select-String -Pattern $regexProd64EXE).Matches.Groups[3].Value

        $regexProd64MSI = 'production build(.*?|\n)*?((?:\d+\.)+(?:\d+)).+win-x64.+(https.+(?:\d+\.)+(?:\d+).+.msi)'
        $versionProd64MSI = ($webRequest.Content | Select-String -Pattern $regexProd64MSI).Matches.Groups[2].Value
        $urlProd64MSI = ($webRequest.Content | Select-String -Pattern $regexProd64MSI).Matches.Groups[3].Value

        $regexProd32EXE = 'production build(.*?|\n)*?((?:\d+\.)+(?:\d+)).+win-x86.+(https.+(?:\d+\.)+(?:\d+).+.exe)'
        $versionProd32EXE = ($webRequest.Content | Select-String -Pattern $regexProd32EXE).Matches.Groups[2].Value
        $urlProd32EXE = ($webRequest.Content | Select-String -Pattern $regexProd32EXE).Matches.Groups[3].Value

        $regexProd32MSI = 'production build(.*?|\n)*?((?:\d+\.)+(?:\d+)).+win-x86.+(https.+(?:\d+\.)+(?:\d+).+.msi)'
        $versionProd32MSI = ($webRequest.Content | Select-String -Pattern $regexProd32MSI).Matches.Groups[2].Value
        $urlProd32MSI = ($webRequest.Content | Select-String -Pattern $regexProd32MSI).Matches.Groups[3].Value

        $regexProdArm64EXE = 'production build(.*?|\n)*?((?:\d+\.)+(?:\d+)).+win-arm64.+(https.+(?:\d+\.)+(?:\d+).+.exe)'
        $versionProdArm64EXE = ($webRequest.Content | Select-String -Pattern $regexProdArm64EXE).Matches.Groups[2].Value
        $urlProdArm64EXE = ($webRequest.Content | Select-String -Pattern $regexProdArm64EXE).Matches.Groups[3].Value

        $regexProdArm64MSI = 'production build(.*?|\n)*?((?:\d+\.)+(?:\d+)).+win-arm64.+(https.+(?:\d+\.)+(?:\d+).+.msi)'
        $versionProdArm64MSI = ($webRequest.Content | Select-String -Pattern $regexProdArm64MSI).Matches.Groups[2].Value
        $urlProdArm64MSI = ($webRequest.Content | Select-String -Pattern $regexProdArm64MSI).Matches.Groups[3].Value

        # Continuous deployment/Development ring
        if ($versionDev64EXE -and $urlDev64EXE)
        {
            [PSCustomObject]@{
                Version      = $versionDev64EXE
                Ring         = 'Development'
                Architecture = 'x64'
                Type         = 'Exe'
                URI          = $urlDev64EXE
            }
        }

        if ($versionDev64EXE -and $urlDev64EXE)
        {
            [PSCustomObject]@{
                Version      = $versionDev64MSI
                Ring         = 'Development'
                Architecture = 'x64'
                Type         = 'Msi'
                URI          = $urlDev64MSI
            }
        }

        if ($versionDev32EXE -and $urlDev32EXE)
        {
            [PSCustomObject]@{
                Version      = $versionDev32EXE
                Ring         = 'Development'
                Architecture = 'x86'
                Type         = 'Exe'
                URI          = $urlDev32EXE
            }
        }

        if ($versionDev32MSI -and $urlDev32MSI)
        {
            [PSCustomObject]@{
                Version      = $versionDev32MSI
                Ring         = 'Development'
                Architecture = 'x86'
                Type         = 'Msi'
                URI          = $urlDev32MSI
            }
        }

        if ($versionDevArm64EXE -and $urlDevArm64EXE)
        {
            [PSCustomObject]@{
                Version      = $versionDevArm64EXE
                Ring         = 'Development'
                Architecture = 'Arm64'
                Type         = 'Exe'
                URI          = $urlDevArm64EXE
            }
        }

        if ($versionDevArm64MSI -and $urlDevArm64MSI)
        {
            [PSCustomObject]@{
                Version      = $versionDevArm64MSI
                Ring         = 'Development'
                Architecture = 'Arm64'
                Type         = 'Msi'
                URI          = $urlDevArm64MSI
            }
        }

        # Exploration/Beta ring
        if ($versionBeta64EXE -and $urlBeta64EXE)
        {
            [PSCustomObject]@{
                Version      = $versionBeta64EXE
                Ring         = 'Beta'
                Architecture = 'x64'
                Type         = 'Exe'
                URI          = $urlBeta64EXE
            }
        }

        if ($versionBeta64EXE -and $urlBeta64EXE)
        {
            [PSCustomObject]@{
                Version      = $versionBeta64MSI
                Ring         = 'Beta'
                Architecture = 'x64'
                Type         = 'Msi'
                URI          = $urlBeta64MSI
            }
        }

        if ($versionBeta32EXE -and $urlBeta32EXE)
        {
            [PSCustomObject]@{
                Version      = $versionBeta32EXE
                Ring         = 'Beta'
                Architecture = 'x86'
                Type         = 'Exe'
                URI          = $urlBeta32EXE
            }
        }

        if ($versionBeta32MSI -and $urlBeta32MSI)
        {
            [PSCustomObject]@{
                Version      = $versionBeta32MSI
                Ring         = 'Beta'
                Architecture = 'x86'
                Type         = 'Msi'
                URI          = $urlBeta32MSI
            }
        }

        if ($versionBetaArm64EXE -and $urlBetaArm64EXE)
        {
            [PSCustomObject]@{
                Version      = $versionBetaArm64EXE
                Ring         = 'Beta'
                Architecture = 'Arm64'
                Type         = 'Exe'
                URI          = $urlBetaArm64EXE
            }
        }

        if ($versionBetaArm64MSI -and $urlBetaArm64MSI)
        {
            [PSCustomObject]@{
                Version      = $versionBetaArm64MSI
                Ring         = 'Beta'
                Architecture = 'Arm64'
                Type         = 'Msi'
                URI          = $urlBetaArm64MSI
            }
        }

        # Preview ring
        if ($versionPreview64EXE -and $urlPreview64EXE)
        {
            [PSCustomObject]@{
                Version      = $versionPreview64EXE
                Ring         = 'Preview'
                Architecture = 'x64'
                Type         = 'Exe'
                URI          = $urlPreview64EXE
            }
        }

        if ($versionPreview64EXE -and $urlPreview64EXE)
        {
            [PSCustomObject]@{
                Version      = $versionPreview64MSI
                Ring         = 'Preview'
                Architecture = 'x64'
                Type         = 'Msi'
                URI          = $urlPreview64MSI
            }
        }

        if ($versionPreview32EXE -and $urlPreview32EXE)
        {
            [PSCustomObject]@{
                Version      = $versionPreview32EXE
                Ring         = 'Preview'
                Architecture = 'x86'
                Type         = 'Exe'
                URI          = $urlPreview32EXE
            }
        }

        if ($versionPreview32MSI -and $urlPreview32MSI)
        {
            [PSCustomObject]@{
                Version      = $versionPreview32MSI
                Ring         = 'Preview'
                Architecture = 'x86'
                Type         = 'Msi'
                URI          = $urlPreview32MSI
            }
        }

        if ($versionPreviewArm64EXE -and $urlPreviewArm64EXE)
        {
            [PSCustomObject]@{
                Version      = $versionPreviewArm64EXE
                Ring         = 'Preview'
                Architecture = 'Arm64'
                Type         = 'Exe'
                URI          = $urlPreviewArm64EXE
            }
        }

        if ($versionPreviewArm64MSI -and $urlPreviewArm64MSI)
        {
            [PSCustomObject]@{
                Version      = $versionPreviewArm64MSI
                Ring         = 'Preview'
                Architecture = 'Arm64'
                Type         = 'Msi'
                URI          = $urlPreviewArm64MSI
            }
        }

        # Production/General ring
        if ($versionProd64EXE -and $urlProd64EXE)
        {
            [PSCustomObject]@{
                Version      = $versionProd64EXE
                Ring         = 'Production'
                Architecture = 'x64'
                Type         = 'Exe'
                URI          = $urlProd64EXE
            }
        }

        if ($versionProd64EXE -and $urlProd64EXE)
        {
            [PSCustomObject]@{
                Version      = $versionProd64MSI
                Ring         = 'Production'
                Architecture = 'x64'
                Type         = 'Msi'
                URI          = $urlProd64MSI
            }
        }

        if ($versionProd32EXE -and $urlProd32EXE)
        {
            [PSCustomObject]@{
                Version      = $versionProd32EXE
                Ring         = 'Production'
                Architecture = 'x86'
                Type         = 'Exe'
                URI          = $urlProd32EXE
            }
        }

        if ($versionProd32MSI -and $urlProd32MSI)
        {
            [PSCustomObject]@{
                Version      = $versionProd32MSI
                Ring         = 'Production'
                Architecture = 'x86'
                Type         = 'Msi'
                URI          = $urlProd32MSI
            }
        }

        if ($versionProdArm64EXE -and $urlProdArm64EXE)
        {
            [PSCustomObject]@{
                Version      = $versionProdArm64EXE
                Ring         = 'Production'
                Architecture = 'Arm64'
                Type         = 'Exe'
                URI          = $urlProdArm64EXE
            }
        }

        if ($versionProdArm64MSI -and $urlProdArm64MSI)
        {
            [PSCustomObject]@{
                Version      = $versionProdArm64MSI
                Ring         = 'Production'
                Architecture = 'Arm64'
                Type         = 'Msi'
                URI          = $urlProdArm64MSI
            }
        }
    }
}

$appVendor = "Microsoft"
$appName = "Teams"
$appProcesses = @("Teams", "Update", "Squirrel", "Outlook")
$appTransformURL = "https://github.com/JonathanPitre/Apps/raw/master/Microsoft/Teams/Teams.mst"
$appTransform = Split-Path -Path $appTransformURL -Leaf
$appInstallParameters = "/QB"
$appAddParameters = "ALLUSER=1 ALLUSERS=1"
$Nevergreen = Get-MicrosoftTeams | Where-Object {$_.Ring -eq "Beta" -and $_.Architecture -eq "x64" -and $_.Type -eq "Msi"}
$appVersion = $Nevergreen.Version
$appURL = $Nevergreen.URI
$appSetup = Split-Path -Path $appURL -Leaf
$appDestination = "${env:ProgramFiles(x86)}\Microsoft\Teams\current"
[boolean]$IsAppInstalled = [boolean](Get-InstalledApplication -Name "$appVendor $appName")
$appInstalledVersion = (Get-FileVersion $appDestination\Teams.exe)
##*===============================================

If ([version]$appVersion -gt [version]$appInstalledVersion)
{
    Set-Location -Path $appScriptDirectory
    If (-Not(Test-Path -Path $appVersion))
    {
        New-Folder -Path $appVersion
    }
    Set-Location -Path $appVersion

    # Uninstall previous versions
    Write-Log -Message "Uninstalling previous versions..." -Severity 1 -LogType CMTrace -WriteHost $True
    Get-Process -Name $appProcesses | Stop-Process -Force

    # Remove machine-wide install
    Remove-MSIApplications -Name "$appVendor $appName" -Parameters $appInstallParameters -ContinueOnError $True
    Remove-MSIApplications -Name "$appName Machine-Wide Installer" -Parameters $appInstallParameters -ContinueOnError $True

    # Delete left over reg keys
    Remove-RegistryKey -Key "HKCR:\CLSID\{00425F68-FFC1-445F-8EDF-EF78B84BA1C7}" -Recurse -ContinueOnError $True
    Remove-RegistryKey -Key "HKCR:\WOW6432Node\CLSID\{00425F68-FFC1-445F-8EDF-EF78B84BA1C7}" -Recurse -ContinueOnError $True

    # Remove user install
    $TeamsUsers = Get-ChildItem -Path "$($env:SystemDrive)\Users"
    $TeamsUsers | ForEach-Object {
        Try
        {
            If (Test-Path "$($env:SystemDrive)\Users\$($_.Name)\AppData\Local\$appVendor\$appName\Update.exe")
            {
                Remove-Folder -Path "$($env:SystemDrive)\Users\$($_.Name)\AppData\Local\$appVendor\$appName" -ContinueOnError $True
                Remove-Folder -Path "$($env:SystemDrive)\Users\$($_.Name)\AppData\Local\SquirrelTemp" -ContinueOnError $True
                Remove-Folder -Path "$($env:SystemDrive)\Users\$($_.Name)\AppData\Local\$($appName)MeetingAddin" -ContinueOnError $True
                Remove-Folder -Path "$($env:SystemDrive)\Users\$($_.Name)\AppData\Local\$($appName)PresenceAddin" -ContinueOnError $True
                Remove-Folder -Path "$($env:SystemDrive)\Users\$($_.Name)\AppData\Local\SquirrelTemp" -ContinueOnError $True
                Remove-Folder -Path "$($env:SystemDrive)\Users\$($_.Name)\AppData\Roaming\$appVendor\$appName" -ContinueOnError $True
                Remove-File -Path "$($env:SystemDrive)\Users\$($_.Name)\AppData\Roaming\$appVendor\Windows\Start Menu\Programs\$appVendor Corporation\$appVendor $appName.lnk" -ContinueOnError $True
                Remove-File -Path "$($env:SystemDrive)\Users\$($_.Name)\AppData\Roaming\$appVendor\Windows\Start Menu\Programs\$appVendor $appName.lnk" -ContinueOnError $True
                Remove-File -Path "$($env:SystemDrive)\Users\$($_.Name)\Desktop\$appVendor $appName.lnk" -ContinueOnError $True
            }
        }
        Catch
        {
            Out-Null
        }
    }

    # Remove Teams registry entries from all user profiles - https://www.reddit.com/r/MicrosoftTeams/comments/gbq8rg/what_prevents_teams_from_reinstalling_or_how_to
    [scriptblock]$HKCURegistrySettings = {
        Remove-RegistryKey -Key "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Teams" -Recurse -ContinueOnError $True -SID $UserProfile.SID
        Remove-RegistryKey -Key "HKCU:\Software\Microsoft\Microsoft\Office\Teams" -Recurse -ContinueOnError $True -SID $UserProfile.SID
    }
    Invoke-HKCURegistrySettingsForAllUsers -RegistrySettings $HKCURegistrySettings

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

    # Install latest version
    Write-Log -Message "Installing $appVendor $appName $appVersion..." -Severity 1 -LogType CMTrace -WriteHost $True
    # Required if not using the custom MST
    #New-Item -Path "HKLM:\SOFTWARE\Citrix" -Name "PortICA" -Force
    Execute-MSI -Action Install -Path $appSetup -Parameters $appInstallParameters -AddParameters $appAddParameters -Transform "$appScriptDirectory\$appTransform"

    Write-Log -Message "Applying customizations..." -Severity 1 -LogType CMTrace -WriteHost $True

    # Remove unneeded applications from running at start-up
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" -Name "TeamsMachineUninstallerLocalAppData" -ContinueOnError $True
    Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" -Name "TeamsMachineUninstallerProgramData" -ContinueOnError $True
    # Uncomment to disable Teams auto-startup
    #Remove-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" -Name $appName -ContinueOnError $True

    # Fix application Start Menu shorcut
    Copy-File -Path "$envCommonStartMenuPrograms\$appVendor $appName.lnk" -Destination "$envCommonStartMenuPrograms\$appName.lnk" -ContinueFileCopyOnError $True
    Remove-File -Path "$envCommonStartMenuPrograms\$appVendor $appName.lnk" -ContinueOnError $True
    Remove-Folder -Path "$envCommonStartMenuPrograms\$appVendor Corporation" -ContinueOnError $True

    # Register Teams add-in for Outlook - https://microsoftteams.uservoice.com/forums/555103-public/suggestions/38846044-fix-the-teams-meeting-addin-for-outlook
    $appDLLs = (Get-ChildItem -Path "$envProgramFilesX86\Microsoft\TeamsMeetingAddin" -Include "Microsoft.Teams.AddinLoader.dll" -Recurse).FullName
    $appX64DLL = $appDLLs[0]
    $appX86DLL = $appDLLs[1]
    Execute-Process -Path "$envWinDir\SysWOW64\regsvr32.exe" -Parameters "/s /n /i:user `"$appX64DLL`"" -ContinueOnError $True
    Execute-Process -Path "$envWinDir\SysWOW64\regsvr32.exe" -Parameters "/s /n /i:user `"$appX86DLL`"" -ContinueOnError $True

    # Register Teams as the chat app for Office
    Set-RegistryKey -Key "HKLM:\SOFTWARE\IM Providers\Teams" -Name "FriendlyName" -Type "String" -Value "Microsoft Teams"
    Set-RegistryKey -Key "HKLM:\SOFTWARE\IM Providers\Teams" -Name "GUID" -Type "String" -Value "{00425F68-FFC1-445F-8EDF-EF78B84BA1C7}"
    Set-RegistryKey -Key "HKLM:\SOFTWARE\IM Providers\Teams" -Name "ProcessName" -Type "String" -Value "Teams.exe"
    Set-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\IM Providers\Teams" -Name "FriendlyName" -Type "String" -Value "Microsoft Teams"
    Set-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\IM Providers\Teams" -Name "GUID" -Type "String" -Value "{00425F68-FFC1-445F-8EDF-EF78B84BA1C7}"
    Set-RegistryKey -Key "HKLM:\SOFTWARE\WOW6432Node\IM Providers\Teams" -Name "ProcessName" -Type "String" -Value "Teams.exe"

    # Add Windows Defender exclusion(s) - https://docs.microsoft.com/en-us/microsoftteams/troubleshoot/teams-administration/include-exclude-teams-from-antivirus-dlp
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Microsoft\Teams\Update.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Microsoft\Teams\current\Squirrel.exe" -Force
    Add-MpPreference -ExclusionProcess "%ProgramFiles(x86)%\Microsoft\Teams\current\Teams.exe" -Force

    # Add Windows Firewall rule(s) - https://docs.microsoft.com/en-us/microsoftteams/get-clients#windows
    If (-Not(Get-NetFirewallRule -DisplayName "$appVendor $appName"))
    {
        New-NetFirewallRule -Displayname "$appVendor $appName" -Direction Inbound -Program "$appDestination\$($appProcesses[0]).exe" -Profile 'Domain, Private, Public'
    }

    # Go back to the parent folder
    Set-Location ..

    Write-Log -Message "$appVendor $appName $appVersion was installed successfully!" -Severity 1 -LogType CMTrace -WriteHost $True
}
Else
{
    Write-Log -Message "$appVendor $appName $appInstalledVersion is already installed." -Severity 1 -LogType CMTrace -WriteHost $True
}