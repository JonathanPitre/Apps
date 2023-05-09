# Standalone application install script for VDI environment - (C)2023 Jonathan Pitre

#Requires -Version 5.1
#Requires -RunAsAdministrator

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

#region Initialisations

$ProgressPreference = "Continue"
$ErrorActionPreference = "SilentlyContinue"
# Set the script execution policy for this process
Try { Set-ExecutionPolicy -ExecutionPolicy 'ByPass' -Scope 'Process' -Force } Catch {}
# Unblock ps1 script
Get-ChildItem -Recurse *.ps*1 | Unblock-File
$env:SEE_MASK_NOZONECHECKS = 1
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
$Modules = @("PSADT") # Modules list

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

function Get-Link
{
    <#
    .SYNOPSIS
        Returns a specific link from a web page.

    .DESCRIPTION
        Returns a specific link from a web page.

    .NOTES
        Site: https://packageology.com
        Author: Dan Gough
        Twitter: @packageologist

    .LINK
        https://github.com/DanGough/Nevergreen

    .PARAMETER Uri
        The URI to query.

    .PARAMETER MatchProperty
        Whether the RegEx pattern should be applied to the href, outerHTML, class, title or data-filename of the link.

    .PARAMETER Pattern
        The RegEx pattern to apply to the selected property. Supply an array of patterns to receive multiple links.

    .PARAMETER ReturnProperty
        Optional. Specifies which property to return from the link. Defaults to href, but 'data-filename' can also be useful to retrieve.

    .PARAMETER UserAgent
        Optional parameter to provide a user agent for Invoke-WebRequest to use. Examples are:

        Googlebot: 'Googlebot/2.1 (+http://www.google.com/bot.html)'
        Microsoft Edge: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246'

    .EXAMPLE
        Get-Link -Uri 'http://somewhere.com' -MatchProperty href -Pattern '\.exe$'

        Description:
        Returns first download link matching *.exe from http://somewhere.com.
    #>
    [CmdletBinding(SupportsShouldProcess = $False)]
    param (
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline)]
        [ValidatePattern('^(http|https)://')]
        [Alias('Url')]
        [String] $Uri,
        [Parameter(
            Mandatory = $true,
            Position = 1)]
        [ValidateSet('href', 'outerHTML', 'innerHTML', 'outerText', 'innerText', 'class', 'title', 'tagName', 'data-filename')]
        [String] $MatchProperty,
        [Parameter(
            Mandatory = $true,
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [String[]] $Pattern,
        [Parameter(
            Mandatory = $false,
            Position = 3)]
        [ValidateNotNullOrEmpty()]
        [String] $ReturnProperty = 'href',
        [Parameter(
            Mandatory = $false)]
        [String] $UserAgent,
        [System.Collections.Hashtable] $Headers,
        [Switch] $PrefixDomain,
        [Switch] $PrefixParent
    )

    $ProgressPreference = 'SilentlyContinue'

    $ParamHash = @{
        Uri              = $Uri
        Method           = 'GET'
        UseBasicParsing  = $True
        DisableKeepAlive = $True
        ErrorAction      = 'Stop'
    }

    if ($UserAgent)
    {
        $ParamHash.UserAgent = $UserAgent
    }

    if ($Headers)
    {
        $ParamHash.Headers = $Headers
    }

    try
    {
        $Response = Invoke-WebRequest @ParamHash

        foreach ($CurrentPattern in $Pattern)
        {
            $Link = $Response.Links | Where-Object $MatchProperty -Match $CurrentPattern | Select-Object -Last 1 -ExpandProperty $ReturnProperty

            if ($PrefixDomain)
            {
                $BaseURL = ($Uri -split '/' | Select-Object -First 3) -join '/'
                $Link = Set-UriPrefix -Uri $Link -Prefix $BaseURL
            }
            elseif ($PrefixParent)
            {
                $BaseURL = ($Uri -split '/' | Select-Object -SkipLast 1) -join '/'
                $Link = Set-UriPrefix -Uri $Link -Prefix $BaseURL
            }

            $Link

        }
    }
    catch
    {
        Write-Error "$($MyInvocation.MyCommand): $($_.Exception.Message)"
    }

}

#endregion

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$appVendor = "Microsoft"
$envOSDisplayVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").DisplayVersion
$targetLangPack = "fr-ca"

#-----------------------------------------------------------[Execution]------------------------------------------------------------

If ($envOSName -like "*Windows 11 Enterprise*")
{
    $appURL = "https://learn.microsoft.com/en-us/azure/virtual-desktop/windows-11-language-packs"
    Set-Location -Path $appScriptPath

    # Get Language Pack ISO
    $regEx = "(https.+.iso).+(Windows 11\, version \d{2}H\d Language and Optional Features ISO)"
    $langISOurl = Get-Link -Uri $appURL -MatchProperty outerHTML -Pattern $regEx
    $langISO = Split-Path -Path $langISOurl -Leaf

    # Get Inbox Apps ISO
    $regEx = "(https.+.iso).+(Windows 11\, version \d{2}H\d Inbox Apps ISO)"
    $inboxAppsISOurl = Get-Link -Uri $appURL -MatchProperty outerHTML -Pattern $regEx
    $inboxAppsISO = Split-Path -Path $inboxAppsISOurl -Leaf

    # Get the FOD Table
    $regEx = "(https.+.xlsx).+(Available Windows \d{2} \d{2}\w\d Languages and Features on Demand table)"
    $FodTableUrl = Get-Link -Uri $appURL -MatchProperty outerHTML -Pattern $regEx
    $FodTable = Split-Path -Path $FodTableUrl -Leaf
    $FodTableCSV = $FodTable.Replace(".xlsx", ".csv")

    # Download ISOs
    # Download latest Language and Optional Features ISO
    If (-Not(Test-Path -Path $appScriptPath\$langISO))
    {
        Write-Log -Message "Downloading $appVendor Windows 11 Language and Optional Features ISO..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $langISOurl -OutFile $langISO
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Download latest Inbox Apps ISO
    If (-Not(Test-Path -Path $appScriptPath\$inboxAppsISO))
    {
        Write-Log -Message "Downloading $appVendor Windows 11 Inbox Apps ISO..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $inboxAppsISOurl -OutFile $inboxAppsISO
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Download latest FOD Table
    If (-Not(Test-Path -Path $appScriptPath\$FodTableCSV))
    {
        Write-Log -Message "Downloading $appVendor Windows 11 FOD Table CSV..." -Severity 1 -LogType CMTrace -WriteHost $True
        Invoke-WebRequest -UseBasicParsing -Uri $FodTableUrl -OutFile $FodTable
    }
    Else
    {
        Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
    }

    # Convert XLSX file to CSV
    foreach ($file in (Get-ChildItem -Path $appScriptPath\*.xlsx))
    {
        $newname = $file.FullName -replace '\.xlsx$', '.csv'
        $excelFile = New-Object -ComObject Excel.Application
        $Workbook = $excelFile.Workbooks.Open($file.FullName)
        $Workbook.SaveAs($newname, 6)
        $Workbook.Close($false)
        $excelFile.quit()
        Remove-Item -Path $appScriptPath\*.xlsx -Force
    }

    # Copy Language Pack ISO files
    $mountResult = Mount-DiskImage -ImagePath "$appScriptPath\$langISO" -PassThru
    $driveLetter = ($mountResult | Get-Volume).DriveLetter
    Write-Log -Message "Copying Language Pack files..." -Severity 1 -LogType CMTrace -WriteHost $True
    Copy-File -Path "$($driveLetter):\LanguagesAndOptionalFeatures\*$($targetLangPack)*.cab" -Destination "$appScriptPath"
    Start-Sleep -Seconds 5
    Dismount-DiskImage -ImagePath "$appScriptPath\$langISO"

    # Add Languages to running Windows Image for Capture
    # Disable Language Pack Cleanup
    Disable-ScheduledTask -TaskPath "\Microsoft\Windows\AppxDeploymentClient\" -TaskName "Pre-staged app cleanup"
    Disable-ScheduledTask -TaskPath "\Microsoft\Windows\MUI\" -TaskName "LPRemove"
    Disable-ScheduledTask -TaskPath "\Microsoft\Windows\LanguageComponentsInstaller" -TaskName "Uninstallation"
    Set-RegistryKey -Key "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International" -Name "BlockCleanupOfUnusedPreinstalledLangPacks" -Value "1" -Type DWord

    # Set Language Pack Content Stores
    $LIPContent = "E:"

    # Import Necesarry CSV File
    $FODList = Import-Csv -Path $appScriptPath\$FodTableCSV -Delimiter ";"

    $sourceLanguage = (($FODList | Where-Object { $_.'Target Lang' -eq $targetLangPack }) | Where-Object { $_.'Source Lang' -ne $targetLangPack } | Select-Object -Property 'Source Lang' -Unique).'Source Lang'

    if (!($sourceLanguage))
    {
        $sourceLanguage = $targetLangPack
    }

    $langGroup = (($FODList | Where-Object { $_.'Target Lang' -eq $targetLangPack }) | Where-Object { $_.'Lang Group:' -ne "" } | Select-Object -Property 'Lang Group:' -Unique).'Lang Group:'

    # List of additional features to be installed
    $additionalFODList = @(
        "$LIPContent\Microsoft-Windows-NetFx3-OnDemand-Package~31bf3856ad364e35~amd64~~.cab",
        "$LIPContent\Microsoft-Windows-MSPaint-FoD-Package~31bf3856ad364e35~amd64~$sourceLanguage~.cab",
        "$LIPContent\Microsoft-Windows-SnippingTool-FoD-Package~31bf3856ad364e35~amd64~$sourceLanguage~.cab",
        "$LIPContent\Microsoft-Windows-Lip-Language_x64_$sourceLanguage.cab" ##only if applicable##
    )

    $additionalCapabilityList = @(
        "Language.Basic~~~$sourceLanguage~0.0.1.0",
        "Language.Handwriting~~~$sourceLanguage~0.0.1.0",
        "Language.OCR~~~$sourceLanguage~0.0.1.0",
        "Language.Speech~~~$sourceLanguage~0.0.1.0",
        "Language.TextToSpeech~~~$sourceLanguage~0.0.1.0"
    )

    # Install all FODs or fonts from the CSV file
    Dism /Online /Add-Package /PackagePath:$LIPContent\Microsoft-Windows-Client-Language-Pack_x64_$sourceLanguage.cab
    Dism /Online /Add-Package /PackagePath:$LIPContent\Microsoft-Windows-Lip-Language-Pack_x64_$sourceLanguage.cab
    foreach ($capability in $additionalCapabilityList)
    {
        Dism /Online /Add-Capability /CapabilityName:$capability /Source:$LIPContent
    }

    foreach ($feature in $additionalFODList)
    {
        Dism /Online /Add-Package /PackagePath:$feature
    }

    if ($langGroup)
    {
        Dism /Online /Add-Capability /CapabilityName:Language.Fonts.$langGroup~~~und-$langGroup~0.0.1.0
    }

    # Add installed language to language list
    $LanguageList = Get-WinUserLanguageList
    $LanguageList.Add("$($targetLangPack)")
    Set-WinUserLanguageList $LanguageList -force
}
ElseIf ($envOSName -like "*Windows 10 Enterprise for Virtual Desktops*")
{
    $installedLanguagePack = Get-InstalledLanguage $targetLangPack
    If ($null -eq $installedLanguagePack)
    {
        $appURL = "https://docs.microsoft.com/en-us/azure/virtual-desktop/language-packs"
        Set-Location -Path $appScriptPath

        # Get Language Pack ISO
        $regEx = "(https.+.iso).+(Windows 10 Language Pack ISO \(version \d{2}\w\d.+\))"
        $langISOurl = Get-Link -Uri $appURL -MatchProperty outerHTML -Pattern $regEx
        $langISO = Split-Path -Path $langISOurl -Leaf

        # Get FOD Disk 1 ISO
        $regEx = "(https.+.iso).+(Windows 10 FOD Disk 1 ISO \(version \d{2}\w\d.+\))"
        $fodISOUrl = Get-Link -Uri $appURL -MatchProperty outerHTML -Pattern $regEx
        $fodISO = Split-Path -Path $fodISOUrl -Leaf

        # Get Inbox Apps ISO
        $regEx = "(https.+.iso).+(Windows 10 Inbox Apps ISO \(version \d{2}H\d.+\))"
        $inboxAppsISOurl = Get-Link -Uri $appURL -MatchProperty outerHTML -Pattern $regEx
        $inboxAppsISO = Split-Path -Path $inboxAppsISOurl -Leaf

        # Get Local Experience Pack (LXP) ISO
        $regEx = "(https.+.iso).+(Windows 10\, version \d{2}\w\d or later \d{2}\w \d{4} LXP ISO)"
        $lxpISOurl = Get-Link -Uri $appURL -MatchProperty outerHTML -Pattern $regEx
        $lxpISO = Split-Path -Path $lxpISOurl -Leaf

        # Download ISOs
        # Download latest Language Pack ISO
        If (-Not(Test-Path -Path $appScriptPath\$langISO))
        {
            Write-Log -Message "Downloading $appVendor Windows 10 Language Pack ISO..." -Severity 1 -LogType CMTrace -WriteHost $True
            Invoke-WebRequest -UseBasicParsing -Uri $langISOurl -OutFile $langISO
        }
        Else
        {
            Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
        }

        # Download latest FOD Disk 1 ISO
        If (-Not(Test-Path -Path $appScriptPath\$fodISO))
        {
            Write-Log -Message "Downloading $appVendor Windows 10 FOD Disk 1 ISO..." -Severity 1 -LogType CMTrace -WriteHost $True
            Invoke-WebRequest -UseBasicParsing -Uri $fodISOUrl -OutFile $fodISO
        }
        Else
        {
            Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
        }

        # Download latest Inbox Apps ISO
        If (-Not(Test-Path -Path $appScriptPath\$inboxAppsIso))
        {
            Write-Log -Message "Downloading $appVendor Windows 10 Inbox Apps ISO..." -Severity 1 -LogType CMTrace -WriteHost $True
            Invoke-WebRequest -UseBasicParsing -Uri $inboxAppsISOurl -OutFile $inboxAppsIso
        }
        Else
        {
            Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
        }

        # Download latest Local Experience Pack (LXP) ISO
        If (-Not(Test-Path -Path $appScriptPath\$lxpISO))
        {
            Write-Log -Message "Downloading $appVendor Windows 10 Local Experience Pack (LXP) ISO..." -Severity 1 -LogType CMTrace -WriteHost $True
            Invoke-WebRequest -UseBasicParsing -Uri $lxpISOurl -OutFile $lxpISO
        }
        Else
        {
            Write-Log -Message "File(s) already exists, download was skipped." -Severity 1 -LogType CMTrace -WriteHost $True
        }

        # Copy Language Pack ISO files
        $mountResult = Mount-DiskImage -ImagePath "$appScriptPath\$langISO" -PassThru
        $driveLetter = ($mountResult | Get-Volume).DriveLetter
        Write-Log -Message "Copying Language Pack files..." -Severity 1 -LogType CMTrace -WriteHost $True
        Copy-File -Path "$($driveLetter):\LocalExperiencePack\$($targetLangPack)\*" -Destination "$appScriptPath"
        Copy-File -Path "$($driveLetter):\x64\langpacks\Microsoft-Windows-Client-Language-Pack_x64_$($targetLangPack).cab" -Destination "$appScriptPath"
        Start-Sleep -Seconds 5
        Dismount-DiskImage -ImagePath "$appScriptPath\$langISO"

        # Copy FOD Disk 1 ISO files
        $mountResult = Mount-DiskImage -ImagePath "$appScriptPath\$fodISO" -PassThru
        $driveLetter = ($mountResult | Get-Volume).DriveLetter
        Write-Log -Message "Copying FOD Disk 1 files..." -Severity 1 -LogType CMTrace -WriteHost $True
        Copy-File -Path "$($driveLetter):\Microsoft-Windows-LanguageFeatures-Basic-$($targetLangPack)-Package~31bf3856ad364e35~amd64~~.cab" -Destination "$appScriptPath"
        Copy-File -Path "$($driveLetter):\Microsoft-Windows-LanguageFeatures-Handwriting-$($targetLangPack)-Package~31bf3856ad364e35~amd64~~.cab" -Destination "$appScriptPath"
        Copy-File -Path "$($driveLetter):\Microsoft-Windows-LanguageFeatures-OCR-$($targetLangPack)-Package~31bf3856ad364e35~amd64~~.cab" -Destination "$appScriptPath"
        Copy-File -Path "$($driveLetter):\Microsoft-Windows-LanguageFeatures-Speech-$($targetLangPack)-Package~31bf3856ad364e35~amd64~~.cab" -Destination "$appScriptPath"
        Copy-File -Path "$($driveLetter):\Microsoft-Windows-LanguageFeatures-TextToSpeech-$($targetLangPack)-Package~31bf3856ad364e35~amd64~~.cab" -Destination "$appScriptPath"
        Copy-File -Path "$($driveLetter):\Microsoft-Windows-NetFx3-OnDemand-Package~31bf3856ad364e35~amd64~$($targetLangPack)~.cab" -Destination "$appScriptPath"
        Copy-File -Path "$($driveLetter):\Microsoft-Windows-InternetExplorer-Optional-Package~31bf3856ad364e35~amd64~$($targetLangPack)~.cab" -Destination "$appScriptPath"
        Copy-File -Path "$($driveLetter):\Microsoft-Windows-MSPaint-FoD-Package~31bf3856ad364e35~amd64~$($targetLangPack)~.cab" -Destination "$appScriptPath"
        Copy-File -Path "$($driveLetter):\Microsoft-Windows-Notepad-FoD-Package~31bf3856ad364e35~amd64~$($targetLangPack)~.cab" -Destination "$appScriptPath"
        Copy-File -Path "$($driveLetter):\Microsoft-Windows-PowerShell-ISE-FOD-Package~31bf3856ad364e35~amd64~$($targetLangPack)~.cab" -Destination "$appScriptPath"
        Copy-File -Path "$($driveLetter):\Microsoft-Windows-Printing-WFS-FoD-Package~31bf3856ad364e35~amd64~$($targetLangPack)~.cab" -Destination "$appScriptPath"
        Copy-File -Path "$($driveLetter):\Microsoft-Windows-StepsRecorder-Package~31bf3856ad364e35~amd64~$($targetLangPack)~.cab" -Destination "$appScriptPath"
        Copy-File -Path "$($driveLetter):\Microsoft-Windows-WordPad-FoD-Package~31bf3856ad364e35~amd64~$($targetLangPack)~.cab" -Destination "$appScriptPath"
        Start-Sleep -Seconds 5
        Dismount-DiskImage -ImagePath "$appScriptPath\$fodISO"

        # Copy Inbox Apps ISO files
        $mountResult = Mount-DiskImage -ImagePath "$appScriptPath\$inboxAppsIso" -PassThru
        $driveLetter = ($mountResult | Get-Volume).DriveLetter
        Write-Log -Message "Copying Inbox Apps files..." -Severity 1 -LogType CMTrace -WriteHost $True
        Copy-File -Path "$($driveLetter):\amd64fre\*" -Destination "$appScriptPath"
        Start-Sleep -Seconds 5
        Dismount-DiskImage -ImagePath "$appScriptPath\$inboxAppsIso"

        # Copy Local Experience Pack (LXP) ISO files
        $mountResult = Mount-DiskImage -ImagePath "$appScriptPath\$lxpISO" -PassThru
        $driveLetter = ($mountResult | Get-Volume).DriveLetter
        Write-Log -Message "Copying Local Experience Pack (LXP) files..." -Severity 1 -LogType CMTrace -WriteHost $True
        Copy-File -Path "$($driveLetter):\LocalExperiencePack\$($targetLangPack)\*" -Destination "$appScriptPath"
        Start-Sleep -Seconds 5
        Dismount-DiskImage -ImagePath "$appScriptPath\$lxpISO"

        # Add Languages to running Windows Image for Capture

        # Disable Language Pack Cleanup
        Disable-ScheduledTask -TaskPath "\Microsoft\Windows\AppxDeploymentClient\" -TaskName "Pre-staged app cleanup"

        # Add Language Files
        Write-Log -Message "Adding language files..." -Severity 1 -LogType CMTrace -WriteHost $True
        Add-AppProvisionedPackage -Online -PackagePath $appScriptPath\$($targetLangPack)\LanguageExperiencePack.$($targetLangPack).Neutral.appx -LicensePath $appScriptPath\$($targetLangPack)\License.xml
        Add-WindowsPackage -Online -PackagePath $appScriptPath\Microsoft-Windows-Client-Language-Pack_x64_$($targetLangPack).cab
        Add-WindowsPackage -Online -PackagePath $appScriptPath\Microsoft-Windows-LanguageFeatures-Basic-$($targetLangPack)-Package~31bf3856ad364e35~amd64~~.cab
        Add-WindowsPackage -Online -PackagePath $appScriptPath\Microsoft-Windows-LanguageFeatures-Handwriting-$($targetLangPack)-Package~31bf3856ad364e35~amd64~~.cab
        Add-WindowsPackage -Online -PackagePath $appScriptPath\Microsoft-Windows-LanguageFeatures-OCR-$($targetLangPack)-Package~31bf3856ad364e35~amd64~~.cab
        Add-WindowsPackage -Online -PackagePath $appScriptPath\Microsoft-Windows-LanguageFeatures-Speech-$($targetLangPack)-Package~31bf3856ad364e35~amd64~~.cab
        Add-WindowsPackage -Online -PackagePath $appScriptPath\Microsoft-Windows-LanguageFeatures-TextToSpeech-$($targetLangPack)-Package~31bf3856ad364e35~amd64~~.cab
        Add-WindowsPackage -Online -PackagePath $appScriptPath\Microsoft-Windows-NetFx3-OnDemand-Package~31bf3856ad364e35~amd64~$($targetLangPack)~.cab
        Add-WindowsPackage -Online -PackagePath $appScriptPath\Microsoft-Windows-InternetExplorer-Optional-Package~31bf3856ad364e35~amd64~$($targetLangPack)~.cab
        Add-WindowsPackage -Online -PackagePath $appScriptPath\Microsoft-Windows-MSPaint-FoD-Package~31bf3856ad364e35~amd64~$($targetLangPack)~.cab
        Add-WindowsPackage -Online -PackagePath $appScriptPath\Microsoft-Windows-Notepad-FoD-Package~31bf3856ad364e35~amd64~$($targetLangPack)~.cab
        Add-WindowsPackage -Online -PackagePath $appScriptPath\Microsoft-Windows-PowerShell-ISE-FOD-Package~31bf3856ad364e35~amd64~$($targetLangPack)~.cab
        Add-WindowsPackage -Online -PackagePath $appScriptPath\Microsoft-Windows-Printing-WFS-FoD-Package~31bf3856ad364e35~amd64~$($targetLangPack)~.cab
        Add-WindowsPackage -Online -PackagePath $appScriptPath\Microsoft-Windows-StepsRecorder-Package~31bf3856ad364e35~amd64~$($targetLangPack)~.cab
        Add-WindowsPackage -Online -PackagePath $appScriptPath\Microsoft-Windows-WordPad-FoD-Package~31bf3856ad364e35~amd64~$($targetLangPack)~.cab

        $LanguageList = Get-WinUserLanguageList
        $LanguageList.Add("$targetLangPack")
        Set-WinUserLanguageList $LanguageList -Force
        Start-Sleep -Seconds 20

        # Update Inbox Apps for Multi Language

        # Update installed Inbox Store App
        Write-Log -Message "Updating Inbox Store App files..." -Severity 1 -LogType CMTrace -WriteHost $True
        foreach ($App in (Get-AppxProvisionedPackage -Online))
        {
            $AppPath = $appScriptPath + $App.DisplayName + '_' + $App.PublisherId
            Write-Host "Handling $AppPath"
            $licFile = Get-Item $AppPath*.xml
            if ($licFile.Count)
            {
                $lic = $true
                $licFilePath = $licFile.FullName
            }
            else
            {
                $lic = $false
            }
            $appxFile = Get-Item $AppPath*.appx*
            if ($appxFile.Count)
            {
                $appxFilePath = $appxFile.FullName
                if ($lic)
                {
                    Add-AppxProvisionedPackage -Online -PackagePath $appxFilePath -LicensePath $licFilePath
                }
                else
                {
                    Add-AppxProvisionedPackage -Online -PackagePath $appxFilePath -SkipLicense
                }
            }
        }

        Write-Log -Message "$targetLangPack language pack was sucesfully installed!" -Severity 1 -LogType CMTrace -WriteHost $True

        # Cleanup
        Remove-File -Path $appScriptPath\*.iso
        Write-Log -Message "$targetLangPack language pack was sucesfully installed!" -Severity 1 -LogType CMTrace -WriteHost $True
    }
    Else
    {
        Write-Log -Message "$targetLangPack language pack is already installed!" -Severity 1 -LogType CMTrace -WriteHost $True
    }


}
#ElseIf ($envOSName -like "*Windows 10 Enterprise*")
ElseIf ($envOSName -like "*Windows Server 2022*")
{
    $installedLanguagePack = Get-InstalledLanguage $targetLangPack
    If ($null -eq $installedLanguagePack)
    {
        Install-Language -Language $targetLangPack
        Write-Log -Message "$targetLangPack language pack was sucesfully installed!" -Severity 1 -LogType CMTrace -WriteHost $True
    }
    Else
    {
        Write-Log -Message "$targetLangPack language pack is already installed!" -Severity 1 -LogType CMTrace -WriteHost $True
    }
}
Else
{
    Write-Log -Message "$envOSName is not supported!" -Severity 3 -LogType CMTrace -WriteHost $True
}