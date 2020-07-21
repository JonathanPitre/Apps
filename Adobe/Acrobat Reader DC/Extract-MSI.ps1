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
Set-Location $appScriptDirectory
$appSetup = (Get-ChildItem $appScriptDirectory | Where-Object -Property Name -Match -Value "(AcroRdr)\w+\.exe" | Sort-Object CreationTime -Descending | Select-Object -First 1 | Select-Object -ExpandProperty Name)

Write-Verbose "Extracting MSI..."
# https://www.adobe.com/devnet-docs/acrobatetk/tools/AdminGuide/basics.html#expanding-exe-packages

Start-Process -FilePath .\$appSetup -ArgumentList "-sfx_o $appScriptDirectory -sfx_ne"
