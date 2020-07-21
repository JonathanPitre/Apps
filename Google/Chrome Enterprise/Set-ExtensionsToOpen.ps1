<#
.FUNCTIONALITY
-Sets extensions to opens automatically with Chrome when downloading files

.SYNOPSIS
-Sets extensions to opens automatically with Chrome when downloading files

.NOTES
Change log

Feb 18, 2020
-Initial version

.DESCRIPTION
Author jonathan.pitre@procontact.ca

.EXAMPLE
./Set-ExtensionsToOpen.ps1

.NOTES

.Link
N/A

#>

$neededFileExt = "ica","msrcincident","jnlp","pdf","docx","doc","xlsx","xls","pptx","ppt","ics","ical","do" 
$path = $env:LOCALAPPDATA + "\Google\Chrome\User Data\Default\Preferences"
$prefContent = Get-Content $path -Encoding utf8
$prefs = ConvertFrom-Json $prefContent
If(($prefs | gm).name -contains "download") #if the download node exists
{
    If(($prefs.download | gm).name -contains "extensions_to_open") #sometimes the download node doesn't have the extensions_to_open child
    {
        If($prefs.download.extensions_to_open) #if it has value, grab the contents
        {
            [string[]]$existingFileExt = $prefs.download.extensions_to_open.tostring().split(":")
        }
        Else
        {
            [string[]]$existingFileExt = $null
        }
    }Else{ #if extensions_to_open doesn't exist, create it
        $prefs.download | Add-Member -MemberType NoteProperty -Name extensions_to_open -Value ""
        [string[]]$existingFileExt = $null
    }
    Foreach($ext in $neededFileExt)
    {
        If($existingFileExt -notcontains $ext) #only add the necessary extension if it isn't already there
        {
            [string[]]$existingFileExt += $ext
        }
    }
    $prefs.download.extensions_to_open = $existingFileExt -join ":" #the extensions are in the format: ext:ext:ext
    ConvertTo-Json $prefs -Compress -depth 100 | Out-File $path -Encoding utf8 #write it back
}
