$FSLogixProfilesPath = "D:\FSLogix"
$IgnoreLessThanGB = "100"
$DeleteOlderThanDays = "90"
$LogFilePath = "$PSScriptRoot\Invoke-FslShrinkDisk.csv"
$ThrottleLimit = "20"

Invoke-Expression "$PSScriptRoot\Invoke-FslShrinkDisk.ps1 -Path $FSLogixProfilesPath -Recurse -IgnoreLessThanGB $IgnoreLessThanGB -DeleteOlderThanDays $DeleteOlderThanDays -LogFilePath $LogFilePath -ThrottleLimit $ThrottleLimit"
Exit
