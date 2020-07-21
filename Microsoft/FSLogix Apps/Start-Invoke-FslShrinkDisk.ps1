Invoke-Expression "$PSScriptRoot\Invoke-FslShrinkDisk.ps1 -Path E:\FSLogix -Recurse -IgnoreLessThanGB 3 -DeleteOlderThanDays 90 -LogFilePath $PSScriptRoot\Invoke-FslShrinkDisk.csv -ThrottleLimit 20"
Exit
