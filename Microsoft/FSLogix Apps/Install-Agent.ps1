    # Enable FSLogix Apps agent search roaming - Apply different configurations based on operating system
    If ($envOSName -Like "*Windows Server 2012*" -or $envOSName -Like "*Windows Server 2016") {
        # Install Windows Search feature when missing, if Office was installed before it must be repair!
        If (!(Get-WindowsFeature -Name Search-Service)) {Install-WindowsFeature Search-Service}
    }
    If ($envOSName -Like "*Windows Server 201*" -or $envOSName -eq "Microsoft Windows 10 Enterprise for Virtual Desktops") {
        # Limit Windows Search to a single cpu core - https://social.technet.microsoft.com/Forums/en-US/88725f57-67ed-4c09-8ae6-780ff785e555/problems-with-search-service-on-server-2012-r2-rds?forum=winserverTS
        Set-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows Search" -Name "CoreCount" -Type "DWord" -Value "1"
        # Configure multi-user search - https://docs.microsoft.com/en-us/fslogix/configure-search-roaming-ht
        Set-RegistryKey -Key "HKLM:\SOFTWARE\FSLogix\Apps" -Name "RoamSearch" -Type "DWord" -Value "2"
        Set-RegistryKey -Key "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "RoamSearch" -Type "DWord" -Value "2"
    }
    If ($envOSName -Like "*Windows Server 2019*" -or $envOSName -eq "Microsoft Windows 10 Enterprise for Virtual Desktops") {
        # Enable Windows per user search catalog since FSLogix search indexing functionality is not recommended on Windows Server 2019 and Windows 10 multi-session
        # https://docs.microsoft.com/en-us/fslogix/configure-search-roaming-ht
        # https://jkindon.com/2020/03/15/windows-search-in-server-2019-and-multi-session-windows-10
        Set-RegistryKey -Key "HKLM:\SOFTWARE\Microsoft\Windows Search" -Name "EnablePerUserCatalog" -Value 1 -Type "DWord"
        Set-RegistryKey -Key "HKLM:\SOFTWARE\FSLogix\Apps" -Name "RoamSearch" -Type "DWord" -Value "0"
        Set-RegistryKey -Key "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "RoamSearch" -Type "DWord" -Value "0"

        # Define CIM object variables - https://virtualwarlock.net/how-to-install-the-fslogix-apps-agent
        # This is needed for accessing the non-default trigger settings when creating a schedule task using Powershell
        $Class = cimclass MSFT_TaskEventTrigger root/Microsoft/Windows/TaskScheduler
        $Trigger = $class | New-CimInstance -ClientOnly
        $Trigger.Enabled = $true
        $Trigger.Subscription = "<QueryList><Query Id=`"0`" Path=`"Application`"><Select Path=`"Application`">*[System[Provider[@Name='Microsoft-Windows-Search-ProfileNotify'] and EventID=2]]</Select></Query></QueryList>"

        # Define additional variables containing scheduled task action and scheduled task principal
        $A = New-ScheduledTaskAction –Execute powershell.exe -Argument "Restart-Service Wsearch"
        $P = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount
        $S = New-ScheduledTaskSettingsSet

        # Cook it all up and create the scheduled task
        $RegSchTaskParameters = @{
            TaskName    = "Restart Windows Search Service on Event ID 2"
            Description = "Restarts the Windows Search service on event ID 2"
            TaskPath    = "\"
            Action      = $A
            Principal   = $P
            Settings    = $S
            Trigger     = $Trigger
        }

        Register-ScheduledTask @RegSchTaskParameters
        Write-Log -Message "Scheduled Task to reset Windows Search was registered!" -Severity 1 -LogType CMTrace -WriteHost $True
    }
    If ($envOSName -Like "*Windows 10*" -and $envOSName -ne "Microsoft Windows 10 Enterprise for Virtual Desktops") {
        Set-RegistryKey -Key "HKLM:\SOFTWARE\FSLogix\Apps" -Name "RoamSearch" -Type "DWord" -Value "1"
        Set-RegistryKey -Key "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "RoamSearch" -Type "DWord" -Value "1"
    }