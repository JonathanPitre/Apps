$ErrorActionPreference = "SilentlyContinue"

# Get current UI language
[Globalization.CultureInfo]$uiculture = Get-UICulture
[String]$currentUILanguage = $uiculture.TwoLetterISOLanguageName.ToUpper()

# Remove old QMId from registry and set SysPrep flag for MSMQ
$regMSMQ = "HKLM:\SOFTWARE\Microsoft\MSMQ\Parameters"
Remove-ItemProperty -Path "$regMSMQ\MachineCache" -Name "QMId" -Force
Set-ItemProperty -Path $regMSMQ -Name "LogDataCreated" -Value "0" -Type DWord
Set-ItemProperty -Path $regMSMQ -Name "SysPrep" -Type DWord -Value 1 -Force

# Fix performance counter issue that prevent service from starting
If ($currentUILanguage -eq "EN") { [string]$appName = "Session Recording Agent" }
ElseIf ($currentUILanguage -eq "FR") { [string]$appName = "Agent d'enregistrement de session" }

$regCitrixSessionRecording = "HKLM:\SYSTEM\CurrentControlSet\Services\$appName\Performance"

$regCitrixSessionRecordingCounter = Get-ItemPropertyValue -Path $regCitrixSessionRecording -Name "First Counter"

If ($null -eq $regCitrixSessionRecordingCounter)
{
    New-ItemProperty -Path $regCitrixSessionRecording -Name "First Counter" -Type DWord -Value "12508" -Force
    New-ItemProperty -Path $regCitrixSessionRecording -Name "First Help" -Type DWord -Value "12509" -Force
    New-ItemProperty -Path $regCitrixSessionRecording -Name "Last Counter" -Type DWord -Value "12512" -Force
    New-ItemProperty -Path $regCitrixSessionRecording -Name "Last Help" -Type DWord -Value "12513" -Force
}

# Get dependent services
$depServices = Get-Service -Name MSMQ -DependentServices | Select-Object -Property Name

# Restart MSMQ to get a new QMId
Restart-Service -Name MSMQ -Force

# Start dependent services
if ($null -eq $depServices)
{

    foreach ($depService in $depServices)
    {
        $startMode = Get-WmiObject win32_service -Filter "NAME = '$($depService.Name)'" | Select-Object -Property StartMode
        if ($startMode.StartMode -eq "Auto")
        {
            Start-Service -Name $depService.Name
        }
    }
}

# Restart Citrix Session Recording Agent service
Restart-Service -Name CitrixSmAudAgent -Force