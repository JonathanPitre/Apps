# Schedule a reboot of servers during Maintenance hours
# Run a delprof2 afterwards

#In the end I've built a script that is scheduled on the RD Broker to check the RD Session Hosts during the night (the script is tied to a scheduled task that runs #every 30 minutes between 03:00 AM and 05:00 AM) to reboot and cleanup the server whenever no users are connected (or are disconnected for at least 10 minutes). It #also does some Client Side Rendering cleanups.

$Computers = (Get-RDSessionCollection | Get-RDSessionHost).SessionHost
$ScriptFolder = "C:\Scripts"
$LogFolder = "C:\Scripts\Logs"
$MinimumDisconnctedTimeInMinutes = 10

#Creating logoutput and filenames
$LogFile = $LogFolder + "\" + (Get-Date -UFormat "%d-%m-%Y") + " Maintain RDS Nodes.txt"

Function Write-Log
{
	param (
		[Parameter(Mandatory = $True)]
		[array]$LogOutput
	)
	$currentDate = (Get-Date -UFormat "%d-%m-%Y")
	$currentTime = (Get-Date -UFormat "%T")
	$logOutput = $logOutput -join (" ")
	"[$currentDate $currentTime] $logOutput" | Out-File $Logfile -Append
}

# Reboot where possible
Write-Log -LogOutput "Starting stage Reboot"
$rdUserSessions = Get-RdUserSession
$RebootedComputers = @()

Foreach ($computer in $Computers)
{
	Write-Log -LogOutput "- Validating $($computer)"

	# Check if the server is online:
	If (Test-Path "\\$($computer)\\c$")
	{
		$noRdSessionBlock = $True
		$rdSessionCount = ($rdUserSessions | Where-Object { $_.HostServer -eq $computer }).Count

		# If there are sessions, see if they are a reason NOT to reboot:
		If ($rdSessionCount -gt 0)
		{
			# Walk through sessions on this computer:
			ForEach ($rdUserSession in ($rdUserSessions | Where-Object { $_.HostServer -eq $computer }))
			{
				# Check if the session was active:
				If ($rdUserSession.SessionState -eq "STATE_ACTIVE")
				{
					$noRdSessionBlock = $False
				}

				# Check if the session is disconncted LESS than it should:
				ElseIf ($rdUserSession.DisconnectTime -gt (Get-Date).AddMinutes(0 - $MinimumDisconnctedTimeInMinutes))
				{
					$noRdSessionBlock = $False
				}
			}
		}

		# Check if we're OK to reboot:
		If ( $noRdSessionBlock )
		{
			# Test if the server has been 'up' for at least 16 hours:
			If ((Get-CimInstance -ComputerName $computer -ClassName Win32_OperatingSystem).LastBootUpTime -le (Get-Date).AddHours(-16))
			{
				# Reboot the server:
				Try
				{
					Restart-Computer -ComputerName $computer -Force -Confirm:$False
					$RebootedComputers += $computer
					Write-Log -LogOutput "-> Server is rebooted"
				}
				Catch
				{
					Write-Log -LogOutput "-> Failed to reboot Server"
				}
			}
			Else { Write-Log -LogOutput "-> Server was recently rebooted already" }
		}
		Else { Write-Log -LogOutput "-> Server still has active or recently disconnected sessions" }
	}
	Else { Write-Log -LogOutput "-> Server is not accessible" }
}

Write-Log -LogOutput "Sleeping 5 minutes to start-up"
Start-Sleep -Seconds 300

# Cleanup old profiles
Write-Log -LogOutput "Starting stage Cleanup"

Foreach ($computer in $RebootedComputers)
{
	Write-Log -LogOutput "- Cleaning $($computer)"

	# Prepare request
	$arguments = ""
	$arguments += " /c:\\" + $computer;
	$arguments += " /u /ed:vt.admin* /ed:SVC-NW-PRTGServices";
	$finalcommand = ".\DelProf2.exe" + $arguments

	# Run request
	Push-Location $ScriptFolder
	$result = Invoke-Expression $finalcommand
	Pop-Location
	Write-Log -LogOutput "-> Profiles Cleaned"

	# Also Cleanup the Printer Client Side Rendering:
	Invoke-Command -Computer $computer -ScriptBlock {
		$RegPath = "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Providers\Client Side Rendering Print Provider"
		If (Test-Path $RegPath)
		{
			Remove-Item $RegPath -Recurse -Force -Confirm:$False
			Restart-Service Spooler -Force
		}
	}
	Write-Log -LogOutput "-> Spooler Cleaned"
}
