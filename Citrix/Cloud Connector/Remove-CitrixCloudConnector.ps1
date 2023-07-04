# Citrix Cloud Connector cleanup script
# Removes the Citrix Cloud Connector and all Directories, Files and Registry Keys after the Uninstall has been completed

# Custom Tools Software Liability Disclaimer:
# These software applications are provided to you as is with no representations,
# warranties or conditions of any kind. You may use and distribute it at your own risk.
# CITRIX DISCLAIMS ALL WARRANTIES WHATSOEVER, EXPRESS, IMPLIED, WRITTEN, ORAL OR STATUTORY,
# INCLUDING WITHOUT LIMITATION WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE,
# TITLE AND NONINFRINGEMENT. Without limiting the generality of the foregoing,
# you acknowledge and agree that (a) the software application may exhibit errors,
# design flaws or other problems, possibly resulting in loss of data or damage to property;
# (b) it may not be possible to make the software application fully functional;
# and (c) Citrix may, without notice or liability to you,
# cease to make available the current version and/or any future versions of the software application.
# In no event should the code be used to support of ultra-hazardous activities,
# including but not limited to life support or blasting activities.
# NEITHER CITRIX NOR ITS AFFILIATES OR AGENTS WILL BE LIABLE,
# UNDER BREACH OF CONTRACT OR ANY OTHER THEORY OF LIABILITY,
# FOR ANY DAMAGES WHATSOEVER ARISING FROM USE OF THE SOFTWARE APPLICATION,
# INCLUDING WITHOUT LIMITATION DIRECT, SPECIAL, INCIDENTAL, PUNITIVE,
# CONSEQUENTIAL OR OTHER DAMAGES, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
# You agree to indemnify and defend Citrix against any and all claims arising from your use,
# modification or distribution of the code.



# It's suggested to run this script within the Windows Powershell ISE.

$ErrorActionPreference = "SilentlyContinue"
# add the required .NET assembly:
Add-Type -AssemblyName System.Windows.Forms

Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -match "citrix" }

# show the MsgBox:
$result = [System.Windows.Forms.MessageBox]::Show('Have you first Uninstalled the Cloud Connector from Add/Remove Programs?  By selecting No will proceed to uninstall the Cloud Connector and then perform a system cleanup.', 'Cloud Connector Cleanup Script', 'YesNo', 'Warning')

if ($result -eq 'No')
{
    $app = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall |
    Get-ItemProperty |
    Where-Object { $_.DisplayName -match "citrix" } |
    Select-Object -Property DisplayName, UninstallString

    ForEach ($ver in $app)
    {

        If ($ver.UninstallString)
        {

            $uninst = $ver.UninstallString
            Start-Process cmd -ArgumentList "/c $uninst /quiet /norestart" -NoNewWindow
            [System.Threading.Thread]::Sleep(5000)
        }
    }
    $path = "C:\Program Files\Citrix"
    $path2 = "C:\Program Files (x86)\Citrix"
    $path3 = "C:\ProgramData\Citrix"
    $path4 = "C:\Program Files\Common Files\Citrix"
    $path5 = "C:\Logs\CDF"
    $path6 = "C:\Logs\InstallLogs"

    # Checks if $path exists, if so deletes it and all subfolders and files
    if (Test-Path $path)
    {

        $path + " Exists"
        Remove-Item -Path $path -Recurse
        Write-Host -ForegroundColor Red $path " Deleted"
        [System.Threading.Thread]::Sleep(1500)

    }
 else
    {

        Write-Host -ForegroundColor Red $path " Does not exist"

    }

    # Checks if $path exists, if so deletes it and all subfolders and files
    if (Test-Path $path2)
    {

        $path2 + " Exists"
        Remove-Item -Path $path2 -Recurse
        Write-Host -ForegroundColor Red $path2 " Deleted"
        [System.Threading.Thread]::Sleep(1500)

    }
 else
    {

        Write-Host -ForegroundColor Red $path2 " Does not exist"

    }

    # Checks if $path exists, if so deletes it and all subfolders and files
    if (Test-Path $path3)
    {

        $path3 + " Exists"
        Remove-Item -Path $path3 -Recurse
        Write-Host -ForegroundColor Red $path3 " Deleted"
        [System.Threading.Thread]::Sleep(1500)

    }
 else
    {

        Write-Host -ForegroundColor Red $path3 " Does not exist"

    }

    # Checks if $path exists, if so deletes it and all subfolders and files
    if (Test-Path $path4)
    {

        $path4 + " Exists"
        Remove-Item -Path $path4 -Recurse
        Write-Host -ForegroundColor Red $path4 " Deleted"
        [System.Threading.Thread]::Sleep(1500)

    }
 else
    {

        Write-Host -ForegroundColor Red $path4 " Does not exist"

    }

    # Checks if $path exists, if so deletes it and all subfolders and files
    if (Test-Path $path5)
    {

        $path5 + " Exists"
        Remove-Item -Path $path5 -Recurse
        Write-Host -ForegroundColor Red $path5 " Deleted"
        [System.Threading.Thread]::Sleep(1500)

    }
 else
    {

        Write-Host -ForegroundColor Red $path5 " Does not exist"

    }

    # Checks if $path exists, if so deletes it and all subfolders and files
    if (Test-Path $path6)
    {

        $path6 + " Exists"
        Remove-Item -Path $path6 -Recurse
        Write-Host -ForegroundColor Red $path6 " Deleted"
        [System.Threading.Thread]::Sleep(1500)

    }
 else
    {

        Write-Host -ForegroundColor Red $path6 " Does not exist"

    }

    Remove-Item -Path "C:\Logs\Rotate CDF*" -Force
    Remove-Item -Path "C:\Logs\Flush CDF*" -Force


    # Checks if Registry Entries, if so deletes it and all Subkeys
    Remove-Item -Path "HKLM:\Software\Citrix" -Recurse -Confirm

    Remove-Item -Path "HKLM:\Software\Wow6432Node\Citrix" -Recurse -Confirm
}
else
{
    $path = "C:\Program Files\Citrix"
    $path2 = "C:\Program Files (x86)\Citrix"
    $path3 = "C:\ProgramData\Citrix"
    $path4 = "C:\Program Files\Common Files\Citrix"
    $path5 = "C:\Logs\CDF"
    $path6 = "C:\Logs\InstallLogs"

    # Checks if $path exists, if so deletes it and all subfolders and files
    if (Test-Path $path)
    {

        $path + " Exists"
        Remove-Item -Path $path -Recurse
        Write-Host -ForegroundColor Red $path " Deleted"
        [System.Threading.Thread]::Sleep(1500)

    }
 else
    {

        Write-Host -ForegroundColor Red $path " Does not exist"

    }

    # Checks if $path exists, if so deletes it and all subfolders and files
    if (Test-Path $path2)
    {

        $path2 + " Exists"
        Remove-Item -Path $path2 -Recurse
        Write-Host -ForegroundColor Red $path2 " Deleted"
        [System.Threading.Thread]::Sleep(1500)

    }
 else
    {

        Write-Host -ForegroundColor Red $path2 " Does not exist"

    }

    # Checks if $path exists, if so deletes it and all subfolders and files
    if (Test-Path $path3)
    {

        $path3 + " Exists"
        Remove-Item -Path $path3 -Recurse
        Write-Host -ForegroundColor Red $path3 " Deleted"
        [System.Threading.Thread]::Sleep(1500)

    }
 else
    {

        Write-Host -ForegroundColor Red $path3 " Does not exist"

    }

    # Checks if $path exists, if so deletes it and all subfolders and files
    if (Test-Path $path4)
    {

        $path4 + " Exists"
        Remove-Item -Path $path4 -Recurse
        Write-Host -ForegroundColor Red $path4 " Deleted"
        [System.Threading.Thread]::Sleep(1500)

    }
 else
    {

        Write-Host -ForegroundColor Red $path4 " Does not exist"

    }

    # Checks if $path exists, if so deletes it and all subfolders and files
    if (Test-Path $path5)
    {

        $path5 + " Exists"
        Remove-Item -Path $path5 -Recurse
        Write-Host -ForegroundColor Red $path5 " Deleted"
        [System.Threading.Thread]::Sleep(1500)

    }
 else
    {

        Write-Host -ForegroundColor Red $path5 " Does not exist"

    }

    # Checks if $path exists, if so deletes it and all subfolders and files
    if (Test-Path $path6)
    {

        $path6 + " Exists"
        Remove-Item -Path $path6 -Recurse
        Write-Host -ForegroundColor Red $path6 " Deleted"
        [System.Threading.Thread]::Sleep(1500)

    }
 else
    {

        Write-Host -ForegroundColor Red $path6 " Does not exist"

    }

    Remove-Item -Path "C:\Logs\Rotate CDF*" -Force
    Remove-Item -Path "C:\Logs\Flush CDF*" -Force


    # Checks if Registry Entries, if so deletes it and all Subkeys
    Remove-Item -Path "HKLM:\Software\Citrix" -Recurse -Confirm

    Remove-Item -Path "HKLM:\Software\Wow6432Node\Citrix" -Recurse -Confirm
}

Restart-Computer -Force