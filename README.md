# Applications
Most applications scripts are leveraging Evergreen module to download the latest version from the vendors software repository and are installed using PowerShell Application Toolkit module.

# Download and Extract
```
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
wget -uri https://github.com/JonathanPitre/Apps/archive/master.zip -OutFile C:\Windows\Temp\Master.zip
Expand-Archive -Path C:\Windows\Temp\Master.zip -DestinationPath C:\
```

# Known Issues
1. There's a powershell prompt that stop the scrip execution with PDQ Deploy. If you know how to fix this please let me know!
2. It was reported to me that the install scripts might not work correctly behind a proxy. More tests is required.
