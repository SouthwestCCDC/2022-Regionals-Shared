<#Set-ExecutionPolicy RemoteSigned –Scope Process
Then
Set-ExecutionPolicy Restricted –Scope Process#>

$EnableSvc = @(
    "wuauserv", # Windows Update Service
    "EventLog", # Windows Event Log Service
    "mpssvc" # Windows Firewall Service
)
ForEach ($Svc in $EnableSvc) { Set-Service "$Svc" -StartupType Automatic; Start-Service "$Svc" }

$DisableSvc = @(
    # Previously scored services (not critical service-dependent)
    "tlntsvr",
    "W3SVC",
    "SNMP",
    "FTPSVC",
    "upnphost",
    "LPDSVC",
    "simptcp",
    "RemoteRegistry",
    "NetTcpPortSharing",
    "SSDPSRV",
    "Spooler",
    "RasAuto",
    "RasMan",
    "RemoteAccess",
    "TapiSrv",
    "WebClient",
    "MSMQ",
    "RpcLocator",
    "XblAuthManager",
    "XblGameSave",
    "iprip",
    "SharedAccess",
    # Expirimental...
    "PlugPlay",
    "fax",
	"BTAGService"
)
ForEach ($Svc in $DisableSvc) {
     $doesExist = (Get-Service $Svc -EA SilentlyContinue).Name
     if ($doesExist) {
        Stop-Service -Force -Name "$Svc" -EA SilentlyContinue; Set-Service -Name "$Svc" -StartupType Disabled -EA SilentlyContinue
     }
}
Write-Host "-> Unnecessary/vulnerable services have been exiled..." -foregroundcolor Green

# Enable firewall protection
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True | Out-Null; Write-Host "-> Firewall protection is enabled" -foregroundcolor Green

# Remove unauthorized SMB shares
$ShareList = (Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares).Property
ForEach ($Share in $ShareList) { 
    Write-Host "[*] Detected non-default SMB Share: $Share" -foregroundcolor Red
    Get-SmbShare -Name "$Share" | Select-Object Name, Path | Format-List 
    $removeShare = Read-Host -Prompt "Would you like to remove this share from the system? (Y/n)"
    if ($removeShare -match '^[Yy]') { 
        net share "$Share" /delete 
    }
}

# Disable hibernation (hiberfil.sys)
powercfg.exe /hibernate off | Out-Null; Write-Host "-> Hibernation has been disabled" -foregroundcolor Green

# Enable Data Execution Prevention for all programs and services
bcdedit.exe /set {current} nx AlwaysOn | Out-Null; Write-Host "-> DEP is enabled for all programs and services" -foregroundcolor Green

# Attempt to remove rogue applications
$x86InstallPath = "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
$x64InstallPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"

# Collector
$location = Read-Host -Prompt "What directory do you wish to export the csv files?"
netstat -ano > $location\netstat.csv
get-NetTCPConnection | export-csv $location\netTCP.csv
get-process > $location\ps.csv
Get-service | export-csv $location\svc.csv
tasklist /svc > $location\tasklist.csv