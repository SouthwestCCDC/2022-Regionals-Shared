<#Set-ExecutionPolicy RemoteSigned –Scope Process
Then
Set-ExecutionPolicy Restricted –Scope Process#>

$location = Read-Host -Prompt "What directory do you wish to download to"

#Autoruns
Invoke-WebRequest https://download.sysinternals.com/files/Autoruns.zip -OutFile $location\autoruns.zip

#Everything
Invoke-WebRequest https://www.voidtools.com/Everything-1.4.1.1015.x86.zip -OutFile $location\everything.zip

#GrepWin
Invoke-WebRequest https://phoenixnap.dl.sourceforge.net/project/grepwin/2.0.10/grepWin-2.0.10_portable.zip -OutFile $location\grepwin.zip

#ProcessHacker
Invoke-WebRequest https://github.com/processhacker/processhacker/releases/download/v2.39/processhacker-2.39-bin.zip -OutFile $location\processhacker.zip

#Malwarebytes
Invoke-WebRequest https://data-cdn.mbamupdates.com/web/mb4-setup-consumer/MBSetup.exe -OutFile $location\MBSetup.exe

#Portmon
Invoke-WebRequest https://download.sysinternals.com/files/PortMon.zip -OutFile $location\PortMon.zip

#PsLoggedOn
Invoke-WebRequest https://download.sysinternals.com/files/PSTools.zip -OutFile $location\PSTools.zip

#TCPView
Invoke-WebRequest https://download.sysinternals.com/files/TCPView.zip -OutFile $location\TCPView.zip

#Handle
Invoke-WebRequest https://download.sysinternals.com/files/Handle.zip -OutFile $location\Handle.zip

#ProcMon
Invoke-WebRequest https://download.sysinternals.com/files/ProcessMonitor.zip -OutFile $location\ProcMon.zip

Write-Output "Your Download Is Complete In $location"