$action = New-ScheduledTaskAction -Execute 'ASHautoexecution.exe'
$trigger = New-ScheduledTaskTrigger -Daily -At 2am
Register-ScheduledTask -TaskName "ASH System Hardening" -Action $action -Trigger $trigger -Description "2am daily"
Write-Host "ASH scheduled to run daily at 2am"
$Task = Read-Host -Prompt "Would you like to unschedule it? y/n"
if ( $Task -eq "y" ){
    Unregister-ScheduledTask -TaskName "ASH System Hardening" -Confirm:$false
    Write-Host "ASH has been unscheduled"
}
Write-Host "---------------------------------------"
function UpdateMPSignatures {
    setx /M MP_FORCE_USE_SANDBOX 1
    Update-MpSignature
    Write-Host "MP Signatures Updated" -Fore Green
}
#Enable defender signatures for PUA(Potentially Unwanted Applications)
function EnableDefenderSignatures {    
    powershell.exe Set-MpPreference -PUAProtection enable
    Write-Host "Windows Defender signatures enabled; PUA Protection enabled" -Fore Green
}
#Enable periodic scanning
function PeriodicScanning {  
    reg add "HKCU\SOFTWARE\Microsoft\Windows Defender" /v PassiveMode /t REG_DWORD /d 2 /f
    Write-Host "Periodic scanning enabled" -Fore Green
}
#Enable Cloud functionality of Windows Defender
function CloudFunctionality {
    powershell.exe Set-MpPreference -MAPSReporting Advanced
    powershell.exe Set-MpPreference -SubmitSamplesConsent 0
    Write-Host "Cloud functinality for Windows Defender enabled" -Fore Green
}
#Enables early launch Anti-malware driver
function AntimalDriver {
    reg add "HKCU\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" /v DriverLoadPolicy /t REG_DWORD /d 8 /f
    Write-Host "Early launch anti-malware driver enabled" -Fore Green
}
#Enable Windows Defender real time monitoring
function RealTimeMontitoring {
    powershell.exe Set-MpPreference -DisableRealtimeMonitoring 0
    Write-Host "Windows defender real time monitoring enabled" -Fore Green
}

#Enable and configure Windows Firewall
function FirewallSettings {
    NetSh Advfirewall set allprofiles state on
    Write-Host "Advanced Firewall All profiles Enabled" -Fore Green
    Set-NetFirewallProfile -All -Enabled True
    #Enable Firewall Logging
    Set-NetFireWallProfile -Profile Domain -LogBlocked True -LogMaxSize 20000 -LogFileName "%systemroot%\system32\LogFiles\Firewall\pfirewall.log"
    netsh advfirewall set currentprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log
    netsh advfirewall set currentprofile logging maxfilesize 4096
    netsh advfirewall set currentprofile logging droppedconnections enable
    Write-Host "Firewall logging enabled and configured" -Fore Green
    #Block all inbound connections on Public profile
    netsh advfirewall set publicprofile firewallpolicy blockinboundalways,allowoutbound
    #Enable Windows Defender Network Protection
    powershell.exe Set-MpPreference -EnableNetworkProtection Enabled
    Write-Host "Widnows Defender network protection enabled" -Fore Green
    #Blocks Win32 binaries from making netconns when they shouldn't
    Netsh.exe advfirewall firewall add rule name="Block Notepad netconns" program="%systemroot%\system32\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
    Netsh.exe advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\system32\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
    Netsh.exe advfirewall firewall add rule name="Block Calculator netconns" program="%systemroot%\system32\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
    Netsh.exe advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\system32\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
    Netsh.exe advfirewall firewall add rule name="Block WScript netconns" program="%systemroot%\system32\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
    Netsh.exe advfirewall firewall add rule name="Block CScript netconns" program="%systemroot%\system32\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
    Netsh.exe advfirewall firewall add rule name="Block RunScriptHelper netconns" program="%systemroot%\system32\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
    Netsh.exe advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\system32\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
    Write-Host "Firewall settings updated" -Fore Green
    Write-Host "Current Firewall Settings" -Fore Green
    Get-NetFirewallProfile -policystore activestore
}

#Chrome Settings
function ChomeSettings {
    #Enables Chromes enhanced safe browsing
    reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AdvancedProtectionAllowed" /t REG_DWORD /d 1 /f
    Write-Host "Chrome Enhanced safe browsing enabled" -Fore Green
    #Prevents third party images from showing an authentication prompt; helps prevent phishing
    reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AllowCrossOriginAuthPrompt" /t REG_DWORD /d 0 /f
    Write-Host "CrossOrigin Authentication Prompts disabled for Chrome, Prevents Phishing" -Fore Green
    #Uses HTTPS for DNS requests; encrypts DNS traffic with HTTPS
    reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DnsOverHttpsMode" /t REG_SZ /d on /f
    Write-Host "DNS requests encrypted with HTTPS" -Fore Green
    #Calls to screen share APIs will fail
    reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ScreenCaptureAllowed" /t REG_DWORD /d 0 /f
    #Prevents audio capture through google APIs
    reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AudioCaptureAllowed" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "VideoCaptureAllowed" /t REG_DWORD /d 0 /f
    Write-Host "Third Parties accessing video, audio, and screen capture prevented" -Fore Green
    reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "BlockExternalExtensions" /t REG_DWORD /d 1 /f
    #Audio process for Chrome runs sandboxed;running the audiosubsystem can lead to security risks
    reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AudioSandboxEnabled" /t REG_DWORD /d 1 /f
    Write-Host "Audio Sanbox mode enabled, decreases security risks on Chrome" -Fore Green
    #Sets a minimum valid value for SSL/TLS versions used by Chrome
    reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SSLVersionMin" /t REG_SZ /d tls1 /f
    Write-Host "Minimum valid value for SSL and TLS versions set" -Fore Green
    #Site isolation; loads each website in its own process
    #Even if a site bypasses the same-origin policy, the extra security will help stop the
    #site from stealing your data from another website
    reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SitePerProcess" /t REG_DWORD /d 1 /f
    Write-Host "Site isolation enabled for Chrome" -Fore Green
    net user guest /active:no
    Write-Host "Guest account for Windows Disabled" -Fore Green
    Write-Host "Chrome browser settings updated" -Fore Green
}

#Disables DNS multicast, smart mutli-homed resolution, netbios, powershellv2, printer driver download and printing over http, icmp redirect
#Enables UAC and sets to always notify, Safe DLL loading (DLL Hijacking prevention), saving zone information, explorer DEP, explorer shell protocol protected mode
#Win Settings
function WindowsSettings {
    #Disables the collection of telemtry data
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
    Write-Host "Collection of telemtry data disabled" -Fore Green
    #disables plain text passwords
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
    Write-Host "Use of plain text password disabled" -Fore Green
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
    Write-Host "Remote destop access for Windows Disabled" -Fore Green
    #Disables IGMP;IGMP is used for multicast, multicast in home environments isn't needed and is an increased security risk
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v IGMPLevel /t REG_DWORD /d 0 /f
    Write-Host "IGMP disabled, dependent on Muticast, it isn't need for home environments; increased security risk if enabled" -Fore Green
    #DIsables HTTP from being utilized for printing
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v DisableHTTPPrinting /t REG_DWORD /d 1 /f
    Write-Host "Disables HTTP printing" -Fore Green
    #Allow the computer to ignore NetBIOS name release requests except from WINS servers
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" /v NoNameReleaseOnDemand /t REG_DWORD /d 1 /f
    Write-Host "Ignore NetBIOS name request enabled" -Fore Green
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v PreXPSP2ShellProtocolBehavior /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v DisableWebPnPDownload /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableVirtualization /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v SafeDLLSearchMode /t REG_DWORD /d 1 /f
    Write-Host "Safe DLL search mode enabled" -Fore Green
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v ProtectionMode /t REG_DWORD /d 1 /f
    Write-Host "Protection mode for Windows Enabled" -Fore Green
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableICMPRedirect /t REG_DWORD /d 0 /f
    Write-Host "ICMP redirect has been disabled" -Fore Green
    #Blocks all configured source routed packets;Source routing is an IP option that allows the packet to specify the route it should take to its destination
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f
    Write-Host "IP Source Routing is disabled" -Fore Green
    #Prevents auto connections to open networks and hotspots
    reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v AutoConnectAllowedOEM /t REG_DWORD /d 0 /f
    Write-Host "Auto connect to open networks disabled" -Fore Green
    #Any new automatic internet connection is blocked when the computer has at least one active internet connection to a preferred type of network
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v fMinimizeConnections /t REG_DWORD /d 1 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v SaveZoneInformation /t REG_DWORD /d 2 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoDataExecutionPrevention /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoHeapTerminationOnCorruption /t REG_DWORD /d 0 /f
    #DIsables multicast; not needed in home networks and can lead to security risks
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f
    Write-Host "MultiCast disabled" -Fore Green
    #Disables sending DNS requests across all available network adapters.
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v DisableSmartNameResolution /t REG_DWORD /d 1 /f
    Write-Host "SmartNameResolution disabled" -Fore Green
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v DisableParallelAandAAAA /t REG_DWORD /d 1 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f
    powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -norestart
    powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -norestart
    Write-Host "Windows settings updated" -Fore Green
}

#MS Office Settings
 
#Prevents content such as scripts from being executed over the internet
function ScriptPrevention {
    reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Excel\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
    reg add "HKCU\Software\Policies\Microsoft\Office\16.0\PowerPoint\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
    reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Word\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
    Write-Host "Script prevention for Windows Apps enabled" -Fore Green

}

#Enables integrity checks
function IntegrityChecks {
    BCDEDIT /set nointegritychecks OFF 
    Write-Host "Integrity checks enabled" -Fore Green
}

#Set screen saver inactivity timeout to 15 minutes
function LockoutTime {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v InactivityTimeoutSecs /t REG_DWORD /d 900 /f
    Write-Host "Inactivity lockout time set to 15 minutes" -Fore Green
}

#Enable password prompt on sleep resume while plugged in and on battery
function SleepResume {
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v ACSettingIndex /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v DCSettingIndex /t REG_DWORD /d 1 /f
    Write-Host "Password prompt on sleep resume enabled" -Fore Green
}

#Require encrypted RPC connections to Remote Desktop
function RPCEncryption {
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fEncryptRPCTraffic /t REG_DWORD /d 1 /f
    Write-Host "Encrypted RPC connections" -Fore Green
}

#Prevent sharing of local drives via Remote Desktop Session Hosts
function LDSharing {
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableCdm /t REG_DWORD /d 1 /f

}

#Biometrics
function BiometricSettings {
    #Enable anti-spoofing for facial recognition
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" /v EnhancedAntiSpoofing /t REG_DWORD /d 1 /f
    Write-Host "Anti Spoofing for facial recognition enabled" -Fore Green
    #Disable other camera use while screen is locked
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v NoLockScreenCamera /t REG_DWORD /d 1 /f
    Write-Host "Camera use while screen is locked disabled" -Fore Green
    #Prevent Windows app voice activation while locked
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsActivateWithVoiceAboveLock /t REG_DWORD /d 2 /f
    Write-Host "Windows App voice activition while locked disabled" -Fore Green
    #Prevent Windows app voice activation entirely
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsActivateWithVoice /t REG_DWORD /d 2 /f
    Write-Host "Boimetric settings updated" -Fore Green
}
#Disables unneeded Windows services
function DisableServices {
    C:\WINDOWS\system32\svchost.exe -k LocalServiceNetworkRestricted -p
    C:\WINDOWS\System32\svchost.exe -k utcsvc -p
    C:\WINDOWS\System32\svchost.exe -k LocalSystemNetworkRestricted -p
    C:\WINDOWS\system32\svchost.exe -k netsvcs -p
    C:\WINDOWS\System32\svchost.exe -k NetworkService -p
    C:\WINDOWS\system32\svchost.exe -k LocalService
    C:\WINDOWS\system32\svchost.exe -k LocalSystemNetworkRestricted
    C:\WINDOWS\system32\svchost.exe -k localService -p
    C:\WINDOWS\System32\svchost.exe -k rdxgroup
    C:\WINDOWS\system32\svchost.exe -k netsvcs -p
    C:\WINDOWS\System32\svchost.exe -k LocalServiceNetworkRestricted -p
    C:\WINDOWS\System32\svchost.exe -k WerSvcGroup
    Write-Host "Unneeded Windows services have been disabled" -Fore Green
}

#Disable publishing of Win10 user activity 
function UserActivity{
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 1 /f
    Write-Host "Publishing of Win10 user activity disabled" -Fore Green
}
#------------------------------------------------------------------------
#Manual Mode code below
function UpdateMPSignaturesMan {
    $UserInputOne = Read-Host -Prompt "Update AntiMalware Definitions(MP Signature Update)? y/n"
    if ( $UserInputOne -eq "y" ){
        setx /M MP_FORCE_USE_SANDBOX 1
        Update-MpSignature
        Write-Host "MP Signatures Updated"-Fore Green
    }
    else {
        Write-Host "MP Signatures not Updated" -Fore Red
    }
}
#Enable defender signatures for PUA(Potentially Unwanted Applications)
function EnableDefenderSignaturesMan {    
    $UserInputTwo = Read-Host -Prompt "Enable or Disable defender signatures for PUA(Potential Unwanted Applications)? enable/disable"
    if ( $UserInputTwo -eq "enable" ){
        powershell.exe Set-MpPreference -PUAProtection enable
        Write-Host "Windows Defender signatures enabled; PUA Protection enabled" -Fore Green
    }
    elseif ( $UserInputTwo -eq "disable" ){
        powershell.exe Set-MpPreference -PUAProtection disable
        Write-Host "Windows Defender signatures disabled; PUA Protection disabled" -Fore Red
    }
}
#Enable periodic scanning
function PeriodicScanningMan {  
    $UserInputThree = Read-Host -Prompt "Enable or Disable periodic scanning? enable/disable"
    if ( $UserInputThree -eq "enable"){
        reg add "HKCU\SOFTWARE\Microsoft\Windows Defender" /v PassiveMode /t REG_DWORD /d 2 /f
        Write-Host "Periodic scanning enabled" -Fore Green
    }
    else{
        Write-Host "Periodic scanning not enabled" -Fore Red
    } 
}
#Enable Cloud functionality of Windows Defender
function CloudFunctionalityMan {
    $UserInputFour = Read-Host -Prompt "Enable cloud functionality for Windows Defender? enable/disable"
    if ( $UserInputFour -eq "enable" ){
        powershell.exe Set-MpPreference -MAPSReporting Advanced
        powershell.exe Set-MpPreference -SubmitSamplesConsent 0
        Write-Host "Cloud functinality for Windows Defender enabled" -Fore Green
    }
    else{
        Write-Host "Cloud functionality for Windows Defender not enabled" -Fore Red
    } 
}
#Enables early launch Anti-malware driver
function AntimalDriverMan {
    $UserInputFive = Read-Host -Prompt "Enable early launch anti-malware driver? enable/disable"
    if ($UserInputFive -eq "enable"){
        reg add "HKCU\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" /v DriverLoadPolicy /t REG_DWORD /d 8 /f
        Write-Host "Early launch anti-malware driver enabled" -Fore Green
    }
    else{
        Write-Host "Early launch for anti-malware driver not enabled" -Fore Red
    }
}
#Chrome Settings
function ChomeSettingsMan {
    $UserInputSix = Read-Host -Prompt "Update Chrome settings? y/n"
    if ( $UserInputSix -eq "y"){
        reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ScreenCaptureAllowed" /t REG_DWORD /d 0 /f
        reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AlwaysOpenPdfExternally" /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AudioCaptureAllowed" /t REG_DWORD /d 0 /f
        reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AudioSandboxEnabled" /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "TLS13HardeningForLocalAnchorsEnabled" /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "VideoCaptureAllowed" /t REG_DWORD /d 0 /f
        reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AmbientAuthenticationInPrivateModesEnabled" /t REG_DWORD /d 0 /f
        reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "BlockExternalExtensions" /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DnsOverHttpsMode" /t REG_SZ /d on /f
        reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SSLVersionMin" /t REG_SZ /d tls1 /f
        reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AdvancedProtectionAllowed" /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AllowCrossOriginAuthPrompt" /t REG_DWORD /d 0 /f
        reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SitePerProcess" /t REG_DWORD /d 1 /f
        Write-Host "Chrome browser settings updated" -Fore Green
    }
    else{
        Write-Host "Chrome settings not updated" -Fore Red
    }
}
 
#Prevents content such as scripts from being executed over the internet
function ScriptPreventionMan {
    $UserInputSeven = Read-Host -Prompt "Block scripts from being executed over the internet? y/n"
    if ( $UserInputSeven -eq "y"){
        reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Word\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
        reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Excel\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
        reg add "HKCU\Software\Policies\Microsoft\Office\16.0\PowerPoint\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
        Write-Host "Script prevention for Windows Apps enabled" -Fore Green
    }
    else{
        Write-Host "Script execution from the internet not blocked" -Fore Red
    }
}
#Win Settings
function WindowsSettingsMan {
    $UserInputEight = Read-Host -Prompt "Update Windows settings? y/n"
    if ( $UserInputEight -eq "y" ){
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v DisableSmartNameResolution /t REG_DWORD /d 1 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v DisableParallelAandAAAA /t REG_DWORD /d 1 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v IGMPLevel /t REG_DWORD /d 0 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableICMPRedirect /t REG_DWORD /d 0 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableVirtualization /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v SafeDLLSearchMode /t REG_DWORD /d 1 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v ProtectionMode /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v SaveZoneInformation /t REG_DWORD /d 2 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoDataExecutionPrevention /t REG_DWORD /d 0 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoHeapTerminationOnCorruption /t REG_DWORD /d 0 /f
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v PreXPSP2ShellProtocolBehavior /t REG_DWORD /d 0 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v DisableWebPnPDownload /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v DisableHTTPPrinting /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v AutoConnectAllowedOEM /t REG_DWORD /d 0 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v fMinimizeConnections /t REG_DWORD /d 1 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" /v NoNameReleaseOnDemand /t REG_DWORD /d 1 /f
        reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore" /v Location /t REG_SZ /d Deny /f
        reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
        reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v AllowSearchToUseLocation /t REG_DWORD /d 0 /f
        reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v CortanaConsent /t REG_DWORD /d 0 /f
        powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -norestart
        powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -norestart
        Write-Host "Windows Settings Updated" -Fore Green
    }
    else{
        Write-Host "Windows Settings not updated" -Fore Red
    }
}
#Enables integrity checks
function IntegrityChecksMan {
    $UserInputNine = Read-Host -Prompt "Enable integrity checks? y/n"
    if ( $UserInputNine -eq "y" ){
        BCDEDIT /set nointegritychecks OFF 
        Write-Host "Integrity checks enabled" -Fore Green
    }
    else{
        Write-Host "Integrity checks not enabled" -Fore Red
    }
}
#Set screen saver inactivity timeout to 15 minutes
function LockoutTimeMan {
    $UserInputTen = Read-Host -Prompt "Chnage inactivity timeout? y/n"
    if ( $UserInputTen -eq "y" ){
        $OptionOne = Read-Host -Prompt "Enter how many seconds until inactivty lockout"
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v InactivityTimeoutSecs /t REG_DWORD /d $OptionOne /f
        Write-Host "Inactivity lockout time set to" $OptionOne" seconds" -Fore Green
    }
    else{
        Write-Host "Inactivity timeout not changed" -Fore Red
    }
}
#Enable password prompt on sleep resume while plugged in and on battery
function SleepResumeMan {
    $UserInputEleven = Read-Host -Prompt "Enable password prompt on sleep resume? y/n"
    if ( $UserInputEleven -eq "y" ){
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v ACSettingIndex /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v DCSettingIndex /t REG_DWORD /d 1 /f
        Write-Host "Password prompt on sleep resume enabled" -Fore Green
    }
    else{
        Write-Host "Password prompt on sleep resume not enabled" -Fore Red
    }
}
#Require encrypted RPC connections to Remote Desktop
function RPCEncryptionMan {
    $UserInputTwelve = Read-Host -Prompt "Encrypt RPC Connections? y/n"
    if ( $UserInputTwelve -eq "y" ){
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fEncryptRPCTraffic /t REG_DWORD /d 1 /f
        Write-Host "Encrypted RPC connections" -Fore Green
    }
    else{
        Write-Host "RPC connections not encrypted" -Fore Red
    }
}
#Prevent sharing of local drives via Remote Desktop Session Hosts
function LDSharingMan {
    $UserInputThirteen = Read-Host -Prompt "Local drive sharing via RDP disabled? y/n"
    if ( $UserInputThirteen -eq "y" ){
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableCdm /t REG_DWORD /d 1 /f
        Write-Host "Sharing of local drives via RDP disabled" -Fore Green
    }
    else{
        Write-Host "Local drive sharing via RDP still enabled" -Fore Red
    }
}
#Biometrics
function BiometricSettingsMan {
    $UserInputFourteen = Read-Host -Prompt "Update biometric settings? y/n"
    if ( $UserInputFourteen -eq "y" ){
        #Enable anti-spoofing for facial recognition
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" /v EnhancedAntiSpoofing /t REG_DWORD /d 1 /f
        #Disable other camera use while screen is locked
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v NoLockScreenCamera /t REG_DWORD /d 1 /f
        #Prevent Windows app voice activation while locked
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsActivateWithVoiceAboveLock /t REG_DWORD /d 2 /f
        #Prevent Windows app voice activation entirely
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsActivateWithVoice /t REG_DWORD /d 2 /f
        Write-Host "Boimetric settings updated" -Fore Green
    }
    else{
        Write-Host "Biometric settings not updated" -Fore Red
    }
}
#Enable and configure Windows Firewall
function FirewallSettingsMan {
    $UserInputFifteen = Read-Host -Prompt "Enbale and configure Windows firewall? y/n"
    if ( $UserInputFifteen -eq "y" ){
        NetSh Advfirewall set allprofiles state on
        #Enable Firewall Logging
        netsh advfirewall set currentprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log
        netsh advfirewall set currentprofile logging maxfilesize 4096
        netsh advfirewall set currentprofile logging droppedconnections enable
        Write-Host "Firewall logging configured" -Fore Green
        #Block all inbound connections on Public profile
        netsh advfirewall set publicprofile firewallpolicy blockinboundalways,allowoutbound
        #Enable Windows Defender Network Protection
        powershell.exe Set-MpPreference -EnableNetworkProtection Enabled
        Write-Host "Widnows Defender network protection enabled" -Fore Green
        Netsh.exe advfirewall firewall add rule name="Block Notepad netconns" program="%systemroot%\system32\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
        Netsh.exe advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\system32\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
        Netsh.exe advfirewall firewall add rule name="Block Calculator netconns" program="%systemroot%\system32\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
        Netsh.exe advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\system32\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
        Netsh.exe advfirewall firewall add rule name="Block WScript netconns" program="%systemroot%\system32\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
        Netsh.exe advfirewall firewall add rule name="Block CScript netconns" program="%systemroot%\system32\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
        Netsh.exe advfirewall firewall add rule name="Block RunScriptHelper netconns" program="%systemroot%\system32\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
        Netsh.exe advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\system32\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
        Write-Host "Firewall settings updated" -Fore Green
        Write-Host "Current Firewall Settings" -Fore Green
        #Displays firewall settings
        Get-NetFirewallProfile -policystore activestore
    }
    else{
        Write-Host "Firewall settings not configured" -Fore Red
    }
}
#Enable Windows Defender real time monitoring
function RealTimeMontitoringMan {
    $UserInputSixteen = Read-Host -Prompt "Windows Defender real time monitoring enabled? y/n"
    if ( $UserInputSixteen -eq "y" ){
        powershell.exe -command "Set-MpPreference -DisableRealtimeMonitoring $false"
        Write-Host "Windows defender real time monitoring enabled" -Fore Green
    }
    else{
        Write-Host "Windows defender real time monitoring not enabled" -Fore Red
    }
}
function DisableServicesMan {
    $UserInputEighteen = Read-Host -Prompt "Disable unneeded Windows Services? y/n"
    if ( $UserInputEighteen -eq "y"){
        C:\WINDOWS\system32\svchost.exe -k LocalServiceNetworkRestricted -p
        C:\WINDOWS\System32\svchost.exe -k utcsvc -p
        C:\WINDOWS\System32\svchost.exe -k LocalSystemNetworkRestricted -p
        C:\WINDOWS\system32\svchost.exe -k netsvcs -p
        C:\WINDOWS\System32\svchost.exe -k NetworkService -p
        C:\WINDOWS\system32\fxssvc.exe
        C:\WINDOWS\system32\svchost.exe -k LocalService
        C:\WINDOWS\system32\svchost.exe -k LocalSystemNetworkRestricted
        C:\WINDOWS\system32\svchost.exe -k localService -p
        C:\WINDOWS\System32\svchost.exe -k rdxgroup
        C:\WINDOWS\system32\svchost.exe -k netsvcs -p
        C:\WINDOWS\System32\svchost.exe -k LocalServiceNetworkRestricted -p
        C:\WINDOWS\System32\svchost.exe -k WerSvcGroup
        C:\WINDOWS\system32\svchost.exe -k netsvcs -p
    }
}
#Disable publishing of Win10 user activity 
function UserActivityMan {
    $UserInputSeventeen = Read-Host -Prompt "Disable publishing of Win10 user activity? y/n"
    if ( $UserInputSeventeen -eq "y"){
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 1 /f
        Write-Host "Publishing of Win10 user activity disabled" -Fore Green
    }
}
#------------------------------------------------------------------
function ViewConfiguration {
    Write-Host "---------------------------------------------------------------------------------------"
    Write-Host "This program defends against buffer overflow attacks, Malware injection, eavesdropping, 
    the unauthorized creation, alteration, and destruction of data, 
    denial of service, illegitimate use of data, ICMP flooding, ping of death attack(PoD),
    network probing, Malspam attacks, DLL hijacking"
    Write-Host ""
       Write-Host ------- "Updates the antimalware definitions for Windows Defender
       Enables Windows Defender signatures for potentially unwanted applications
       Enables periodic scanning and cloud functionality for Windows Defender
       Enables the early launch antimalware driver"
       Write-Host "Hardens Chrome web browser settings(Prevents screen, audio, and video capture through Google APIs, 
       blocks external extensions, enables DNS over HTTPS, Advanced protection, website isolation)"
       Write-Host "-------------------------------------------------------------------------------------------"
       Write-Host "Disables content execution from the internet for Windows Apps(Word, Excel, PowerPoint); 
       prevents external scripts from being executed on your device"
       Write-Host "Hardens Windows device settings(Disables multicast, smart name resolution, auto connect,
       HTTP printing, IP source routing, ICMP Redirecting, PSv2/root etc. Enables data execution prevention, protection mode, etc)"
       Write-Host "Disables unneeded Windows Services
       (Connected User Experiences and Telemetry, Distributed Link Tracking Client, Remote Registry, Windows Error Reporting Service)"
       Write-Host "Enables integrity checks
       Sets screen saver inactivity timeout to 15 minutes(Adjustable in the manual mode)
       Enables password prompt on sleep resume
       Enables encryptions for RPC traffic
       Prevents location sharing
       Encrypts DNS request with HTTPS
       Disables sharing of local drives via RDP
       Enables anti-spoofing for facial recognition
       Disables camera use while screen is locked
       Prevents Windows app voice activation when screen is locked
       Configures firewall settings
       Enables firewall logging
       Blocks all inbound connections when on a public profile
       Enables Windows Defender network Protection
       Enables Windows Defender real time monitoring
       Disables publishing of Windows user activity" 
    }
    

function BackupRegistry {
    reg export HKCR C:\ASH\WINREG-Backups\Old\HKCR.REG
    reg export HKCU C:\ASH\WINREG-Backups\Old\HKCU.REG
    reg export HKLM C:\ASH\WINREG-Backups\Old\HKLM.REG
    reg export HKU C:\ASH\WINREG-Backups\Old\HKU.REG
    reg export HKCC C:\ASH\WINREG-Backups\Old\HKCC.REG
    Write-Host "Windows Registry has been backed up before any changes have been made. Backup files can be found in ASH's directory"
}
#Updates any outdated drivers
function UpdateDrivers {
    $UpdateSvc = New-Object -ComObject Microsoft.Update.ServiceManager
    $UpdateSvc.AddService2("7971f918-a847-4430-9279-4a52d1efe18d",7,"")
    $Session = New-Object -ComObject Microsoft.Update.Session
    $Searcher = $Session.CreateUpdateSearcher() 

    $Searcher.ServiceID = '7971f918-a847-4430-9279-4a52d1efe18d'
    $Searcher.SearchScope =  1 # MachineOnly
    $Searcher.ServerSelection = 3 # Third Party
          
    $Criteria = "IsInstalled=0 and Type='Driver'"
    Write-Host('Searching Driver-Updates...') -Fore Green     
    $SearchResult = $Searcher.Search($Criteria)          
    $Updates = $SearchResult.Updates
    if([string]::IsNullOrEmpty($Updates)){
        Write-Host "No pending driver updates."
    }
    else {
    #Show available Drivers...
        $Updates | Select-Object Title, DriverModel, DriverVerDate, Driverclass, DriverManufacturer | Format-List
        $UpdatesToDownload = New-Object -Com Microsoft.Update.UpdateColl
        $updates | ForEach-Object { $UpdatesToDownload.Add($_) | out-null }
        Write-Host('Downloading Drivers...')  -Fore Green
        $UpdateSession = New-Object -Com Microsoft.Update.Session
        $Downloader = $UpdateSession.CreateUpdateDownloader()
        $Downloader.Updates = $UpdatesToDownload
        $Downloader.Download()
        $UpdatesToInstall = New-Object -Com Microsoft.Update.UpdateColl
        $updates | ForEach-Object { if($_.IsDownloaded) { $UpdatesToInstall.Add($_) | out-null } }

        Write-Host('Installing Drivers...')  -Fore Green
        $Installer = $UpdateSession.CreateUpdateInstaller()
        $Installer.Updates = $UpdatesToInstall
        $InstallationResult = $Installer.Install()
        if($InstallationResult.RebootRequired) { 
            Write-Host('Reboot required! Please reboot now.') -Fore Red
        } 
        else { Write-Host('Done.') -Fore Green }
        $updateSvc.Services | Where-Object { $_.IsDefaultAUService -eq $false -and $_.ServiceID -eq "7971f918-a847-4430-9279-4a52d1efe18d" } | ForEach-Object { $UpdateSvc.RemoveService($_.ServiceID) }
    }
}
#Deletes temporary files, cleans trash bin,
function DiskCleanup {
    $objShell = New-Object -ComObject Shell.Application   
    $objFolder = $objShell.Namespace(0xA)   
      
    $temp = get-ChildItem "env:\TEMP"   
    $temp2 = $temp.Value   
      
    $WinTemp = "c:\Windows\Temp\*"   
      
 
  
# Remove temp files located in "C:\Users\USERNAME\AppData\Local\Temp"   
    write-Host "Removing Junk files in $temp2." -ForegroundColor Magenta    
    Remove-Item -Recurse  "$temp2\*" -Force -Verbose   
     
    write-Host "Emptying Recycle Bin." -ForegroundColor Cyan    
    $objFolder.items() | ForEach-Object{ remove-item $_.path -Recurse -Confirm:$false}   
      
# Remove Windows Temp Directory    
    write-Host "Removing Junk files in $WinTemp." -ForegroundColor Green   
    Remove-Item -Recurse $WinTemp -Force    
      
# Running Disk Clean up Tool    
    write-Host "Finally now, Running Windows disk Clean up Tool" -ForegroundColor Cyan   
    cleanmgr /sagerun:1 | out-Null    
       
    $([char]7)   
    Start-Sleep 1    
    $([char]7)   
    Start-Sleep 1        
    
    write-Host "Clean Up Task Finished!"
}
function BackupRegistryUpdated {
    Write-Host "Backing up changes to Windows Registry"
    reg export HKCR C:\ASH\WINREG-Backups\SystemHardened\HKCR.REG
    reg export HKCU C:\ASH\WINREG-Backups\SystemHardened\HKCU.REG
    reg export HKLM C:\ASH\WINREG-Backups\SystemHardened\HKLM.REG
    reg export HKU C:\ASH\WINREG-Backups\SystemHardened\HKU.REG
    reg export HKCC C:\ASH\WINREG-Backups\SystemHardened\HKCC.REG
    Write-Host "Changes to Windows Registry have been recorded"
}

function Intro {
    Write-Host "This program automates system hardening and makes your Windows device more secure. "
    Write-Host ""
    Write-Host "It prioritizes security but still ensures your Windows Device will remain completely functional
    without the need of having to do future troubleshooting."
    Write-Host ""
    $BackupRegOption = Read-Host -Prompt "Before continuing it is recommended to backup the Windows Registry, would you like to? y/n"
    if ( $BackupRegOption -eq "y" ){
        BackupRegistry
        Mode

    }
    Write-Host ""
    Write-Host "---------------------------------------------------------------------"
    Write-Host ""
}

function Mode{
    Write-Host "--------------------------------------------------------------------"
    $Global:MainOption = Read-Host -Prompt "Type 'ASH' to start system hardening 
    Type 'v' to view the changes this program will make 
    Type 'r' to restore Windows Registry from backup 
    Type 'c' to delete temporary and junk files"
    if ( $Global:MainOption -eq "ASH" ){
        $ModeChoice = Read-Host -Prompt "Choose hardening mode: Automated or Manual? a/m"
        if ( $ModeChoice -eq "A" ){
            UpdateMPSignatures
            EnableDefenderSignatures
            PeriodicScanning
            CloudFunctionality
            AntimalDriver
            ChomeSettings
            ScriptPrevention
            WindowsSettings
            LockoutTime
            SleepResume
            RPCEncryption
            LDSharing
            BiometricSettings
            FirewallSettings
            RealTimeMontitoring
            DisableServices
            UserActivity
            BackupRegistryUpdated
            UpdateDrivers
            Write-Host "Scanning for corrupted files"
            sfc /scannow
            Write-Host "Conducting a full scan of your device for malware"
            start-mpscan -scantype fullscan
        }
        elseif ( $ModeChoice -eq "M" ){
            UpdateMPSignaturesMan
            EnableDefenderSignaturesMan
            PeriodicScanningMan
            CloudFunctionalityMan
            AntimalDriverMan
            ChomeSettingsMan
            ScriptPreventionMan
            WindowsSettingsMan
            LockoutTimeMan
            SleepResumeMan
            RPCEncryptionMan
            LDSharingMan
            BiometricSettingsMan
            FirewallSettingsMan
            RealTimeMontitoringMan
            DisableServicesMan
            UserActivityMan
            BackupRegistryUpdated
            UpdateDrivers
            sfc /scannow
            start-mpscan -scantype fullscan
        }
    }
    elseif ( $Global:MainOption -eq "v" ){
        ViewConfiguration
        Mode
    }
    elseif ( $Global:MainOption -eq "r" ){
        reg import C:\ASH\WINREG-Backups\Old\HKCR.REG
        reg import C:\ASH\WINREG-Backups\Old\HKCU.REG
        reg import C:\ASH\WINREG-Backups\Old\HKLM.REG
        reg import C:\ASH\WINREG-Backups\Old\HKU.REG
        reg import C:\ASH\WINREG-Backups\Old\HKCC.REG
        Write-Host "Windows Registry has been restored from backup"
        Mode
    }
    elseif ( $Global:MainOption -eq "c" ){
        DiskCleanup
        Mode
    }
}
function Main {
    Intro
    Mode
    
}

Main