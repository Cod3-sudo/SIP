
function UpdateMPSignatures {
    setx /M MP_FORCE_USE_SANDBOX 1
    Update-MpSignature
    Write-Host "MP Signatures Updated"
}
#Enable defender signatures for PUA(Potentially Unwanted Applications)
function EnableDefenderSignatures {    
    powershell.exe Set-MpPreference -PUAProtection enable
    Write-Host "Windows Defender signatures enabled; PUA Protection enabled"
}
#Enable periodic scanning
function PeriodicScanning {  
    reg add "HKCU\SOFTWARE\Microsoft\Windows Defender" /v PassiveMode /t REG_DWORD /d 2 /f
    Write-Host "Periodic scanning enabled"
}
#Enable Cloud functionality of Windows Defender
function CloudFunctionality {
    powershell.exe Set-MpPreference -MAPSReporting Advanced
    powershell.exe Set-MpPreference -SubmitSamplesConsent 0
    Write-Host "Cloud functinality for Windows Defender enabled"
}
#Enables early launch Anti-malware driver
function AntimalDriver {
    reg add "HKCU\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" /v DriverLoadPolicy /t REG_DWORD /d 8 /f
    Write-Host "Early launch anti-malware driver enabled"
}
#Chrome Settings
function ChomeSettings {
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
    Write-Host "Chrome browser settings updated"
}
#MS Office Settings
 
#Prevents content such as scripts from being executed over the internet
function ScriptPrevention {
    reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Word\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
    reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Excel\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
    reg add "HKCU\Software\Policies\Microsoft\Office\16.0\PowerPoint\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
    Write-Host "Script prevention for Windows Apps enabled"

}
#Win Settings
function WindowsSettings {
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
    powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -norestart
    powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -norestart
    Write-Host "Windows settings updated"
}
#Enables integrity checks
function IntegrityChecks {
    BCDEDIT /set nointegritychecks OFF 
    Write-Host "Integrity checks enabled"
}
#Set screen saver inactivity timeout to 15 minutes
function LockoutTime {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v InactivityTimeoutSecs /t REG_DWORD /d 900 /f
    Write-Host "Inactivity lockout time set to 15 minutes"
}
#Enable password prompt on sleep resume while plugged in and on battery
function SleepResume {
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v ACSettingIndex /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v DCSettingIndex /t REG_DWORD /d 1 /f
    Write-Host "Password prompt on sleep resume enabled"
}
#Require encrypted RPC connections to Remote Desktop
function RPCEncryption {
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fEncryptRPCTraffic /t REG_DWORD /d 1 /f
    Write-Host "Encrypted RPC connections"
}
#Prevent sharing of local drives via Remote Desktop Session Hosts
function LDSharing {
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableCdm /t REG_DWORD /d 1 /f

}
#Biometrics
function BiometricSettings {
    #Enable anti-spoofing for facial recognition
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" /v EnhancedAntiSpoofing /t REG_DWORD /d 1 /f
    #Disable other camera use while screen is locked
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v NoLockScreenCamera /t REG_DWORD /d 1 /f
    #Prevent Windows app voice activation while locked
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsActivateWithVoiceAboveLock /t REG_DWORD /d 2 /f
    #Prevent Windows app voice activation entirely
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsActivateWithVoice /t REG_DWORD /d 2 /f
    Write-Host "Boimetric settings updated"
}
#Enable and configure Windows Firewall
function FirewallSettings {
    NetSh Advfirewall set allprofiles state on
    #Enable Firewall Logging
    netsh advfirewall set currentprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log
    netsh advfirewall set currentprofile logging maxfilesize 4096
    netsh advfirewall set currentprofile logging droppedconnections enable
    Write-Host "Firewall logging configured"
    #Block all inbound connections on Public profile
    netsh advfirewall set publicprofile firewallpolicy blockinboundalways,allowoutbound
    #Enable Windows Defender Network Protection
    powershell.exe Set-MpPreference -EnableNetworkProtection Enabled
    Write-Host "Widnows Defender network protection enabled"
    Write-Host "Firewall settings updated"
}
#Enable Windows Defender real time monitoring
function RealTimeMontitoring {
    powershell.exe Set-MpPreference -DisableRealtimeMonitoring 0
    reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 0 /f
    Write-Host "Windows defender real time monitoring enabled"
}
#Disable publishing of Win10 user activity 
function UserActivity {
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 1 /f
    Write-Host "Publishing of Win10 user activity disabled"
}
Set-ExecutionPolicy unrestricted 

#------------------------------------------------------------------------
function UpdateMPSignaturesMan {
    $UserInputOne = Read-Host -Prompt "Update AntiMalware Definitions(MP Signature Update)? y/n"
    if ( $UserInputOne -eq "y" ){
        setx /M MP_FORCE_USE_SANDBOX 1
        Update-MpSignature
        Write-Host "MP Signatures Updated"
    }
    else {
        Write-Host "MP Signatures not Updated"
    }
}
#Enable defender signatures for PUA(Potentially Unwanted Applications)
function EnableDefenderSignaturesMan {    
    $UserInputTwo = Read-Host -Prompt "Enable or Disable defender signatures for PUA(Potential Unwanted Applications)? enable/disable"
    if ( $UserInputTwo -eq "enable" ){
        powershell.exe Set-MpPreference -PUAProtection enable
        Write-Host "Windows Defender signatures enabled; PUA Protection enabled"
    }
    elseif ( $UserInputTwo -eq "disable" ){
        powershell.exe Set-MpPreference -PUAProtection disable
        Write-Host "Windows Defender signatures enabled; PUA Protection disabled"
    }
}
#Enable periodic scanning
function PeriodicScanningMan {  
    $UserInputThree = Read-Host -Prompt "Enable or Disable periodic scanning? enable/disable"
    if ( $UserInputThree -eq "enable"){
        reg add "HKCU\SOFTWARE\Microsoft\Windows Defender" /v PassiveMode /t REG_DWORD /d 2 /f
        Write-Host "Periodic scanning enabled"
    }
    else{
        Write-Host "Periodic scanning not enabled"
    } 
}
#Enable Cloud functionality of Windows Defender
function CloudFunctionalityMan {
    $UserInputFour = Read-Host -Prompt "Enable cloud functionality for Windows Defender? enable/disable"
    if ( $UserInputFour -eq "enable" ){
        powershell.exe Set-MpPreference -MAPSReporting Advanced
        powershell.exe Set-MpPreference -SubmitSamplesConsent 0
        Write-Host "Cloud functinality for Windows Defender enabled"
    }
    else{
        Write-Host "Cloud functionality for Windows Defender not enabled"
    } 
}
#Enables early launch Anti-malware driver
function AntimalDriverMan {
    $UserInputFive = Read-Host -Prompt "Enable early launch anti-malware driver? enable/disable"
    if ($UserInputFive -eq "enable"){
        reg add "HKCU\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" /v DriverLoadPolicy /t REG_DWORD /d 8 /f
        Write-Host "Early launch anti-malware driver enabled"
    }
    else{
        Write-Host "Early launch for anti-malware driver not enabled"
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
        Write-Host "Chrome browser settings updated"
    }
    else{
        Write-Host "Chrome settings not updated"
    }
}
 
#Prevents content such as scripts from being executed over the internet
function ScriptPreventionMan {
    $UserInputSeven = Read-Host -Prompt "Block scripts from being executed over the internet? y/n"
    if ( $UserInputSeven -eq "y"){
        reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Word\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
        reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Excel\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
        reg add "HKCU\Software\Policies\Microsoft\Office\16.0\PowerPoint\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
        Write-Host "Script prevention for Windows Apps enabled"
    }
    else{
        Write-Host "Script execution from the internet not blocked"
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
        powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -norestart
        powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -norestart
        Write-Host "Windows Settings Updated"
    }
    else{
        Write-Host "Windows Settings not updated"
    }
}
#Enables integrity checks
function IntegrityChecksMan {
    $UserInputNine = Read-Host -Prompt "Enable integrity checks? y/n"
    if ( $UserInputNine -eq "y" ){
        BCDEDIT /set nointegritychecks OFF 
        Write-Host "Integrity checks enabled"
    }
    else{
        Write-Host "Integrity checks not enabled"
    }
}
#Set screen saver inactivity timeout to 15 minutes
function LockoutTimeMan {
    $UserInputTen = Read-Host -Prompt "Chnage inactivity timeout? y/n"
    if ( $UserInputTen -eq "y" ){
        $OptionOne = Read-Host -Prompt "Enter how many seconds until inactivty lockout"
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v InactivityTimeoutSecs /t REG_DWORD /d $OptionOne /f
        Write-Host "Inactivity lockout time set to 15 minutes"
    }
    else{
        Write-Host "Inactivity timeout not changed"
    }
}
#Enable password prompt on sleep resume while plugged in and on battery
function SleepResumeMan {
    $UserInputEleven = Read-Host -Prompt "Enable password prompt on sleep resume? y/n"
    if ( $UserInputEleven -eq "y" ){
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v ACSettingIndex /t REG_DWORD /d 1 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v DCSettingIndex /t REG_DWORD /d 1 /f
        Write-Host "Password prompt on sleep resume enabled"
    }
    else{
        Write-Host "Password prompt on sleep resume not enabled"
    }
}
#Require encrypted RPC connections to Remote Desktop
function RPCEncryptionMan {
    $UserInputTwelve = Read-Host -Prompt "Encrypt RPC Connections? y/n"
    if ( $UserInputTwelve -eq "y" ){
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fEncryptRPCTraffic /t REG_DWORD /d 1 /f
        Write-Host "Encrypted RPC connections"
    }
    else{
        Write-Host "RPC connections not encrypted"
    }
}
#Prevent sharing of local drives via Remote Desktop Session Hosts
function LDSharingMan {
    $UserInputThirteen = Read-Host -Prompt "Local drive sharing via RDP disabled? y/n"
    if ( $UserInputThirteen -eq "y" ){
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableCdm /t REG_DWORD /d 1 /f
        Write-Host "Sharing of local drives via RDP disabled"
    }
    else{
        Write-Host "Local drive sharing via RDP still enabled"
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
        Write-Host "Boimetric settings updated"
    }
    else{
        Write-Host "Biometric settings not updated"
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
        Write-Host "Firewall logging configured"
        #Block all inbound connections on Public profile
        netsh advfirewall set publicprofile firewallpolicy blockinboundalways,allowoutbound
        #Enable Windows Defender Network Protection
        powershell.exe Set-MpPreference -EnableNetworkProtection Enabled
        Write-Host "Widnows Defender network protection enabled"
        Write-Host "Firewall settings updated"
    }
    else{
        Write-Host "Firewall settings not configured"
    }
}
#Enable Windows Defender real time monitoring
function RealTimeMontitoringMan {
    $UserInputSixteen = Read-Host -Prompt "Windows Defender real time monitoring enabled? y/n"
    if ( $UserInputSixteen -eq "y" ){
        powershell.exe -command "Set-MpPreference -DisableRealtimeMonitoring $false"
        reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 0 /f
        Write-Host "Windows defender real time monitoring enabled"
    }
    else{
        Write-Host "Windows defender real time monitoring not enabled"
    }
}
#Disable publishing of Win10 user activity 
function UserActivityMan {
    $UserInputSeventeen = Read-Host -Prompt "Disable publishing of Win10 user activity? y/n"
    if ( $UserInputSeventeen -eq "y"){
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 1 /f
        Write-Host "Publishing of Win10 user activity disabled"
    }
}
function Main {
    Write-Host "This program automates system hardening and makes your Windows device more secure. "

    $Mode_Choice = Read-Host -Prompt "Choose hardening mode: Automated or Manual"
    
    if ( $Mode_Choice -eq "Automated" ){
        UpdateMPSignatures
        EnableDefenderSignatures
        PeriodicScanning
        CloudFunctionality
        AntimalDriver
        ChomeSettings
        ScriptPrevention
        WindowsSettings
        IntegrityChecks
        LockoutTime
        SleepResume
        RPCEncryption
        LDSharing
        BiometricSettings
        FirewallSettings
        RealTimeMontitoring
        UserActivity
    }
    elseif ( $Mode_Choice -eq "Manual" ){
        UpdateMPSignaturesMan
        EnableDefenderSignaturesMan
        PeriodicScanningMan
        CloudFunctionalityMan
        AntimalDriverMan
        ChomeSettingsMan
        ScriptPreventionMan
        WindowsSettingsMan
        IntegrityChecksMan
        LockoutTimeMan
        SleepResumeMan
        RPCEncryptionMan
        LDSharingMan
        BiometricSettingsMan
        FirewallSettingsMan
        RealTimeMontitoringMan
        UserActivityMan
    }
}
Main