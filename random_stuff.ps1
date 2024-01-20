Function Test-Admin {

    $CurrentUser = New-Object -TypeName Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $CurrentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

}  # End Function Test-Admin
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri https://raw.githubusercontent.com/0x6d69636b/windows_hardening/master/HardeningKitty.psm1 -OutFile HardeningKitty.psm1
Invoke-WebRequest -Uri https://raw.githubusercontent.com/0x6d69636b/windows_hardening/master/HardeningKitty.psd1 -OutFile HardeningKitty.psd1
Invoke-WebRequest -Uri https://raw.githubusercontent.com/scipag/HardeningKitty/master/lists/finding_list_0x6d69636b_machine.csv -OutFile finding_list_0x6d69636b_machine.csv
Invoke-WebRequest -Uri https://raw.githubusercontent.com/scipag/HardeningKitty/master/lists/finding_list_cis_microsoft_windows_server_2022_22h2_2.0.0_machine.csv -OutFile finding_list_cis_microsoft_windows_server_2022_22h2_2.csv
Invoke-WebRequest -Uri https://raw.githubusercontent.com/scipag/HardeningKitty/master/lists/finding_list_cis_microsoft_windows_10_enterprise_22h2_machine.csv -OutFile finding_list_cis_microsoft_windows_10_enterprise_22h2_machine.csv

If ((Test-Admin) -eq $False) {

    If ($Elevated) {
        Write-Output "[*] Tried to elevate, did not work, aborting"

    }  # End Else
    Else {

        Start-Process -FilePath "C:\Windows\System32\powershell.exe" -Verb RunAs -ArgumentList ('-NoProfile -NoExit -File "{0}" -Elevated' -f ($myinvocation.MyCommand.Definition))

    }  # End Else

    Exit

}  # End If


Write-Output "BEGINING EXECUTION OF SCRIPT TO HARDEN A WINDOWS 10 MACHINE NOT JOINED TO A DOMAIN"

# WDIGEST CACHE
Write-Output "[*] Disabling WDigest credentials caching. More info here: https://www.stigviewer.com/stig/windows_10/2017-02-21/finding/V-71763"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest" -Name UseLogonCredential -Value 0 -Force
ipconfig /flushdns
sc.exe config RemoteRegistry start= disabled
# AUTOLOGIN PASSWORD
$AutoLoginPassword = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" | Select-Object -Property "DefaultUserName","DefaultPassword"
If (($AutoLoginPassword).DefaultPassword) {

    Write-Output "[!] Auto Login Credentials Found: "
    Write-Output " $AutoLoginPassword"

    Write-Output "[*] Sometimes it is required to allow a computer to auto logon. To secure the above password use this tool to ensure the password is hashed/obfuscated and not stored in clear text:  `nhttps://docs.microsoft.com/en-us/sysinternals/downloads/autologon"
    $Remediate = Read-Host -Prompt "Would you like to disable auto-logon? [y/N]"
    If ($Remediate -like "y*") {

        $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

        Set-ItemProperty -Path $RegPath -Name AutoAdminLogon -Value 0
        Set-ItemProperty -Path $RegPath -Name DefaultUserName -Value $Null
        Set-ItemProperty -Path $RegPath -Name DefaultPassword -Value $Null

    }  # End If

}  # End If
Else {

    Write-Output "[*] Great work! You are not using auto-logon"

}  # End Else


# ALWAYS INSTALL ELEVATED
If (((Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\Installer").AlwaysInstallElevated) -eq 1) {

    Write-Output "[*] Device is vulnerable to AlwaysInstallElevated priviliege escalation. Mitigating threat. Read more here if desired: https://docs.microsoft.com/en-us/windows/win32/msi/alwaysinstallelevated"
    reg add "HKLM\Software\Policies\Microsoft\Windows\Installer" /v "AlwaysInstallElevated" /t REG_DWORD /d 0 /f

}  # End If
Else {

    Write-Output "[*] EXCELLENT: Target is not vulnerable to AlwaysInstallElevated PrivEsc method "

}  # End Else

# WSUS
Write-Output "[*] Checking for WSUS updates allowed over HTTP for PrivEsc"
If (((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -ErrorAction "SilentlyContinue") -eq 1) -and (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -ErrorAction "SilentlyContinue" -Contains "http://")) {

    Write-Output "[!] Target is vulnerable to HTTP WSUS updates. Configure your update server to use HTTPS only if you must have it custom defined. `n EXPLOIT: https://github.com/pimps/wsuxploit"

}  # End If
Else {

    Write-Output "[*] $env:COMPUTERNAME is not vulnerable to WSUS using HTTP."

}  # End Else

# SSDP
Write-Output "[*] Disabling the SSDP Service"
Stop-Service -Name "SSDPSRV" -Force -ErrorAction SilentlyContinue
Set-Service -Name "SSDPSRV" -StartupType Disabled
Disable-NetFirewallRule -DisplayName "Network Discovery*"

# SMB
Write-Output '[*] Disabling SMB version 1'
Set-SmbServerConfiguration -EnableSMB1Protocol $False -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" SMB1 -Type DWord -Value 0

Write-Output '[*] Enabling SMBv2 and SMBv3'
Set-SmbServerConfiguration -EnableSMB2Protocol $True -Force

Write-Output '[*] Enabling SMB Signing'
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkStation\Parameters" -Name RequireSecuritySignature -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
New-Item -Path "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkStation\Parameters" -Name EnableSecuritySignature -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
New-Item -Path "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name RequireSecuritySignature -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
New-Item -Path "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name EnableSecuritySignature -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null

Write-Output "[*] Blocking a few common ports attackers may use with reverse shells."
New-NetFirewallRule -DisplayName "Disallow Common Ports That Attackers Use" -Direction "Outbound" -LocalPort 1336,1337,1338,1339,4444,4445,4446,4447,4448,4449 -Protocol "TCP" -Action Block
New-NetFirewallRule -DisplayName "Disallow Common Ports That Attackers Use" -Direction "Outbound" -LocalPort 1336,1337,1338,1339,4444,4445,4446,4447,4448,4449 -Protocol "UDP" -Action Block

Write-Output "[*] Disabling SMBv3 Compression"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name DisableCompression -Value 1 -ItemType DWORD -Force

# DNS
Write-Output "[*] Enabling DNS over HTTPS for all Windows applications"
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name EnableAutoDOH -PropertyType DWORD -Value 2 -Force

Write-Output "[*] Disable the use of the LMHOSTS File"
Invoke-CimMethod -Namespace root/CIMV2 -ClassName Win32_NetworkAdapterConfiguration -MethodName EnableWINS -Arguments @{ DNSEnabledForWINSResolution = $False; WINSEnableLMHostsLookup = $False }

Write-Output "[*] Disabling the use of NetBIOS"
$CIMInstance = Get-CimInstance -Namespace "root/CIMV2" -ClassName "Win32_NetworkAdapterConfiguration"
$CIMInstance | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=2} | Out-Null

# RDP
Write-Output "[*] Disabling Remote Assistance"
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v UserAuthentication /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableLPT /t REG_DWORD /d 1 /f
#https://serverfault.com/questions/617699/difference-between-hklm-software-policies-and-hklm-system-currentcontrolset

$Answer3 = Read-Host -Prompt "Would you like to allow remote access to your computer? [y/N]"
    If ($Answer3 -like "y*") {

        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 0
        Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

        Write-Output "Enabling NLA on $env:COMPUTERNAME. This setting can be seen under 'View Advanced System Settings' under the 'Remote' Tab"
        $NLAinfo = Get-CimInstance -ClassName Win32_TSGeneralSetting -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'"
        $NLAinfo | Invoke-CimMethod -MethodName SetUserAuthenticationRequired -Arguments @{ UserAuthenticationRequired = $True }

        $TSSetting = Get-CimInstance -Namespace root/cimv2/TerminalServices -ClassName Win32_TerminalServiceSetting
        $TSGeneralSetting = Get-CimInstance -Namespace root/cimv2/TerminalServices -ClassName Win32_TSGeneralSetting
        $TSSetting | Invoke-CimMethod -MethodName SetAllowTSConnections -Arguments @{AllowTSConnections=1;ModifyFirewallException=1}
        $TSGeneralSetting | Invoke-CimMethod -MethodName SetUserAuthenticationRequired -Arguments @{UserAuthenticationRequired=1}

    }  # End If
    ElseIf ($Answer3 -like "n*") {

        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 1
        Disable-NetFirewallRule -DisplayGroup "Remote Desktop"

    }  # End ElseIf


# SSL
Write-Output "[*] Disabling outdated SSL ciphers. I was leniant to still allow for possible legacy applications"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_3DES_EDE_CBC_SHA"

Write-Output "[*] Disabling weak outdated protocols"
# NULL Ciphers
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL' -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
# DES Ciphers
(Get-Item -Path 'HKLM:\').OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('DES 56/56')
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56' -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
(Get-Item -Path 'HKLM:\').OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('Triple DES 168/168')
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168' -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
# RC4 Ciphers
(Get-Item -Path 'HKLM:\').OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('RC4 40/128')
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128' -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
(Get-Item -Path 'HKLM:\').OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('RC4 56/128')
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128' -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
(Get-Item -Path 'HKLM:\').OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('RC4 64/128')
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128' -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
(Get-Item -Path 'HKLM:\').OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('RC4 128/128')
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128' -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
# ENABLING AES
(Get-Item -Path 'HKLM:\').OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('AES 128/128')
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128' -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null
(Get-Item -Path 'HKLM:\').OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('AES 256/256')
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256' -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null
# SSL2
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Force | Out-Null
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name 'DisabledByDefault' -value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name 'DisabledByDefault' -value '1' -PropertyType 'DWord' -Force | Out-Null
# SSL3
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Force | Out-Null
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null
# TLS 1.0
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force | Out-Null
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null
# ENABLING TLS 1.1 and 1.2
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force | Out-Null
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force | Out-Null
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
# POWERSHELL DOWNGRADE
Write-Output "[*] Removing outdated PowerShell version 2"
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -Remove


# UNQUOTED SERVICE PATHS
$UnquotedServicePaths = Get-CimInstance -ClassName "Win32_Service" -Property "Name","DisplayName","PathName","StartMode" | Where-Object { $_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*' } | Select-Object -Property "PathName","DisplayName","Name"

If ($UnquotedServicePaths) {

    Write-Output "Unquoted Service Path(s) have been found"

    $UnquotedServicePaths | Select-Object -Property PathName,DisplayName,Name | Format-List -GroupBy Name
    Write-Output "[*] Modify the above registry values so double or single quotes surround the defined file path locations"

}  # End If
Else {

    Write-Output "[*] $env:COMPUTERNAME does not contain any unquoted service paths"

}  # End Else

# EXTRANEOUS SERVICES
Write-Output "[*] Disabling receommended unused services"
$Services = "BTAGService","bthserv","Browser","MapsBroker","lfsvc","IISADMIN","irmon","SharedAccess","lltdsvc","LxssManager","FTPSVC","MSiSCSI","sshd","PNRPsvc","p2psvc","PNRPAutoReg","Spooler","wercplsupport","RasAuto","SessionEnv","TermService","UmRdpService","RpcLocator","RemoteRegistry","RemoteAccess","LanmanServer","simptcp","SNMP","sacsvr","SSDPSRV","upnphost","WMSvc","WerSvc","Wecsvc","WMPNetworkSvc","icssvc","WpnService","PushToInstall","WinRM","W3SVC","XboxGipSvc","XblAuthManager","XblGameSave","XboxNetApiSvc"
Stop-Service -Name $Services
$Services | ForEach-Object { Set-Service -Name $_ -StartupType Disabled }

Write-Output "[*] Enabling and Hardening Firewall"

# FIREWALL LOG FILES
Write-Output "[*] Defining log file locations for Public, Domain, and Private firewall connections"
$FirewallLogFiles = "C:\Windows\System32\LogFiles\Firewall\domainfw.log","C:\Windows\System32\LogFiles\Firewall\domainfw.log.old","C:\Windows\System32\LogFiles\Firewall\privatefw.log","C:\Windows\System32\LogFiles\Firewall"
New-Item -Path $Path -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

$Acl = Get-Acl -Path $FirewallLogFiles
$Acl.SetAccessRuleProtection($True, $False)
$PermittedUsers = @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators', 'BUILTIN\Network Configuration Operators', 'NT SERVICE\MpsSvc')
ForEach ($User in $PermittedUsers) {

  $Permission = $User, 'FullControl', 'Allow'
  $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $Permission
  $Acl.AddAccessRule($AccessRule)

}  # End ForEach

$Acl.SetOwner((New-Object -TypeName System.Security.Principal.NTAccount('BUILTIN\Administrators')))
$Acl | Set-Acl -Path $FirewallLogFiles

# GROUP MEMBERSHIP
Write-Output "[*] Enabling UAC on all processes that require elevation"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2

Write-Output "[*] Checking if current user is a member of the local Administrators group"
If ((Get-LocalGroupMember -Group "Administrators").Name -Contains "$env:COMPUTERNAME\$env:USERNAME") {

    Write-Output "[*] It is considered best practice to log into Windows using a user account that does not have Administrative priviledge. If you wish to continue doing what you are doing it is not critical to adapt to this suggestion"

    $Answer1 = Read-Host -Prompt "Would you like to create a user account to sign into Windows with from now on and use the $env:USERNAME account and password whenever you need to elevate privilege? [y/N]"
    If ($Answer1 -like "y*") {

        $FullName = Read-Host -Prompt "What is the full name of the user who will use this account"
        $Name = Read-Host -Prompt "What should the account Name be? EXAMPLE: John Smith"
        $Description = Read-Host -Prompt "Add a description for this user account if you like. Feel free to leave blank"

        Write-Output "[*] Creating the $Name user account"
        New-LocalUser -FullName $FullName -Name $Name -Description $Description -Password (Read-Host -Prompt "Set the password for the account" -AsSecureString)

        Write-Output "[*] Adding $Name to the local Users group"
        Add-LocalGroupMember -Group "Users" -Member "$Name"

    }  # End If

}  # End If

Write-Host "[*] Disabling all system default accounts"

# PASSWORD VAULT
[Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
$Vault = New-Object -TypeName Windows.Security.Credentials.PasswordVault
$Vault.RetrieveAll()

#$Answer2 = Read-Host -Prompt "[*] If you see any saved passwords in the output above it is because they credentials are most likely saved by Internet Explorer. Would you like to clear these clear text passwords? This only affects the Internet Explorer browser [y/N]"
$Answer2 = "y"
If ($Answer2 -like "y*") {

    Write-Output "[*] Deleting clear text credentials from the Windows Password Vault"
    ForEach ($V in $Vault) {

        $Cred = New-Object -TypeName Windows.Security.Credentials.PasswordCredential
        $Cred.Resource = $V.RetrieveAll().Resource
        $Cred.UserName = $V.RetrieveAll().UserName
        $V.Remove($Cred)

    }  # End ForEach

}  # End If
reg add "HKLM\System\CurrentControlSet\Services\mpssvc" /v "Start" /t REG_DWORD /d 2 /f
sc.exe config mpssvc start= auto
start-service mpssvc

# LOGGING
If ($PSVersionTable.PSVersion.Major -lt 5) {

    $PSProfile = "C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1"
    New-Item -Path $PSProfile -ItemType File -Force
    Add-Content -Path $PSProfile -Value '$LogCommandHealthEvent = $true'
    Add-Content -Path $PSProfile -Value '$LogCommandLifecycleEvent = $true'
    Add-Content -Path $PSProfile -Valuie '$LogPipelineExecutionDetails= $true'

}  # End If

Write-Output "[*] Enabling Command Line Logging"
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1

Write-Output "[*] Ensure PowerShell versions 4 and 5 are collecting logs"
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1 -Force
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Force

Write-Output "[*] Defining the max log file sizes"
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name "MaxSize" -Value 524288000 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Windows PowerShell" -Name "MaxSize" -Value 262144000 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell/Operational" -Name "MaxSize" -Value 524288000 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System" -Name "MaxSize" -Value 262144000 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application" -Name "MaxSize" -Value 262144000 -Force

Write-Output "[*] Enable applying the Advanced Audit Policies"
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -Value 1

Write-Output "[*] Enable Task Scheduler Logging"
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Operational" -Name "Enabled" -Value 1 -Force

Write-Output "[*] Enabling DNS Logging"
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DNS-Client/Operational" -Name "Enabled" -Value 1 -Force

Write-Output "[*] Enabling USB logging"
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DriverFrameworks-UserMode/Operational" -Name "Enabled" -Value 1 -Force

# ENABLE DATA EXECUTION PREVENTION (DEP)
Write-Output "[*] Enabling Data Execution Prevention (DEP)"
Set-Processmitigation -System -Enable DEP

Write-Output "[*] Enabling all other Process Mitigation Settings "
#https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/enable-exploit-protection?view=o365-worldwide
Set-ProcessMitigation -System -Enable CFG,StrictCFG,SuppressExports
Set-ProcessMitigation -System -Enable ForceRelocateImages
Set-ProcessMitigation -System -Enable BottomUp,HighEntropy
Set-ProcessMitigation -System -Enable SEHOP,SEHOPTelemetry 
Set-ProcessMitigation -System -Enable TerminateOnError

net accounts /minpwlen:0

Get-LocalUser | ForEach-Object {
    $newPassword = "password"  # Replace with your desired password
    $securePassword = ConvertTo-SecureString -String $newPassword -AsPlainText -Force
    Set-LocalUser -Name $_.Name -PasswordNeverExpires $false -Password $securePassword
}
net accounts /minpwlen:14



# WINDOWS AUTO UPDATES
$WUSettings = (New-Object -ComObject Microsoft.Update.AutoUpdate).Settings
$WUSettings.NotificationLevel= 3
$WUSettings.Save()

# WINDOWS DEFENDER
Write-Output "Enabling Windows Defender to check archive file types"
Set-MpPreference -DisableArchiveScanning 0

Write-Output "Enabling Windows Defender Potentially Unwanted Program (PUP) protection which prevents applications you do not tell Windows to install from installing"
Set-MpPreference -PUAProtection 1

Set-MpPreference -DisableBehaviorMonitoring $False
Enable-WindowsOptionalFeature -FeatureName "Windows-Defender-ApplicationGuard" -Online

Write-Output "[*] Enabling the sanbox of Windows Defender"
setx /m mp_force_use_sandbox 1

Write-Output "[*] Enabling Structured Exception Handling Overwrite Protection (SEHOP)"
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name DisableExceptionChainValidation -Value 0 -PropertyType Dword

Write-Output "[*] Applying UAC restrictions to local accounts on network logons"
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name LocalAccountTokenFilterPolicy -Value 0 -PropertyType Dword

Write-Output "[*] Configure SMB v1 client driver so it is set to 'Disable driver (recommended)"
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10" -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10" -Name Start -Value 4 -PropertyType Dword

Write-Output "[*] Securing Against NetBIOS Name Service (NBT-NS) Poisoning Attacks"
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NetBT\Parameters" -Name NodeType -Value 2 -PropertyType Dword

Write-Output "[*] Disabling IPv4 Source Routing"
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" -Name DisableIPSourceRouting -Value 2 -PropertyType Dword

Write-Output "[*] Disabling IPv6 source routing"
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters" -Name DisableIPSourceRouting -Value 2 -PropertyType Dword

Write-Output "[*] Disabling ICMP redirects"
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" -Name  EnableICMPRedirect -Value 0 -PropertyType Dword

Write-Output "[*] Preventing a WINS DoS attack avenue"
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netbt\Parameters" -Name   NoNameReleaseOnDemand -Value 1 -PropertyType Dword

Write-Output "[*] Ensuring the use of Safe DLL Search mode"
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager" -Name SafeDllSearchMode -Value 1 -PropertyType Dword

Write-Output "[*] Generate an event when security event log reaches 90% capacity"
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Eventlog\Security" -Name WarningLevel -Value 90 -PropertyType Dword

Write-Output "[*] Verifing that Windows is configured to have password protection take effect within a limited time frame when the screen saver becomes active."
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name ScreenSaverGracePeriod -Value 0 -PropertyType String

Write-Output "[*] Enabling Windows Defender AV to prevent user and apps from accessing dangerous websites"
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Force -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Name EnableNetworkProtection -Value 1 -PropertyType Dword

<#######################################################################

Enable and Configure Google Chrome Internet Browser Settings

#######################################################################>

Write-Output "[*] Hardening Chrome"


reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AllowCrossOriginAuthPrompt" /t REG_DWORD /d 0 /f
reg delete "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SafeBrowsingAllowlistDomains" /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SafeBrowsingProtectionLevel" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "MediaRouterCastAllowAllIPs" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "BrowserNetworkTimeQueriesEnabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AudioSandboxEnabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "PromptForDownloadLocation" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "BackgroundModeEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SafeSitesFilterBehavior" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ChromeVariations" /t REG_DWORD /d 0 /f
reg delete "HKLM\SOFTWARE\Policies\Google\Chrome" /v "CertificateTransparencyEnforcementDisabledForLegacyCas" /f
reg delete "HKLM\SOFTWARE\Policies\Google\Chrome" /v "CertificateTransparencyEnforcementDisabledForUrls" /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SavingBrowserHistoryDisabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DNSInterceptionChecksEnabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ComponentUpdatesEnabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "GloballyScopeHTTPAuthCacheEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "EnableOnlineRevocationChecks" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "RendererCodeIntegrityEnabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "CommandLineFlagSecurityWarningsEnabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ThirdPartyBlockingEnabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "EnterpriseHardwarePlatformAPIEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ForceEphemeralProfiles" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ImportAutofillFormData" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ImportHomepage" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ImportSearchEngine" /t REG_DWORD /d 0 /f
reg delete "HKLM\SOFTWARE\Policies\Google\Chrome" /v "HSTSPolicyBypassList" /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "OverrideSecurityRestrictionsOnInsecureOrigin" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "LookalikeWarningAllowlistDomains" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SuppressUnsupportedOSWarning" /t REG_DWORD /d 0 /f
reg delete "HKLM\SOFTWARE\Policies\Google\Chrome" /v "WebRtcLocalIpsAllowedUrls" /f

# https://admx.help/?Category=GoogleUpdate&Policy=Google.Policies.Update::Pol_UpdatePolicyGoogleChrome
reg add "HKLM\SOFTWARE\Policies\Google\Update" /v "Update{8A69D345-D564-463C-AFF1-A69D9E530F96}" /t REG_DWORD /d 1 /f
# https://admx.help/?Category=ChromeEnterprise&Policy=Google.Policies.Update::Pol_DefaultUpdatePolicy
reg add "HKLM\SOFTWARE\Policies\Google\Update" /v "UpdateDefault" /t REG_DWORD /d 1 /f

reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultInsecureContentSetting" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultWebBluetoothGuardSetting" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultWebUsbGuardSetting" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultNotificationsSetting" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "BlockExternalExtensions" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ExtensionAllowedTypes" /t REG_MULTI_SZ /d 1 /f

reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AllowCrossOriginAuthPrompt" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AlwaysOpenPdfExternally" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AmbientAuthenticationInPrivateModesEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AudioCaptureAllowed" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "BlockExternalExtensions" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DnsOverHttpsMode" /t REG_SZ /d on /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SSLVersionMin" /t REG_SZ /d tls1.2 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ScreenCaptureAllowed" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SitePerProcess" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "TLS13HardeningForLocalAnchorsEnabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "VideoCaptureAllowed" /t REG_DWORD /d 0 /f

# I'm losing my sanity

reg add "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" /v "LDAPServerIntegrity" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v "SupportedEncryptionTypes" /t REG_DWORD /d "2147483640" /f
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDataRetransmissions" /t REG_DWORD /d 3 /f
reg add "HKLM\System\CurrentControlSet\Services\DNS\Parameters" /v "SecureResponses" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "DisableWindowsUpdateAccess" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\SystemCertificates\AuthRoot" /v "DisableRootAutoUpdate" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers" /v "DisableWebPnPDownload" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers" /v "DisableHTTPPrinting" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "AutoInstallMinorUpdates" /t REG_DWORD /d 1 /f 
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "DetectionFrequencyEnabled" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "DetectionFrequency" /t REG_DWORD /d 20 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "AUOptions" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "IncludeRecommendedUpdates" /t REG_DWORD /d 1 /f
reg add  "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "DisallowCpl" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "CrashDumpEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" /v "ForceDefenderPassiveMode" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v "RestrictDriverInstallationToAdministrators" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" /v "ForceDefenderPassiveMode" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" /v "ForceDefenderPassiveMode" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableLockScreenAppNotifications" /t REG_DWORD /d 1 /f
Import-Module ActiveDirectory
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "DisableAutoplay" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 1 /f
auditpol /set /category:* /success:enable /failure:enable
Get-ADUser -Filter * | Set-ADUser -PasswordNeverExpires $false
Get-ADUser -Filter * | Set-ADUser -PasswordNotRequired $false
Get-ADUser -Filter * | Set-ADUser -AllowReversiblePasswordEncryption $false
# Script for firewall settings

# Enabling Firewall
Set-NetFirewallProfile -All -Enabled True
Set-NetFirewallProfile -All -DefaultInboundAction Block
Set-NetFirewallProfile -All -DefaultOutboundAction Allow

# Disabling rules
Set-NetFirewallProfile -All -AllowInboundRules False
Set-NetFirewallProfile -All -AllowLocalFirewallRules False
Set-NetFirewallProfile -All -AllowLocalIPsecRules False
$profiles = @("PublicProfile", "StandardProfile", "PrivateProfile")

foreach ($profile in $profiles) {
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\$profile"
    if (-not (Test-Path $path)) {
        New-Item -Path $path -Force
    }
    New-ItemProperty -Path $path -Name AllowLocalIPsecPolicyMerge -Value 0
}

# Configure Firewall Logging
$fwLogPath = "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
if (Test-Path $fwLogPath -PathType Leaf) 
{
    Set-NetFirewallProfile -All -LogFileName $fwLogPath
} 
else 
{
    New-Item -Path $fwLogPath -ItemType File -Force
    Set-NetFirewallProfile -All -LogFileName $fwLogPath
}
Set-NetFirewallProfile -All -LogBlocked True
Set-NetFirewallProfile -All -LogAllowed True
Set-NetFirewallProfile -All -LogMaxSizeKilobytes 16384
Set-NetFirewallProfile -All -LogIgnored False # Not sure about this one

# Other Settings
Set-NetFirewallProfile -All -AllowUserApps False
Set-NetFirewallProfile -All -AllowUserPorts False
Set-NetFirewallProfile -All -NotifyOnListen False
Set-NetFirewallProfile -All -EnableStealthModeForIPsec True
Set-NetFirewallProfile -All -DisabledInterfaceAliases NotConfigured
Set-NetFirewallProfile -All -AllowUnicastResponseToMulticast True 

$password123 = "password123"
$securePassword = ConvertTo-SecureString -String $password123 -AsPlainText -Force
Get-ADUser -Filter * | Set-ADAccountPassword -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "password123" -Force)
net accounts /minpwlen:14
net accounts /maxpwage:59
net accounts /minpwage:2
net accounts /uniquepw:24
net accounts /lockoutthreshold:3
net accounts /lockoutduration:15
net accounts /lockoutwindow:15
net accounts /minpwlen:0
Get-LocalUser | Enable-LocalUser
Get-LocalUser -Name "Administrator" | Disable-LocalUser
Get-LocalUser -Name "Guest" | Disable-LocalUser
Get-LocalUser -Name "DefaultAccount" | Disable-LocalUser
Get-LocalUser -Name "WDAGUtilityAccount" | Disable-LocalUser
net accounts /minpwlen:14

Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
Set-ProcessMitigation -System -Enable CFG,StrictCFG,SuppressExports
Set-ProcessMitigation -System -Enable DEP
Set-ProcessMitigation -System -Enable ForceRelocateImages
Set-ProcessMitigation -System -Enable BottomUp,HighEntropy
Set-ProcessMitigation -System -Enable SEHOP,SEHOPTelemetry 
Set-ProcessMitigation -System -Enable TerminateOnError


Get-LocalUser | Set-LocalUser -PasswordNeverExpires $false
Get-LocalUser | Set-LocalUser -AccountNeverExpires $true
Get-ADUser -Filter * -properties sidhistory | foreach {Set-ADUser $_ -remove @{sidhistory=$_.sidhistory.value}}
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v "EnableScriptBlockLogging" /t REG_DWORD /d 255 /f
reg add "HKLM\Software\Policies\Microsoft\Microsoft Antimalware\Real-Time Protection" /v "LocalSettingOverrideDisableOnAccessProtection" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Microsoft Antimalware\Real-Time Protection" /v "LocalSettingOverrideRealTimeScanDirection" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Microsoft Antimalware\Real-Time Protection" /v "LocalSettingOverrideDisableIOAVProtection" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Microsoft Antimalware\Real-Time Protection" /v "LocalSettingOverrideDisableBehaviorMonitoring" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Microsoft Antimalware\Real-Time Protection" /v "LocalSettingOverrideDisableScriptScanning" /t REG_DWORD /d 0 /f
Set-MpPreference -DisableScriptScanning $false
Set-MpPreference -DisableArchiveScanning $false
Set-MpPreference -EnableNetworkProtection Enabled
Set-MpPreference -DisableRealtimeMonitoring $false
# Configure Real-Time Protection
Set-MpPreference -DisableRealtimeMonitoring $false
# Configure Script Scanning
Set-MpPreference -DisableScriptScanning $false

# Configure Archive Scanning
Set-MpPreference -DisableArchiveScanning $false

# Configure Network Protection
Set-MpPreference -EnableNetworkProtection Enabled
Set-MpPreference -PUAProtection Enabled
Set-MpPreference -DisableCatchupFullScan $false
Set-MpPreference -DisableCatchupQuickScan $false
Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $false
Set-MpPreference -RealTimeScanDirection Incoming #Both is more secure
Set-MpPreference -CheckForSignaturesBeforeRunningScan $true
Set-MpPreference -SignatureScheduleDay 0 # 0 is every day
Set-MpPreference -SubmitSamplesConsent 0
Set-MpPreference -UnknownThreatDefaultAction 2
Set-MpPreference -ScanPurgeItemsAfterDelay 365
#Set-MpPreference -ThreatIDDefaultAction_Actions 2 # Quarantine by default
#List of actions: https://msdn.microsoft.com/es-es/library/windows/desktop/dn439474%28v=vs.85%29.aspx
Set-MpPreference -ScanAvgCPULoadFactor 20
Set-MpPreference -ScanOnlyIfIdleEnabled $true # If CPU is idle, run scheduled scan.
Set-MpPreference -SignatureUpdateInterval 4
Set-MpPreference -CheckForSignaturesBeforeRunningScan 1
reg add "HKCU\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" /v DriverLoadPolicy /t REG_DWORD /d 3 /f
bcdedit.exe /set nointegritychecks off
Set-MpPreference -EnableControlledFolderAccess Enabled
Set-MpPreference -MAPSReporting 2
Set-MpPreference -SubmitSamplesConsent 3
Set-MpPreference -CloudExtendedTimeout 50
Set-MpPreference -CloudBlockLevel ZeroTolerance
Set-Processmitigation -System -Enable DEP,EmulateAtlThunks,BottomUp,HighEntropy,SEHOP,SEHOPTelemetry,TerminateOnError
Set-MpPreference -EnableNetworkProtection Enabled 
reg add "HKCU\Software\Policies\Microsoft\Office\12.0\Publisher\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\12.0\Word\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\14.0\Publisher\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\14.0\Word\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Outlook\Security" /v markinternalasunsafe /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Word\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Excel\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\PowerPoint\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Word\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Publisher\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Outlook\Security" /v markinternalasunsafe /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Word\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Excel\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\PowerPoint\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Word\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Publisher\Security" /v vbawarnings /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Office\12.0\Onenote\options" /v disableembeddedfiles /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\14.0\Onenote\options" /v disableembeddedfiles /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Onenote\options" /v disableembeddedfiles /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Onenote\options" /v disableembeddedfiles /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Office\16.0\Common\Security" /v MacroRuntimeScanScope /t REG_DWORD /d 2 /f
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Common\Security" /v MacroRuntimeScanScope /t REG_DWORD /d 2 /f
reg add "HKCU\Software\Microsoft\Office\14.0\Word\Options" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
reg add "HKCU\Software\Microsoft\Office\14.0\Word\Options\WordMail" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
reg add "HKCU\Software\Microsoft\Office\15.0\Word\Options" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
reg add "HKCU\Software\Microsoft\Office\15.0\Word\Options\WordMail" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
reg add "HKCU\Software\Microsoft\Office\16.0\Word\Options" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
reg add "HKCU\Software\Microsoft\Office\16.0\Word\Options\WordMail" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
reg add "HKCU\Software\Microsoft\Office\14.0\Word\Security\FileBlock" /v RtfFiles /t REG_DWORD /d 00000002 /f
reg add "HKCU\Software\Microsoft\Office\15.0\Word\Security\FileBlock" /v RtfFiles /t REG_DWORD /d 00000002 /f
reg add "HKCU\Software\Microsoft\Office\16.0\Word\Security\FileBlock" /v RtfFiles /t REG_DWORD /d 00000002 /f
reg add "HKCU\Software\Microsoft\Office\14.0\Word\Security\FileBlock" /v OpenInProtectedView /t REG_DWORD /d 00000000 /f
reg add "HKCU\Software\Microsoft\Office\15.0\Word\Security\FileBlock" /v OpenInProtectedView /t REG_DWORD /d 00000000 /f
reg add "HKCU\Software\Microsoft\Office\16.0\Word\Security\FileBlock" /v OpenInProtectedView /t REG_DWORD /d 00000000 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v SupportedEncryptionTypes /t REG_DWORD /d 2147483640 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v DisableSmartNameResolution /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v DisableParallelAandAAAA /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v IGMPLevel /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableICMPRedirect /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v RestrictNullSessAccess /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableVirtualization /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v SaveZoneInformation /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoDataExecutionPrevention /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoHeapTerminationOnCorruption /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v DisableWebPnPDownload /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v DisableHTTPPrinting /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v AutoConnectAllowedOEM /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v fMinimizeConnections /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" /v NoNameReleaseOnDemand /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v RestrictSendingNTLMTraffic /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v NTLMMinServerSec /t REG_DWORD /d 537395200 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v NTLMMinClientSec /t REG_DWORD /d 537395200 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" /v allownullsessionfallback /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v EveryoneIncludesAnonymous /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictRemoteSAM /t REG_SZ /d "O:BAG:BAD:(A;;RC;;;BA)" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v UseMachineId /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" /v WpadOverride /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v DisableFirstRunCustomize /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v SCRemoveOption /t REG_DWORD /d 2 /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanWorkStation\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanWorkStation\Parameters" /v "EnableSecuritySignature" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "EnableSecuritySignature" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" /v "LDAPServerIntegrity" /t REG_DWORD /d 2 /f
reg add "HKLM\System\CurrentControlSet\Services\ldap" /v "LDAPClientIntegrity " /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanWorkStation\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanWorkStation\Parameters" /v "EnableSecuritySignature" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "EnableSecuritySignature" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" /v "LDAPServerIntegrity" /t REG_DWORD /d 2 /f
reg add "HKLM\System\CurrentControlSet\Services\ldap" /v "LDAPClientIntegrity " /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v RequireSignOrSeal /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v SealSecureChannel /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v SignSecureChannel /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v ShellSmartScreenLevel /t REG_SZ /d Block /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" /v AllowInsecureGuestAuth /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v CWDIllegalInDllSearch /t REG_DWORD /d 0x2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v SafeDLLSearchMode /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v ProtectionMode /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows Script Host\Settings" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows Script Host\Settings" /v ActiveDebugging /t REG_SZ /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows Script Host\Settings" /v DisplayLogo /t REG_SZ /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows Script Host\Settings" /v SilentTerminate /t REG_SZ /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows Script Host\Settings" /v UseWINSAFER /t REG_SZ /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\services\tcpip6\parameters" /v DisabledComponents /t REG_DWORD /d 0xFF /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fEncryptRPCTraffic /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config\" /v DODownloadMode /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoAutoplayfornonVolume /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 0xff /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 0xff /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoAutorun /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoRecentDocsHistory /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoRecentDocsMenu /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v ClearRecentDocsOnExit /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v DisableAutoplay /t REG_DWORD /d 1 /f
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SeparateProcess" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "NavPaneShowAllFolders" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DontPrettyPath" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowStatusBar" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideIcons" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "AutoCheckSelect" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "NavPaneShowAllFolders" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "AlwaysShowMenus" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowRecent" /t REG_DWORD /d 0 /f
net stop WinRM
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" /v AllowUnencryptedTraffic /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /v AllowDigest /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule" /v DisableRpcOverTcp /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" /v DisableRemoteScmEndpoints /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10" /v Start /t REG_DWORD /d 4 /f
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2
powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 00000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdminOutboundCreds /t REG_DWORD /d 00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v Negotiate /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" /v AllowProtectedCreds /t REG_DWORD /d 1 /f
sc.exe config mpssvc start= auto
sc.exe config wuauserv start= auto
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 00000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdminOutboundCreds /t REG_DWORD /d 00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v Negotiate /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" /v AllowProtectedCreds /t REG_DWORD /d 1 /f

reg add "HKLM\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel" /v MyComputer /t REG_SZ /d "Disabled" /f
reg add "HKLM\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel" /v LocalIntranet /t REG_SZ /d "Disabled" /f
reg add "HKLM\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel" /v Internet /t REG_SZ /d "Disabled" /f
reg add "HKLM\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel" /v TrustedSites /t REG_SZ /d "Disabled" /f
reg add "HKLM\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel" /v UntrustedSites /t REG_SZ /d "Disabled" /f
netsh Advfirewall set allprofiles state on
netsh advfirewall firewall add rule name="Block appvlp.exe netconns" program="C:\Program Files (x86)\Microsoft Office\root\client\AppVLP.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\system32\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block certutil.exe netconns" program="%systemroot%\system32\certutil.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block cmstp.exe netconns" program="%systemroot%\system32\cmstp.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\system32\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block esentutl.exe netconns" program="%systemroot%\system32\esentutl.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block expand.exe netconns" program="%systemroot%\system32\expand.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block extrac32.exe netconns" program="%systemroot%\system32\extrac32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block findstr.exe netconns" program="%systemroot%\system32\findstr.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\system32\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block makecab.exe netconns" program="%systemroot%\system32\makecab.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\system32\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block msiexec.exe netconns" program="%systemroot%\system32\msiexec.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block nltest.exe netconns" program="%systemroot%\system32\nltest.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block notepad.exe netconns" program="%systemroot%\system32\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block pcalua.exe netconns" program="%systemroot%\system32\pcalua.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block print.exe netconns" program="%systemroot%\system32\print.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\system32\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block replace.exe netconns" program="%systemroot%\system32\replace.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block rundll32.exe netconns" program="%systemroot%\system32\rundll32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\system32\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block scriptrunner.exe netconns" program="%systemroot%\system32\scriptrunner.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block SyncAppvPublishingServer.exe netconns" program="%systemroot%\system32\SyncAppvPublishingServer.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block wmic.exe netconns" program="%systemroot%\system32\wbem\wmic.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\system32\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block regasm.exe netconns" program="%systemroot%\system32\regasm.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block odbcconf.exe netconns" program="%systemroot%\system32\odbcconf.exe" protocol=tcp dir=out enable=yes action=block profile=any

netsh advfirewall firewall add rule name="Block regasm.exe netconns" program="%systemroot%\SysWOW64\regasm.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block odbcconf.exe netconns" program="%systemroot%\SysWOW64\odbcconf.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block appvlp.exe netconns" program="C:\Program Files\Microsoft Office\root\client\AppVLP.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\SysWOW64\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block certutil.exe netconns" program="%systemroot%\SysWOW64\certutil.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block cmstp.exe netconns" program="%systemroot%\SysWOW64\cmstp.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\SysWOW64\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block esentutl.exe netconns" program="%systemroot%\SysWOW64\esentutl.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block expand.exe netconns" program="%systemroot%\SysWOW64\expand.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block extrac32.exe netconns" program="%systemroot%\SysWOW64\extrac32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block findstr.exe netconns" program="%systemroot%\SysWOW64\findstr.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\SysWOW64\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block makecab.exe netconns" program="%systemroot%\SysWOW64\makecab.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\SysWOW64\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block msiexec.exe netconns" program="%systemroot%\SysWOW64\msiexec.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block nltest.exe netconns" program="%systemroot%\SysWOW64\nltest.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block notepad.exe netconns" program="%systemroot%\SysWOW64\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block pcalua.exe netconns" program="%systemroot%\SysWOW64\pcalua.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block print.exe netconns" program="%systemroot%\SysWOW64\print.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\SysWOW64\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block replace.exe netconns" program="%systemroot%\SysWOW64\replace.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block rpcping.exe netconns" program="%systemroot%\SysWOW64\rpcping.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block rundll32.exe netconns" program="%systemroot%\SysWOW64\rundll32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\SysWOW64\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block scriptrunner.exe netconns" program="%systemroot%\SysWOW64\scriptrunner.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block SyncAppvPublishingServer.exe netconns" program="%systemroot%\SysWOW64\SyncAppvPublishingServer.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block wmic.exe netconns" program="%systemroot%\SysWOW64\wbem\wmic.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\SysWOW64\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
fsutil behavior set disable8dot3 1
fsutil behavior set disablelastaccess 0
powercfg -h off
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" /v EnhancedAntiSpoofing /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v NoLockScreenCamera /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsActivateWithVoiceAboveLock /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsActivateWithVoice /t REG_DWORD /d 2 /f

reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA256" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA384" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA512" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" /v ServerMinKeyBitLength /t REG_DWORD /d 0x00001000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\ECDH" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" /v EccCurves /t REG_MULTI_SZ /d NistP384,NistP256 /f
reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" /v SchUseStrongCrypto /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" /v SystemDefaultTlsVersions /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" /v SchUseStrongCrypto /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" /v SystemDefaultTlsVersions /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" /v SchUseStrongCrypto /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" /v SystemDefaultTlsVersions /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" /v SchUseStrongCrypto /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" /v SystemDefaultTlsVersions /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /f
reg add "HKLM\Software\Policies\Microsoft\Edge"  /v "BackgroundModeEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" /v SafeForScripting /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v "FormSuggest Passwords" /t REG_SZ /d no /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SitePerProcess" /t REG_DWORD /d "0x00000001" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SSLVersionMin" /t REG_SZ /d "tls1.2^@" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "NativeMessagingUserLevelHosts" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SmartScreenEnabled" /t REG_DWORD /d "0x00000001" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "PreventSmartScreenPromptOverride" /t REG_DWORD /d "0x00000001" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "PreventSmartScreenPromptOverrideForFiles" /t REG_DWORD /d "0x00000001" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SSLErrorOverrideAllowed" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SmartScreenPuaEnabled" /t REG_DWORD /d "0x00000001" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "AllowDeletingBrowserHistory" /t REG_DWORD /d "0x00000000" /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AdvancedProtectionAllowed" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AllowCrossOriginAuthPrompt" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AlwaysOpenPdfExternally" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AmbientAuthenticationInPrivateModesEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AudioCaptureAllowed" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AudioSandboxEnabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "BlockExternalExtensions" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "SSLVersionMin" /t REG_SZ /d "tls1.2" /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ScreenCaptureAllowed" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SitePerProcess" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "TLS13HardeningForLocalAnchorsEnabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "VideoCaptureAllowed" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AllowFileSelectionDialogs" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AlwaysOpenPdfExternally" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AutoFillEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AutofillAddressEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AutofillCreditCardEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "PasswordManagerEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "MetricsReportingEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ImportSavedPasswords" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "CloudPrintSubmitEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "CloudPrintProxyEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AllowOutdatedPlugins" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AlternateErrorPagesEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DnsOverHttpsMode" /t REG_SZ /d "automatic" /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DnsOverHttpsTemplates" /t REG_SZ /d "https://1.1.1.2/dns-query" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "NetworkServiceSandbox" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "AllowOutdatedPlugins" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "AlternateErrorPagesEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "BlockThirdPartyCookies" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "ImportAutofillFormData" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "UrlKeyedAnonymizedDataCollectionEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "WebRtcEventLogCollectionAllowed" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "SafeBrowsingProtectionLevel" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "BackgroundModeEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "PasswordLeakDetectionEnabled" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "RemoteDebuggingAllowed" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "UserFeedbackAllowed" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "DNSInterceptionChecksEnabled" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "AlternateErrorPagesEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Google\Chrome\Recommended" /v "RestoreOnStartup" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Google\Chrome\Recommended" /v "TranslateEnabled" /t REG_DWORD /d 0 /f
taskkill /f /im OneDrive.exe
powershell.exe -command "Get-ScheduledTask XblGameSaveTaskLogon | Disable-ScheduledTask"
powershell.exe -command "Get-ScheduledTask XblGameSaveTask | Disable-ScheduledTask"
powershell.exe -command "Get-ScheduledTask Consolidator | Disable-ScheduledTask"
powershell.exe -command "Get-ScheduledTask UsbCeip | Disable-ScheduledTask"
powershell.exe -command "Get-ScheduledTask DmClient | Disable-ScheduledTask"
powershell.exe -command "Get-ScheduledTask DmClientOnScenarioDownload | Disable-ScheduledTask"
powershell.exe -command "Set-WinLanguageBarOption -UseLegacyLanguageBar"
#https://gist.github.com/ricardojba/ecdfe30dadbdab6c514a530bc5d51ef6
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri https://raw.githubusercontent.com/gunnarhaslinger/Windows-Defender-Exploit-Guard-Configuration/master/Windows10-v2104_ExploitGuard-Security-Baseline.xml -OutFile ProcessMitigation.xml
powershell.exe -Command "Set-ProcessMitigation -PolicyFilePath ProcessMitigation.xml"
del ProcessMitigation.xml
Invoke-WebRequest -Uri https://raw.githubusercontent.com/gunnarhaslinger/Windows-Defender-Exploit-Guard-Configuration/master/Windows10-v2104_ExploitGuard-Security-Baseline.xml -OutFile ProcessMitigation.xml
Invoke-WebRequest -Uri https://raw.githubusercontent.com/NWong-24/sus/main/secpol.cfg -OutFile secpol.cfg
powershell.exe -command "secedit /configure /db C:\Windows\security\local.sdb /cfg secpol.cfg /areas SECURITYPOLICY"
del secpol.cfg
bcdedit.exe /set '{current}' nx AlwaysOn
Disable-WindowsOptionalFeature -Online -FeatureName WorkFolders-Client -NoRestart -ErrorAction Stop
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 4 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v ScheduledInstallDay /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v ScheduledInstallTime /t REG_DWORD /d 3 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v RescheduleWaitTime /t REG_DWORD /d 10 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoRebootWithLoggedOnUsers /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v UseWUServer /t REG_DWORD /d 0 /f
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri https://raw.githubusercontent.com/0x6d69636b/windows_hardening/master/HardeningKitty.psm1 -OutFile HardeningKitty.psm1
Invoke-WebRequest -Uri https://raw.githubusercontent.com/0x6d69636b/windows_hardening/master/HardeningKitty.psd1 -OutFile HardeningKitty.psd1
Invoke-WebRequest -Uri https://raw.githubusercontent.com/scipag/HardeningKitty/master/lists/finding_list_0x6d69636b_machine.csv -OutFile finding_list_0x6d69636b_machine.csv
Invoke-WebRequest -Uri https://raw.githubusercontent.com/scipag/HardeningKitty/master/lists/finding_list_cis_microsoft_windows_server_2022_22h2_2.0.0_machine.csv -OutFile finding_list_cis_microsoft_windows_server_2022_22h2_2.csv
Invoke-WebRequest -Uri https://raw.githubusercontent.com/scipag/HardeningKitty/master/lists/finding_list_cis_microsoft_windows_10_enterprise_22h2_machine.csv -OutFile finding_list_cis_microsoft_windows_10_enterprise_22h2_machine.csv


Import-Module .\HardeningKitty.psm1

# Get the OS information
$osInfo = systeminfo | Select-String -Pattern "OS Name", "OS Version"

# Check if the information contains "Server 2022"
if ($osInfo -match "Server 2022") {
    Invoke-HardeningKitty -Mode HailMary -Log -Report -skiprestorepoint -FileFindingList .\finding_list_0x6d69636b_machine.csv
    Invoke-HardeningKitty -Mode HailMary -Log -Report -skiprestorepoint -FileFindingList .\finding_list_cis_microsoft_windows_server_2022_22h2_2.csv
}
else {
    Invoke-HardeningKitty -Mode HailMary -Log -Report -SkipRestorePoint -FileFindingList .\finding_list_0x6d69636b_machine.csv
    Invoke-HardeningKitty -Mode HailMary -Log -Report -skiprestorepoint -FileFindingList .\finding_list_cis_microsoft_windows_10_enterprise_22h2_machine.csv 
}
get-aduser -Filter * | Set-ADUser -AccountNotDelegated $true
Set-MpPreference -DisableArchiveScanning 0
Set-MpPreference -DisableEmailScanning 0
Set-MpPreference -EnableFileHashComputation 1
Set-MpPreference -DisableIntrusionPreventionSystem $false
Set-MpPreference -CloudBlockLevel High
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendAllSamples
Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled
#Block all Office applications from creating child processes
Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
#Block Office applications from creating executable content
Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled
#Block Office applications from injecting code into other processes
Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled
#Block JavaScript or VBScript from launching downloaded executable content
Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled
#Block execution of potentially obfuscated scripts
Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled
#Block Win32 API calls from Office macros
Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled
#Block executable files from running unless they meet a prevalence, age, or trusted list criterion
Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions Enabled
#Use advanced protection against ransomware
Add-MpPreference -AttackSurfaceReductionRules_Ids c1db55ab-c21a-4637-bb3f-a12568109d35 -AttackSurfaceReductionRules_Actions Enabled
#Block credential stealing from the Windows local security authority subsystem
Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled
#Block process creations originating from PSExec and WMI commands
Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions Enabled
#Block untrusted and unsigned processes that run from USB
Add-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions Enabled
#Block Office communication application from creating child processes
Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49e8-8b27-eb1d0a1ce869 -AttackSurfaceReductionRules_Actions Enabled
#Block Adobe Reader from creating child processes
Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions Enabled
#Block persistence through WMI event subscription
Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled
netsh int tcp set global timestamps=disabled
reg add "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v "EnableMulticast" /t DWord /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BTAGService" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\bthserv" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Browser" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MapsBroker" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\IISADMIN" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\irmon" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lltdsvc" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LxssManager" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\FTPSVC" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MSiSCSI" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\sshd" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PNRPsvc" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\p2psvc" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PNRPAutoReg" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PNRPsvc" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wercplsupport" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RasAuto" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SessionEnv" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\TermService" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\UmRdpService" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RpcLocator" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RemoteAccess" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\simptcp" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\sacsvr" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SSDPSRV" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\upnphost" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WMSvc" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WerSvc" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Wecsvc" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\icssvc" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WpnService" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PushToInstall" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinRM" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\XboxGipSvc" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\EventLog" /v Start /t REG_DWORD /d 2 /f
sc.exe config eventlog start= auto

Set-ExecutionPolicy Bypass -Scope Process
Start-Service EventLog
#unchecked code, no time to test
$result = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services'
$ServiceItems = $result | Foreach-Object {Get-ItemProperty $_.PsPath}
# Iterate through the keys and check for Unquoted ImagePath's
ForEach ($si in $ServiceItems) {
    if ($si.ImagePath -ne $nul) { 
        $obj = New-Object -Typename PSObject
        $obj | Add-Member -MemberType NoteProperty -Name Status -Value "Retrieved"
        # There is certianly a way to use the full path here but for now I trim it until I can find time to play with it
            $obj | Add-Member -MemberType NoteProperty -Name Key -Value $si.PSPath.TrimStart("Microsoft.PowerShell.Core\Registry::")
            $obj | Add-Member -MemberType NoteProperty -Name ImagePath -Value $si.ImagePath
        
        ########################################################################
            # Find and Fix Bad Keys for each key object
            ########################################################################
        
        #We're looking for keys with spaces in the path and unquoted
        $examine = $obj.ImagePath
        if (!($examine.StartsWith('"'))) { #Doesn't start with a quote
            if (!($examine.StartsWith("\??"))) { #Some MS Services start with this but don't appear vulnerable
                if ($examine.contains(" ")) { #If contains space
                    #when I get here, I can either have a good path with arguments, or a bad path
                    if ($examine.contains("-") -or $examine.contains("/")) { #found arguments, might still be bad
                        #split out arguments
                        $split = $examine -split " -", 0, "simplematch"
                        $split = $split[0] -split " /", 0, "simplematch"
                        $newpath = $split[0].Trim(" ") #Path minus flagged args
                        if ($newpath.contains(" ")){
                            #check for unflagged argument
                            $eval = $newpath -Replace '".*"', '' #drop all quoted arguments
                            $detunflagged = $eval -split "\", 0, "simplematch" #split on foler delim
                            if ($detunflagged[-1].contains(" ")){ #last elem is executable and any unquoted args
                                $fixarg = $detunflagged[-1] -split " ", 0, "simplematch" #split out args
                                $quoteexe = $fixarg[0] + '"' #quote that EXE and insert it back
                                $examine = $examine.Replace($fixarg[0], $quoteexe)
                                $examine = $examine.Replace($examine, '"' + $examine)
                                $badpath = $true
                            } #end detect unflagged
                            $examine = $examine.Replace($newpath, '"' + $newpath + '"')
                            $badpath = $true
                        } #end if newpath
                        else { #if newpath doesn't have spaces, it was just the argument tripping the check
                            $badpath = $false
                        } #end else
                    } #end if parameter
                    else
                    {#check for unflagged argument
                        $eval = $examine -Replace '".*"', '' #drop all quoted arguments
                        $detunflagged = $eval -split "\", 0, "simplematch"
                        if ($detunflagged[-1].contains(" ")){
                            $fixarg = $detunflagged[-1] -split " ", 0, "simplematch"
                            $quoteexe = $fixarg[0] + '"'
                            $examine = $examine.Replace($fixarg[0], $quoteexe)
                            $examine = $examine.Replace($examine, '"' + $examine)
                            $badpath = $true
                        } #end detect unflagged
                        else
                        {#just a bad path
                            #surround path in quotes
                            $examine = $examine.replace($examine, '"' + $examine + '"')
                            $badpath = $true
                        }#end else
                    }#end else
                }#end if contains space
                else { $badpath = $false }
            } #end if starts with \??
            else { $badpath = $false }
        } #end if startswith quote
        else { $badpath = $false }

        #Update Objects
        if ($badpath -eq $false){
            $obj | Add-Member -MemberType NoteProperty -Name BadKey -Value "No"
            $obj | Add-Member -MemberType NoteProperty -Name FixedKey -Value "N/A"
            $obj = $nul #clear $obj
        }
            
        # Plans to change this check. I believe it can be done more efficiently. But It works for now!
        if ($badpath -eq $true){
            $obj | Add-Member -MemberType NoteProperty -Name BadKey -Value "Yes"
            #sometimes we catch doublequotes
            if ($examine.endswith('""')){ $examine = $examine.replace('""','"') }
            $obj | Add-Member -MemberType NoteProperty -Name FixedKey -Value $examine
            if ($obj.badkey -eq "Yes"){
                #Write-Progress -Activity "Fixing $($obj.key)" -Status "Working..."
                $regpath = $obj.Fixedkey
                $obj.status = "Fixed"
                    $regkey = $obj.key.replace('HKEY_LOCAL_MACHINE', 'HKLM:')
                    # Comment the next line out to run without modifying the registry
                # Alternatively uncomment any line with Write-Output or Write-Object for extra verbosity.
                Set-ItemProperty -Path $regkey -name 'ImagePath' -value $regpath
            }               
        $obj = $nul #clear $obj
        }
    }
}   
# https://github.com/NetSecJedi/FixUnquotedPaths/blob/master/FixUnquotedPaths.ps1

reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v "RequireTPM" /t REG_DWORD /d 0 /f
$SecureString = ConvertTo-SecureString "1234" -AsPlainText -Force
Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -UsedSpaceOnly -Pin $SecureString -TPMandPinProtector

BCDEDIT /set "{current}" nx OptOut
Set-Processmitigation -System -Enable DEP
Set-MpPreference -DisableRemovableDriveScanning 0
Set-MpPreference -EnableFileHashComputation 1
Set-MpPreference -DisableIntrusionPreventionSystem $false
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Type DWord -Value 0
reg add "HKLM\Software\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenSlideshow" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AllowOnlineTips" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Print" /v "RpcAuthnLevelPrivacyEnabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10" /v "Start" /t REG_DWORD /d 4 /f
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v "DisablePasswordChange" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v "DisablePasswordChange" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d 1 /f

#LGPO TIME BABY

#https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_STIG_GPO_Package_October_2023.zip
#stupid ssl/tls error so im using a google drive direct download link
Invoke-WebRequest -OutFile DISA_STIGS.zip -Uri "http://drive.google.com/uc?export=download&id=1htu1de8nABGOk0B1fn6IZWaUkw8xL7nW"
Invoke-WebRequest -OutFile LGPO.zip -Uri "https://github.com/rootsecdev/Microsoft-Blue-Forest/raw/master/Security%20Baselines/LGPO.zip"
Expand-Archive -Path LGPO.zip -DestinationPath LGPO -Force
Expand-Archive -Path DISA_STIGS.zip -DestinationPath DISA_STIGS -Force
Move-Item .\LGPO\LGPO.exe .\LGPO.exe
del LGPO -Recurse
del LGPO.zip
<#
.\LGPO.exe /g ".\DISA_STIGS\DoD Windows Defender Firewall v2r2\GPOs\{EB82B913-90A2-4599-A554-90B3A116B382}" /v
.\LGPO.exe /g ".\DISA_STIGS\DoD Windows 10 v2r8\GPOs\{D44AA262-F641-4083-87B1-1BC05572792D}" /v
.\LGPO.exe /g ".\DISA_STIGS\DoD Windows 10 v2r8\GPOs\{876C5A1E-7050-4D3F-9FA5-99E9B31BF80E}" /v
.\LGPO.exe /g ".\DISA_STIGS\DoD WinSvr 2022 MS and DC v1r4\GPOs\{0868DCD3-069B-4027-89A9-995435DC3064}" /v
.\LGPO.exe /g ".\DISA_STIGS\DoD WinSvr 2022 MS and DC v1r4\GPOs\{46680758-56F4-4673-9D15-1AF560115185}" /v
.\LGPO.exe /g ".\DISA_STIGS\DoD Microsoft Defender Antivirus STIG v2r4\GPOs\{1733BFC6-8E8E-41F7-BB76-EB2070330C89}" /v
.\LGPO.exe /g ".\DISA_STIGS\DoD Mozilla Firefox v6r5\GPOs\{F1176AFA-BA81-47FB-A41E-5CDE92DA0EF4}" /v
#>
$chrometest = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe'

if($chrometest -eq $true){
   Write-Host "Chrome is installed"
   $Path = $env:TEMP;
    $Installer = "chrome_installer.exe";
    Invoke-WebRequest "http://dl.google.com/chrome/install/latest/chrome_installer.exe" -OutFile $Path\$Installer;
    Start-Process -FilePath $Path\$Installer -Args "/silent /install" -Verb RunAs -Wait;
    Remove-Item $Path\$Installer
    .\LGPO.exe /g ".\DISA_STIGS\DoD Google Chrome v2r8\GPOs\{0FBEE738-6902-4E7E-8E79-9A0B1B2668B9}" /v
} else {
   Write-Host "Chrome is not installed"
}

# harambe made me insane
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealTimeMonitoring" /t REG_DWORD /d 0 /f
auditpol /set /category:* /success:enable /failure:enable
Invoke-WebRequest -Uri https://raw.githubusercontent.com/NWong-24/sus/main/secpol.cfg -OutFile secpol.cfg
powershell.exe -command "secedit /configure /db C:\Windows\security\local.sdb /cfg secpol.cfg /areas SECURITYPOLICY"
del secpol.cfg
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ValidateAdminCodeSignatures /t REG_DWORD /d 1 /f
# now baldi too
# List of modules to be removed
$modulesToRemove = @("PowerSploit", "DSInternals", "Nishang", "Empire", "Mimikatz", "Invoke-Obfuscation", "Powercat", "Invoke-Shellcode")

# Loop through each module and uninstall it
foreach ($moduleName in $modulesToRemove) {
    try {
        Uninstall-Module -Name $moduleName -Force -ErrorAction Stop
        Write-Host "Module $moduleName has been successfully removed."
    } catch {
        Write-Host "Failed to remove module $moduleName. Error: $_"
    }
}

$additionalModulesToRemove = @("Veil", "CrackMapExec", "UnmanagedPowerShell", "LaZagne", "ReconDog", "Invoke-Phant0m", "Invoke-CradleCrafter", "Sherlock", "PowerUpSQL")

foreach ($moduleName in $additionalModulesToRemove) {
    try {
        Uninstall-Module -Name $moduleName -Force -ErrorAction Stop
        Write-Host "Module $moduleName has been successfully removed."
    } catch {
        Write-Host "Failed to remove module $moduleName. Error: $_"
    }
}
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DiskQuota" -Name "ApplyToRemovableMedia" -Value 1
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DiskQuota" -Name "Enable" -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "NtfsDisableLastAccessUpdate" -Value 1

#saving time 
$user = $env:USERNAME
$baseDirectory = "C:\Users"

# Get all directories under C:\Users
$directories = Get-ChildItem -Path $baseDirectory -Directory -Recurse

# Loop through each directory and grant full control to the specified user
foreach ($directory in $directories) {
    try {
        $acl = Get-Acl $directory.FullName
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($user, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.SetAccessRule($rule)
        Set-Acl -Path $directory.FullName -AclObject $acl
        Write-Host "Full control granted to $user on $($directory.FullName)"
    } catch {
        Write-Host "Failed to grant full control on $($directory.FullName). Error: $_"
    }
}
bcdedit /set TESTSIGNING OFF
REG ADD "HKCU\Software\Policies\Microsoft\Windows NT\Driver Signing" /v BehaviorOnFailedVerify /t REG_DWORD /d 2 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v DisableHHDEP /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Messenger\Client" /v PreventRun /t REG_DWORD /d 1 /f
