net view /all

## File Integrity

C:\\> fciv.exe c:\ -r -mdS -xml .xml
C:\\> fciv.exe -list -shal -xml .xml
C:\\> fciv.exe -v -shal -xml .xml

C:\\> psloggedon \\computername


## Active Directory
dsquery user domainroot
dsquery *
netdom query WORKSTATION(or SERVER/DC)

PS C:\\> import-module activedirectory 
PS C:\\> Get-QADUser -CreatedAfter (GetDate).AddDays(-90) 
PS C:\\> Get-ADUser -Filter * -Properties whenCreated I Where-Object {$_.whenCreated -ge ((GetDate).AddDays(-90)).Date}



## Services
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
sc query 
sc config "service" start= disabled
sc stop "service"
wmic service where name='service' call ChangeStartmode Disabled

## Passwords
net user * /domain

## SysInternals
wget https://download.sysinternals.com/files/SysinternalsSuite.zip
wget https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml
sysmon -accepteula -i c:\windows\config.xml
If wget not installed, Invoke-WebRequest -Uri <URL> -OutFile <full path>

## Registry

reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\WIndows\CurrentVersion\Authentication\LogonUI" /v ShowTabletKeyboard /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareWks /t REG_DWORD /d 0 /f

