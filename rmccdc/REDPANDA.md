net view /all

## File Integrity

C:\\> fciv.exe c:\ -r -mdS -xml .xml
C:\\> fciv.exe -list -shal -xml .xml
C:\\> fciv.exe -v -shal -xml .xml

C:\\> psloggedon \\computername


## Active Directory
Get-ADDomain
dsquery user domainroot
dsquery *
Get-ADDomainController -filter * | select hostname,operatingsystem
invoke-command -ComputerName DC-Name -scriptblock {wbadmin start systemstateback up -backupTarget:"Backup-Path" -quiet}

netdom query WORKSTATION(or SERVER/DC)

PS C:\\> import-module activedirectory 
PS C:\\> Get-QADUser -CreatedAfter (GetDate).AddDays(-90) 
PS C:\\> Get-ADUser -Filter * -Properties whenCreated I Where-Object {$_.whenCreated -ge ((GetDate).AddDays(-90)).Date}

Get-ADUser username -Properties *
Disable-ADAccount -Identity rallen
Set-ADUser -Identity username -ChangePasswordAtLogon $true //Force pass reset
Move-ADObject -Identity "CN=Test User (0001),OU=ADPRO Users,DC=ad,DC=activedirectorypro,DC=com" -TargetPath "OU=HR,OU=ADPRO Users,DC=ad,DC=activedirectorypro,DC=com" // Move user to new OU

Get-ADGroup -Filter * // Show security groups
Get-ADGroupMember -Identity "HR Full" // Show all members of security group
Add-ADGroupMember -Identity group-name -Members User1, User2 //Users to grp

Get-ADComputer -Filter "name -like '*'" -Properties operatingSystem | group -Property operatingSystem | Select Name,Count // List machines by OS

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



https://github.com/Topazstix/mlc-rmccdc-23/blob/main/cheatsheets/Powershell-Commands.md