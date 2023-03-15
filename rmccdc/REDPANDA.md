net view /all

## File Integrity

C:\\> fciv.exe c:\ -r -mdS -xml .xml
C:\\> fciv.exe -list -shal -xml .xml
C:\\> fciv.exe -v -shal -xml .xml

C:\\> psloggedon \\computername


## Active Directory

C:\\> dsquery user domainroot
C:\\> dsquery ou DC=,DC=
C:\\> netdom query WORKSTATION(or SERVER/DC)

PS C:\\> import-module activedirectory 
PS C:\\> Get-QADUser -CreatedAfter (GetDate).AddDays(-90) 
PS C:\\> Get-ADUser -Filter * -Properties whenCreated I Where-Object {$_.whenCreated -ge ((GetDate).AddDays(-90)).Date}



## Services
sc query 
sc config "service" start= disabled
sc stop "service"
wmic service where name='service' call ChangeStartmode Disabled

## Passwords
net user * /domain