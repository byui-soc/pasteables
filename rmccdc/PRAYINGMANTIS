# Keyed Access Setup

ssh-keygen -b 4096
ssh-copy-id vagrant@[remote_ip]

# SSH Hardening

sudo sed -i 's/*PermitRootLogin (yes|without-password|prohibit-password)/PermitRootLogin no/g' /etc/ssh/sshd_config
sudo sed -i 's/*PasswordAuthentication yes/PasswordAuthentication no' /etc/ssh/sshd_config

# Save SSH Config

sudo systemctl restart ssh
/etc/init.d/ssh restart

# Permissions

getent group sudo
getent group adm
cat /etc/group | grep sudo

# Remove permissions
gpasswd --delete user group

# See who else is on the box

who -a --ips
tty #see what tty you are

ps aux | grep pts/[number]
sudo kill -KILL [PID]
