#RHEL 6.5 lockdown script based on running SECSCN 6.3 x64

if [ `whoami` != "root" ]; then
        echo "$0 error: you must run this script as root user"
        exit 1
fi

# L1.2
chkconfig --level 12345 auditd on

# L1.8, L1.9, L1.10, L1.11, L1.12
# Fix this sed logic, it sucks
cp /etc/audit/auditd.conf /etc/audit/auditd.conf.bak
sed -i s/SUSPEND/HALT/g /etc/audit/auditd.conf
sed -i s/INCREMENTAL/SYNC/g /etc/audit/auditd.conf
sed -i s/SYSLOG/email/g /etc/audit/auditd.conf
sed -i s/SUSPEND/email/g /etc/audit/auditd.conf

#L1.14
# Add audit=1 to the end of the kernal lines in /etc/grub.conf
cp /etc/grub.conf /etc/grub.conf.bak
sed -r -i 's/^kernel.*$/& audit=1/g ' /etc/grub.conf

#L1.15, L1.16, L1.17, L1.18, L1.19, L1.20, L1.21, L1.22, L1.23, L1.24, L1.25
#L1.26, L1.27, L1.28
# Need to make sure that it is reading the audit_rules.txt from the right place
echo -e "\n###### Added by RHEL65_lockdown.sh script ######" >> /etc/audit/audit.rules
cat ~/audit_rules.txt >> /etc/audit/audit.rules

# L2.3
# GRUB password needs to be set manually.  See grub.txt for details.

# L2.4
chmod 0644 /etc/aliases
chmod 0600 /etc/at.deny
chmod 0600 /etc/audit/audit.rules 
chmod 0600 /etc/audit/auditd.conf 
chmod 0444 /etc/bashrc
chmod 0400 /etc/crontab
chmod 0444 /etc/csh.cshrc
chmod 0444 /etc/csh.login
chmod 0600 /etc/cups/client.conf
chmod 0600 /etc/cups/cupsd.conf
chmod 0444 /etc/hosts
chmod 0600 /etc/inittab
chmod 0640 /etc/login.defs
chmod 0444 /etc/networks
chmod 0600 /etc/ntp.conf
chmod 0444 /etc/profile
chmod 0744 /etc/rc.d/init.d/auditd
chmod 0400 /etc/securetty
chmod 0640 /etc/security/access.conf
chmod 0600 /etc/security/console.perms
chmod 0444 /etc/services
chmod 0444 /etc/shells
chmod 0600 /etc/skel/.bashrc
chmod 0600 /etc/sysctl.conf
chmod 0600 /root/.bash_logout
chmod 0400 /root/.bash_profile
chmod 0400 /root/.bashrc
chmod 0400 /root/.cshrc
chmod 0400 /root/.tcshrc
chmod 0600 /var/log/dmesg
chmod 0400 /var/log/lastlog
chmod 0600 /var/log/wtmp

# L2.5
chmod 0750 /etc/cron.d
chmod 0750 /etc/cron.daily
chmod 0750 /etc/cron.hourly
chmod 0750 /etc/cron.monthly
chmod 0750 /etc/cron.weekly
chmod 0750 /etc/security
chmod 0700 /root
chmod 0700 /var/log/audit

#L2.15, L2.16, L2.17
sed -r -i.bak s/umask\ [0-9]{3}/umask\ 027/g /etc/init.d/functions
sed -r -i.bak s/umask\ [0-9]{3}/umask\ 027/g /etc/profile
sed -r -i.bak s/umask\ [0-9]{3}/umask\ 027/g /etc/csh.cshrc
sed -r -i.bak s/umask\ [0-9]{3}/umask\ 027/g /etc/bashrc

#L2.18 L2.19
cp /etc/fstab /etc/fstab.bak
sed -r -i 's:\/boot.*$:& nodev nosuid:g' /etc/fstab
sed -r -i 's:\/home.*$:& nodev nosuid:g' /etc/fstab

#L2.21, L2.22
cp /etc/sysconfig/init /etc/sysconfig/init.bak
sed -i 's/SINGLE=\/sbin\/sushell/SINGLE=\/sbin\/sulogin/' /etc/sysconfig/init
sed -r -i 's/PROMPT=.*/PROMPT=no/' /etc/sysconfig/init

#L3.2
chkconfig acpid off
chkconfig atd off
chkconfig autofs off
chkconfig avahi-daemon off
chkconfig bluetooth off
chkconfig cups off
chkconfig mdmonitor off
chkconfig netfs off
chkconfig nfslock off
chkconfig rhnsd off
chkconfig rpcgssd off

#L3.5
cp /etc/passwd /etc/passwd.bak
sed -i /ftp/d /etc/passwd

#L3.10
echo -e "\n###### Added by RHEL65_lockdown.sh script ######" >> /etc/ssh/sshd_config
cat ~/ssh_config.txt >> /etc/ssh/sshd_config


#L4.1
cp /etc/login.defs /etc/login.defs.bak
sed -r -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 180/' /etc/login.defs
sed -r -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs
sed -r -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 14/' /etc/login.defs
sed -r -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 8/' /etc/login.defs

#L5.1
sed -i.bak '/vc/d' /etc/securetty

#L6.4
sed -i 's:/sbin/shutdown:/sbin/nologin:g' /etc/passwd
sed -i 's:/bin/sync:/sbin/nologin:g' /etc/passwd
sed -i 's:/sbin/halt:/sbin/nologin:g' /etc/passwd

#L8.1, L8.2, L8.3
#Assumes motd.txt is in your home directory
cat ~/motd.txt > /etc/motd
cat ~/motd.txt > /etc/issue
cat ~/motd.txt > /etc/issue.net

#L8.4
# Need to create the directory and file since it doesn't exist by default
mkdir /usr/share/gdm/themes
mkdir /usr/share/gdm/themes/RHEL
cat ~/motd_gui.xml > /usr/share/gdm/themes/RHEL/RHEL.xml

#L11.1, L11.2
echo "root" > /etc/cron.allow
echo "root" > /etc/at.allow
chmod 0400 /etc/cron.allow
chmod 0400 /etc/at.allow


#L11.4
echo -e "\n###### Added by RHEL65_lockdown.sh script ######" >> /etc/security/limits.conf
echo "* soft core 0" >> /etc/security/limits.conf
echo "* hard core 0" >> /etc/security/limits.conf

#L7.3, L7.6, L7.9. L7.10, L7.12, L7.13, L7.14
echo -e "\n###### Added by RHEL65_lockdown.sh script ######" >> /etc/sysctl.conf
cat ~/sysctl.txt >> /etc/sysctl.conf

# GNOME warning banner
echo -e 'zenity --text-info --filename=/etc/motd --width=700 --height=700 --title="LOGIN WARNING"' >> /etc/gdm/Init/Default

# Disable user list on GNOME login

# Edit the /etc/gconf/gconf.xml.defaults/%gconf-tree.xml
# and change the boolean for disable_user_list from false to true. 
