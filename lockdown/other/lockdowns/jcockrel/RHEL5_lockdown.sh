#!/bin/bash

echo "############################################################"
echo "#                                                          #"
echo "#                   RHEL 5 Lockdown                        #"
echo "#                                                          #"
echo "############################################################"
echo "# Running this lockdown script will disable certain system #"
echo "# functions, services, and directory/file access in an     #"
echo "# attempt to secure this host to meet compliance with DoD  #"
echo "# and project security requirements.                       #"
echo "#                                                          #"
echo "# Do not run this script unless you are knowledgeable of   #"
echo "# the changes that may result as it can render the host    #"
echo "# inaccessible and/or unoperable.                         #"
echo "############################################################"

echo -n "Would you like to continue (y/n)"?
read answer

if [ "$answer" != "y" -a "$answer" != "Y" ]; then
  exit
fi

if [ ! -f ./security_blurb.txt ]; then
  echo "Could not locate necessary file: security_blurb.txt"
  echo "Exiting"
  exit
fi

if [ ! -f ./argon_audit_rules ]; then
  echo "Could not locate necessary file: argon_audit_rules"
  echo "Exiting"
  exit
fi

CP_ALIAS_CHECK=`alias | grep -w cp`
if [ "$CP_ALIAS_CHECK" != "" ]; then
  unalias cp
fi
MV_ALIAS_CHECK=`alias | grep -w mv`
if [ "$MV_ALIAS_CHECK" != "" ]; then
  unalias mv
fi

timestamp=`date +'%Y%m%d%H%M%S'`

#Turn off rhnsd
/sbin/chkconfig rhnsd off

#turn off yum-updatesd
/sbin/chkconfig yum-updatesd off

#Create /etc/vsftpd/ftpusers file
mkdir -p /etc/vsftpd/ftpusers

#remove user ftp from passwd and set several service accounts to /sbin/nologin
FILENAME=/etc/passwd
if [ `ls -1 $FILENAME.hardened.* 2> /dev/null | wc -l` -eq 0 ]; then
  cp -f /etc/passwd /etc/passwd.hardened.$timestamp
  sed -i -e 's/ftp/#ftp/' /etc/passwd
  sed -i -e 's:/bin/sync:/sbin/nologin:' /etc/passwd
  sed -i -e 's:/sbin/shutdown:/sbin/nologin:' /etc/passwd
  sed -i -e 's:/sbin/halt:/sbin/nologin:' /etc/passwd
  sed -i -e 's_/mysql:/bin/bash_/mysql:/sbin/nologin_' /etc/passwd
  sed -i -e 's_/tomcat5:/bin/sh_/tomcat5:/sbin/nologin_' /etc/passwd
  sed -i -e 's_/pgsql:/bin/bash_/pgsql:/sbin/nologin_' /etc/passwd
fi


#edit /etc/securetty for only console and tty0..11
FILENAME=/etc/securetty
if [ `ls -1 $FILENAME.hardened.* 2> /dev/null | wc -l` -eq 0 ]; then
  cp -f /etc/securetty /etc/securetty.hardened.$timestamp
  sudo sed -i -e '/vc/d' /etc/securetty
fi 

# Add nodev Option to Non-Root Local Partitions
FILENAME=/etc/fstab
if [ `ls -1 $FILENAME.hardened.* 2> /dev/null | wc -l` -eq 0 ]; then
  cp -f /etc/fstab /etc/fstab.hardened.$timestamp
  sed -i -e '/ext/s/defaults /defaults,nodev,nosuid/' /etc/fstab 
  sed -i -e '/ \/ /s/defaults,.*/defaults/' /etc/fstab 
fi

#Restrict Console Device Access
FILENAME=/etc/security/console.perms.d/50-default.perms
if [ `ls -1 $FILENAME.hardened.* 2> /dev/null | wc -l` -eq 0 ]; then
  cp /etc/security/console.perms.d/50-default.perms /etc/security/console.perms.d/50-default.perms.hardened.$timestamp
  sed -i -e 's/^<console>/#<console>/g' /etc/security/console.perms.d/50-default.perms
  sed -i -e 's/^<xconsole>/#<xconsole>/g' /etc/security/console.perms.d/50-default.perms
fi

FILENAME=/etc/security/console.perms
if [ `ls -1 $FILENAME.hardened.* 2> /dev/null | wc -l` -eq 0 ]; then
  cp -f /etc/security/console.perms /etc/security/console.perms.hardened.$timestamp
  sed -e '/<console>.*/d' -e '/<xconsole>.*/d' /etc/security/console.perms > /tmp/tmp_hard
  echo "<console>=tty[0-9][0-9]* vc/[0-9][0-9]* :[0-9]\.[0-9] :[0-9]" >> /tmp/tmp_hard
  echo "<xconsole>=:[0-9]\.[0-9] :[0-9]" >> /tmp/tmp_hard
  cp -f /tmp/tmp_hard /etc/security/console.perms
fi

# Move USB Storage Driver
/bin/mv /lib/modules/`uname -r`/kernel/drivers/usb/storage/usb-storage.ko  /lib/modules/`uname -r`/kernel/drivers/usb/storage/usb-storage.ko.orig

# Verify Permissions on passwd, shadow, group and gshadow Files
chown root:root /etc/passwd /etc/shadow /etc/group /etc/gshadow
chmod 644 /etc/passwd /etc/group
chmod 400 /etc/shadow /etc/gshadow

# Verify that All World-Writable Directories Have Sticky Bits Set
echo ""
echo ""
echo "World writable directories.  Verify and change if necessary with:" > /tmp/world_writable.txt
echo "chmod +t <dir>" >> /tmp/world_writable.txt
echo ""  >> /tmp/world_writable.txt
for partition in `grep ext /proc/mounts | awk '{print $2}'`
do
find $partition -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print >> /tmp/world_writable.txt 
done
echo ""  >> /tmp/world_writable.txt
echo ""  >> /tmp/world_writable.txt
# Find Unauthorized World-Writable Files
echo ""
echo ""
echo "World writable files.  Verify and change if necessary with:" >> /tmp/world_writable.txt
echo "chmod o-w <file>" >> /tmp/world_writable.txt
echo ""  >> /tmp/world_writable.txt
for partition in `grep ext /proc/mounts | awk '{print $2}'`
do
find $partition -xdev -type f -perm -0002 -print >> /tmp/world_writable.txt 
done
cat /tmp/world_writable.txt
echo ""
echo ""
echo "Please verify any world writable dirs/files that might be listed above."
echo "Output is is /tmp/world_writeable.txt"
sleep 3

# Find Unauthorized SUID/SGID System Executables
echo "SUID/SGID set on the following files.  Verify and change if necessary with:" >> /tmp/suid_sgid.txt
echo "chmod -s <file>" >> /tmp/suid_sgid.txt
echo ""  >> /tmp/suid_sgid.txt
for partition in `grep ext /proc/mounts | awk '{print $2}'`
do
find $partition -xdev \( -perm -4000 -o -perm -2000 \) -type f -print >> /tmp/suid_sgid.txt
done
cat /tmp/suid_sgid.txt
echo""
echo""
echo "Please verify any SUID/SGID files that might be listed above."
echo "Output is is /tmp/suid_sgid.txt"
sleep 3

# Find and Repair Unowned Files
for partition in `grep ext /proc/mounts | awk '{print $2}'`
do
  find $partition -xdev \( -nouser \) -exec chown root {} \; -print
  find $partition -xdev \( -nogroup \) -exec chgrp root {} \; -print
done

# Disable Core Dumps
FILENAME=/etc/security/limits.conf
if [ `ls -1 $FILENAME.hardened.* 2> /dev/null | wc -l` -eq 0 ]; then
  cp -f /etc/security/limits.conf /etc/security/limits.conf.hardened.$timestamp
  echo "* soft core 0" >> /etc/security/limits.conf
  echo "* hard core 0" >> /etc/security/limits.conf
fi

# Enable ExecShield
FILENAME=/etc/sysctl.conf
if [ `ls -1 $FILENAME.hardened.* 2> /dev/null | wc -l` -eq 0 ]; then
  cp -f /etc/sysctl.conf /etc/sysctl.conf.hardened.$timestamp
  sed -e 's/kernel.exec-shield=0/kernel.exec-shield=1/g' /etc/sysctl.conf > /tmp/tmp_hard
  cp -f /tmp/tmp_hard /etc/sysctl.conf
  sed -e 's/kernel.randomize_va_space=0/kernel.randomize_va_space=1/g' /etc/sysctl.conf > /tmp/tmp_hard
  cp -f /tmp/tmp_hard /etc/sysctl.conf
  #Network Parameters for Hosts Only
  echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
  echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
  echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
  echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
  echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
  echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
  echo "net.ipv4.conf.all.log_martians = 0" >> /etc/sysctl.conf
  echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
  echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
  echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
  echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
fi

#Limit su Access to the Root Account
#FILENAME=/etc/pam.d/su
#if [ `ls -1 $FILENAME.hardened.* 2> /dev/null | wc -l` -eq 0 ]; then
#  cp -f /etc/pam.d/su /etc/pam.d/su.hardened.$timestamp
#  sed '/required/s/#auth/auth/g' /etc/pam.d/su > /tmp/tmp_hard
#  cp -f /tmp/tmp_hard /etc/pam.d/su
#fi

# Configure pam_tally
#FILENAME=/etc/pam.d/system-auth-ac
#if [ `ls -1 $FILENAME.hardened.* 2> /dev/null | wc -l` -eq 0 ]; then
#  cp /etc/pam.d/system-auth-ac /etc/pam.d/system-auth-ac.hardened.$timestamp
#  head -3 /etc/pam.d/system-auth-ac > /tmp/testfile
#  echo "auth        required      pam_tally.so onerr=succeed" >> /tmp/testfile
#  tail -17 /etc/pam.d/system-auth-ac >> /tmp/testfile
#  head -12 /tmp/testfile > /tmp/testfile2
#  echo "account     required      pam_tally.so deny=5">> /tmp/testfile2
#  tail -9 /etc/pam.d/system-auth-ac >> /tmp/testfile2
#  cp /tmp/testfile2 /etc/pam.d/system-auth-ac
#  rm /tmp/testfile
#  rm /tmp/testfile2
#fi


# Verify that No Accounts Have Empty Password Fields
awk -F: '($2 == "") {print}' /etc/shadow > /tmp/empty_passwords.txt
echo ""
echo "Empty Passwords:"
cat /tmp/empty_passwords.txt
echo "Please fix password(s) for the above account(s) if any."
sleep 3

# Verify that No Non-Root Accounts Have UID 0
awk -F: '($3 == "0") {print}' /etc/passwd > /tmp/non_root.txt
cat /tmp/non_root.txt
echo "Only root should have a UID of 0.  If any others are listed above, please fix."
sleep 3

# Set Password Expiration Parameters
FILENAME=/etc/login.defs
if [ `ls -1 $FILENAME.hardened.* 2> /dev/null | wc -l` -eq 0 ]; then
  cp -f /etc/login.defs /etc/login.defs.hardened.$timestamp
  sed -e 's/PASS_MAX_DAYS.*/PASS_MAX_DAYS 180/' \
  -e 's/PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' \
  -e 's/PASS_MIN_LEN.*/PASS_MIN_LEN 8/' \
  -e 's/PASS_WARN_AGE.*/PASS_WARN_AGE 14/' \
  /etc/login.defs > /tmp/tmp_hard
  cp -f /tmp/tmp_hard /etc/login.defs
fi

# Disable Interactive Boot
FILENAME=/etc/sysconfig/init
if [ `ls -1 $FILENAME.hardened.* 2> /dev/null | wc -l` -eq 0 ]; then
  cp -f /etc/sysconfig/init /etc/sysconfig/init.hardened.$timestamp
  sed -e 's/PROMPT=yes/PROMPT=no/' /etc/sysconfig/init > /tmp/tmp_hard
  cp -f /tmp/tmp_hard  /etc/sysconfig/init
fi

# Implement Inactivity Time-out for Login Shells
echo "TMOUT=10800" > /etc/profile.d/tmout.sh
echo "readonly TMOUT" >> /etc/profile.d/tmout.sh
echo "export TMOUT" >> /etc/profile.d/tmout.sh
chown root:root /etc/profile.d/tmout.sh
chmod 755 /etc/profile.d/tmout.sh

# Configure GUI Screen Locking
gconftool-2 --direct \
            --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
            --type bool \
            --set /apps/gnome-screensaver/idle_activation_enabled true
gconftool-2 --direct \
            --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
            --type bool \
            --set /apps/gnome-screensaver/lock_enabled true
gconftool-2 --direct \
            --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
            --type string \
            --set /apps/gnome-screensaver/mode cosmos
gconftool-2 --direct \
            --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
            --type int \
            --set /apps/gnome-screensaver/idle_delay 15

# Modify the System Login Banner
FILENAME=/etc/issue
if [ `ls -1 $FILENAME.hardened.* 2> /dev/null | wc -l` -eq 0 ]; then
  cp -f /etc/issue /etc/issue.hardened.$timestamp
  cat security_blurb.txt >> /etc/issue
fi

FILENAME=/etc/issue.net
if [ `ls -1 $FILENAME.hardened.* 2> /dev/null | wc -l` -eq 0 ]; then
  if [ -f /etc/issue.net ]; then
    cp -f /etc/issue.net /etc/issue.net.hardened.$timestamp
  fi
  cat security_blurb.txt >> /etc/issue.net
fi

FILENAME=/etc/motd
if [ `ls -1 $FILENAME.hardened.* 2> /dev/null | wc -l` -eq 0 ]; then
  if [ -f /etc/motd ]; then
    cp -f /etc/motd /etc/motd.hardened.$timestamp
  fi
  cat security_blurb.txt >> /etc/motd
fi

FILENAME=/etc/gdm/custom.conf
if [ `ls -1 $FILENAME.hardened.* 2> /dev/null | wc -l` -eq 0 ]; then
  cp -f /etc/gdm/custom.conf /etc/gdm/custom.conf.hardened.$timestamp
  sed -e 's/\[greeter\]/\[greeter\]\nInfoMsgFile=\/etc\/issue/' /etc/gdm/custom.conf >> /tmp/tmp_hard
  cp -f /tmp/tmp_hard /etc/gdm/custom.conf
  sed -e 's/\[security\]/\[security\]\nDisallowTCP=true/' /etc/gdm/custom.conf >> /tmp/tmp_hard
  cp -f /tmp/tmp_hard /etc/gdm/custom.conf
fi

# Disable Automatic Loading of IPv6 Kernel Module
#Disable Modprobe Loading of USB Storage Driver 
FILENAME=/etc/modprobe.conf
if [ `ls -1 $FILENAME.hardened.* 2> /dev/null | wc -l` -eq 0 ]; then
  cp -f /etc/modprobe.conf /etc/modprobe.conf.hardened.$timestamp
  echo "install ipv6 /bin/true" >>/etc/modprobe.conf 
  echo "install usb-storage :" >> /etc/modprobe.conf
fi

# Ensure All Important Messages are Captured
FILENAME=/etc/syslog.conf
if [ `ls -1 $FILENAME.hardened.* 2> /dev/null | wc -l` -eq 0 ]; then
  cp -f /etc/syslog.conf /etc/syslog.conf.hardened.$timestamp 
  echo "auth,info.*								/var/log/messages" >> /etc/syslog.conf
  echo "kern.*									/var/log/kern.log" >> /etc/syslog.conf
  echo "daemon.*								/var/log/daemon.log" >> /etc/syslog.conf
  echo "syslog.*								/var/log/syslog" >> /etc/syslog.conf
  echo "lpr,news,uucp,local0,local1,local2,local3,local4,local5,local6.*	/var/log/unused.log" >> /etc/syslog.conf
  if [ ! -f /var/log/kern.log ]; then
     touch /var/log/kern.log
     chown root:root /var/log/kern.log
     chmod 0600 /var/log/kern.log
  fi
  if [ ! -f /var/log/unused.log ]; then
       touch /var/log/unused.log
       chown root:root /var/log/unused.log
       chmod 0600 /var/log/unused.log
  fi
  if [ ! -f /var/log/syslog ]; then
       touch /var/log/syslog
       chown root:root /var/log/syslog
       chmod 0600 /var/log/syslog
  fi
  if [ ! -f /var/log/daemon.log ]; then
       touch /var/log/daemon.log
       chown root:root /var/log/daemon.log
       chmod 0600 /var/log/daemon.log
  fi
fi

# Ensure that the system is configured to set the auditable flag during boot for processes that start prior to the audit daemon
# Ensure that grub.conf is password protected
#FILENAME=/etc/grub.conf
if [ `ls -1 $FILENAME.hardened.* 2> /dev/null | wc -l` -eq 0 ]; then
   cp /etc/grub.conf /etc/grub.conf.hardened.$timestamp
   TEST=`grep "audit=1" /etc/grub.conf`
   if [ "$TEST" == "" ];then
     sed -i -e '/kernel/s/$/ audit=1/' /etc/grub.conf 
   fi
   TEST=`grep "password" /etc/grub.conf`
   if [ "$TEST" == "" ];then
     sed -i -e '/hiddenmenu/apassword --md5 $1$fjqFnDiM$BNdhjOJkDHqB\/oezmo\/rI0' /etc/grub.conf 
   fi
fi

# Enable the auditd Service
FILENAME=/etc/AUD.RULES
if [ `ls -1 $FILENAME.hardened.* 2> /dev/null | wc -l` -eq 0 ]; then
  /sbin/chkconfig auditd off
  cp -f /etc/audit/audit.rules /etc/AUD.RULES.hardened.$timestamp

# Copy in our rules file
  cp -f ./argon_audit_rules /etc/audit/audit.rules

  /sbin/chkconfig auditd on
fi

# Guidance on Default Services
# Turn off services not needed
/sbin/chkconfig acpid off
/sbin/chkconfig anacron off
/sbin/chkconfig atd off
/sbin/chkconfig avahi-daemon off
/sbin/chkconfig bluetooth off
/sbin/chkconfig cpuspeed off
/sbin/chkconfig cups off
/sbin/chkconfig haldaemon off
/sbin/chkconfig firstboot off
/sbin/chkconfig gpm off
/sbin/chkconfig hidd off
/sbin/chkconfig ip6tables off
/sbin/chkconfig iptables off
/sbin/chkconfig irqbalance off
/sbin/chkconfig kdump off
/sbin/chkconfig kudzu off
/sbin/chkconfig lvm2-monitor off
/sbin/chkconfig mcstrans off
/sbin/chkconfig mdmonitor off
/sbin/chkconfig messagebus off
/sbin/chkconfig microcode_ctl off
/sbin/chkconfig netfs off
/sbin/chkconfig pcscd off
/sbin/chkconfig readahead_early off
/sbin/chkconfig readahead_later off
/sbin/chkconfig restorecond off
/sbin/chkconfig rpcgssd off
/sbin/chkconfig rpcidmapd off
/sbin/chkconfig setroubleshoot off
/sbin/chkconfig smartd off
/sbin/chkconfig xfs off
/sbin/chkconfig rlogin off


# Disable Zeroconf Networking
FILENAME=/etc/sysconfig/network
if [ `ls -1 $FILENAME.hardened.* 2> /dev/null | wc -l` -eq 0 ]; then
  cp -f /etc/sysconfig/network /etc/sysconfig/network.hardened.$timestamp
  echo "NOZEROCONF=yes" >> /etc/sysconfig/network
fi

# Restrict Permissions on Files Used by cron
chown root:root /etc/crontab
chmod 600 /etc/crontab
chown root:root /etc/crontab
chmod 600 /etc/crontab
chown -R root:root /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d
chmod -R go-rwx /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d
chown root:root /var/spool/cron
chmod -R go-rwx /var/spool/cron

# Run ntpd using Cron
echo "15 * * * * root /usr/sbin/ntpd -q -u ntp:ntp" > /etc/cron.d/ntpd

# Disable the Listening Sendmail Daemon
FILENAME=/etc/sysconfig/sendmail
if [ `ls -1 $FILENAME.hardened.* 2> /dev/null | wc -l` -eq 0 ]; then
  cp -f /etc/sysconfig/sendmail /etc/sysconfig/sendmail.hardened.$timestamp
  sed -e 's/DAEMON=.*/DAEMON=no/'  /etc/sysconfig/sendmail > /tmp/tmp_hard
  cp -f /tmp/tmp_hard /etc/sysconfig/sendmail 
  chown root.root /var/log/maillog
  chmod 600 /var/log/maillog
fi

#Enable audit daemon
/sbin/chkconfig --level 12345 auditd on
FILENAME=/etc/auditd.conf
if [ `ls -1 $FILENAME.hardened.* 2> /dev/null | wc -l` -eq 0 ]; then
  cp -f /etc/audit/auditd.conf /etc/auditd.conf.hardened.$timestamp
  sed 's/flush = INCREMENTAL/flush = SYNC/' /etc/audit/auditd.conf > /tmp/tmp_hard
  cp -f /tmp/tmp_hard /etc/audit/auditd.conf 
  sed 's/space_left_action = SYSLOG/space_left_action = email/' /etc/audit/auditd.conf > /tmp/tmp_hard
  cp -f /tmp/tmp_hard /etc/audit/auditd.conf 
  sed 's/admin_space_left_action = SUSPEND/admin_space_left_action = email/' /etc/audit/auditd.conf > /tmp/tmp_hard
  cp -f /tmp/tmp_hard /etc/audit/auditd.conf 
  sed 's/SUSPEND/HALT/' /etc/audit/auditd.conf > /tmp/tmp_hard
  cp -f /tmp/tmp_hard /etc/audit/auditd.conf
fi

# Verify file permissions are set correctly
chmod 0444 /etc/bashrc
chmod 0600 /etc/cron.deny
chmod 0400 /etc/crontab
chmod 0444 /etc/csh.cshrc
chmod 0444 /etc/csh.login
chmod 0600 /etc/cups/cupsd.conf
chmod 0444 /etc/hosts
chmod 0444 /etc/hosts.allow
chmod 0444 /etc/hosts.deny
chmod 0000 /etc/hosts.equiv
chmod 0640 /etc/login.defs
chmod 0444 /etc/mail/sendmail.cf
chmod 0444 /etc/mail/submit.cf
chmod 0600 /etc/ntp.conf
chmod 0444 /etc/profile
chmod 0744 /etc/rc.d/init.d/auditd
chmod 0400 /etc/securetty
chmod 0600 /var/log/messages
chmod 0600 /etc/security/console.perms
chmod 0600 /etc/security/console.perms.d/50-default.perms
chmod 0444 /etc/services
chmod 0444 /etc/shells
chmod 0600 /etc/sysctl.conf
chmod 0600 /root/.bash_logout
chmod 0600 /root/.bash_profile
chmod 0600 /root/.bashrc
chmod 0600 /root/.cshrc
chmod 0600 /root/.tcshrc
touch /root/.rhosts
chmod 0000 /root/.rhosts
chmod 0600 /var/log/dmesg
chmod 0400 /var/log/lastlog
chmod 0600 /var/log/scrollkeeper.log
chmod 0600 /var/log/wtmp
chmod 0750 /usr/local
chmod 0700 /var/log/audit
chmod 0755 /etc/security
chmod 0600 /etc/audit/audit.rules
chmod 0600 /etc/audit/auditd.conf
chown lp:sys /etc/cups/client.conf
chmod 0600 /etc/cups/client.conf
chmod 0600 /etc/inittab
chmod 0600 etc/rc.d/rc.local
chmod 0600 /etc/rc.local
chmod 0640 /etc/security/access.conf
chmod 0600 /etc/skel/.bashrc
chmod 0600 /etc/syslog.conf
chmod 0400 /root/.bash_profile
chmod 0400 /root/.bashrc
chmod 0400 /root/.cshrc
chmod 0400 /root/.tcshrc
chown root:root /var/log/wtmp
chmod 0600 /var/log/wtmp
chmod 700 /root
chmod 755 /usr/share/doc
chmod 755 /usr/share/man
chmod 660 /usr/bin/finger
chmod 600 /var/log/wtmp
chmod 644 /etc/fstab
chmod 750 /etc/security
chmod 644 /usr/share/doc/
chmod 644 /usr/share/man/

# Verify directory permissions are set correctly
chmod 0755 /
chmod 0755 /etc
chmod 0755 /etc/rc.d/init.d/
chmod 0755 /opt
if [ -f /var/log/snare ]; then
  chmod 0750 /var/log/snare
fi

# set umask in /etc/profile
FILENAME=/etc/profile
if [ `ls -1 $FILENAME.hardened.* 2> /dev/null | wc -l` -eq 0 ]; then
  cp -f /etc/profile /etc/profile.hardened.$timestamp
  sed -i -e 's/umask .*/umask 027/' /etc/profile 
fi

# set umask in /etc/init.d/functions
FILENAME=/etc/init.d/functions
if [ `ls -1 $FILENAME.hardened.* 2> /dev/null | wc -l` -eq 0 ]; then
  cp -f /etc/init.d/functions /etc/init.d/functions.hardened.$timestamp
  sed -e 's/umask .*/umask 027/' /etc/init.d/functions > /tmp/tmp_hard
  cp -f /tmp/tmp_hard /etc/init.d/functions
fi

# set umask in /etc/csh.cshrc
FILENAME=/etc/csh.cshrc
if [ `ls -1 $FILENAME.hardened.* 2> /dev/null | wc -l` -eq 0 ]; then
  cp -f /etc/csh.cshrc /etc/csh.cshrc.hardened.$timestamp
  sed -e 's/umask .*/umask 027/' /etc/csh.cshrc > /tmp/tmp_hard
  cp -f /tmp/tmp_hard /etc/csh.cshrc
fi

# set umask in /etc/bashrc
FILENAME=/etc/bashrc
if [ `ls -1 $FILENAME.hardened.* 2> /dev/null | wc -l` -eq 0 ]; then
  cp -f /etc/bashrc /etc/bashrc.hardened.$timestamp
  sed -e 's/umask .*/umask 027/' /etc/bashrc > /tmp/tmp_hard 
  cp -f /tmp/tmp_hard /etc/bashrc
fi

# Set umask in /etc/profile
FILENAME=/etc/profile
if [ `ls -1 $FILENAME.hardened.* 2> /dev/null | wc -l` -eq 0 ]; then
  cp -f /etc/profile /etc/profile.hardened.$timestamp
  TEST=`grep "umask 027" /etc/profile`
  if [ "$TEST" == "" ];then
    echo "umask 027" >> /etc/profile
  fi
fi

# Set inittab run-level to 3
# Require Authentication for Single-User Mode (2.3.5.3)
FILENAME=/etc/inittab
if [ `ls -1 $FILENAME.hardened.* 2> /dev/null | wc -l` -eq 0 ]; then
 cp -f /etc/inittab /etc/inittab.hardened.$timestamp
 sed 's/id:5:initdefault:/id:3:initdefault:/' /etc/inittab > /tmp/tmp_hard
 cp -f /tmp/tmp_hard /etc/inittab
 echo "~~:S:wait:/sbin/sulogin" >> /etc/inittab
fi

#Add root to /etc/cron.allow and /etc/at.allow
if [ ! -f /etc/cron.allow ]; then
  echo "root" > /etc/cron.allow
  chmod 400 /etc/cron.allow
fi

if [ ! -f /etc/at.allow ]; then
  echo "root" > /etc/at.allow
  chmod 400 /etc/at.allow
fi

# Setting on /etc/ssh/sshd_config
FILENAME=/etc/ssh/sshd_config
if [ `ls -1 $FILENAME.hardened.* 2> /dev/null | wc -l` -eq 0 ]; then
  cp -f /etc/ssh/sshd_config  /etc/ssh/sshd_config.hardened.$timestamp
  sudo sed -i -e 's/#MaxAuthTries 6/MaxAuthTries 1/' /etc/ssh/sshd_config
  sudo sed -i -e 's/#IgnoreRhosts no/IgnoreRhosts yes/' /etc/ssh/sshd_config
  sudo sed -i -e 's/#LogLevel INFO/LogLevel INFO/' /etc/ssh/sshd_config
  sudo sed -i -e 's/#HostbasedAuthentication no/HostbasedAuthentication yes/' /etc/ssh/sshd_config
  sudo sed -i -e 's/#GatewayPorts no/GatewayPorts no/' /etc/ssh/sshd_config
  sudo sed -i -e 's/#PrintLastLog yes/PrintLastLog yes/' /etc/ssh/sshd_config
  sudo sed -i -e 's/#PermitRootLogin no/PermitRootLogin no/' /etc/ssh/sshd_config
  sudo sed -i -e 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config
  sudo sed -i -e 's/#Banner /some/path/Banner /etc/issue/' /etc/ssh/sshd_config
  sudo sed -i -e 's/#PermitUserEnvironment no/PermitUserEnvironment no/' /etc/ssh/sshd_config
fi

if [ -f /tmp/tmp_hard ]; then
  /bin/rm -f /tmp/tmp_hard
fi
exit
