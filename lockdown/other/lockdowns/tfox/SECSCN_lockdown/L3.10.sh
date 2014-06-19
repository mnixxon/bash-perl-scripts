#!/bin/bash
# To resolve SECSCN test L3.10
# Description:
#  Verify SSH Configuration Settings
#
# This sshd_config is meant for server applications

sed -e '/PermitRootLogin/d' /etc/ssh/sshd_config > /tmp/tmp_hard
cp -f /tmp/tmp_hard /etc/ssh/sshd_config
echo "PermitRootLogin no" >> /etc/ssh/sshd_config

######
# Please allow X forwarding from servers 
######
#sed -e '/X11Forwarding/d' /etc/ssh/sshd_config > /tmp/tmp_hard
#cp -f /tmp/tmp_hard /etc/ssh/sshd_config
#echo "X11Forwarding no" >> /etc/ssh/sshd_config 

######
# But don't really do this, it breaks ssh
######

#sed -e '/MaxAuthTries/d' /etc/ssh/sshd_config > /tmp/tmp_hard
#cp -f /tmp/tmp_hard /etc/ssh/s"" >> /etc/ssh/sshd_config 
#echo "MaxAuthTries 1" >> /etc/ssh/sshd_config 

sed -e '/IgnoreRhosts/d' /etc/ssh/sshd_config > /tmp/tmp_hard
cp -f /tmp/tmp_hard /etc/ssh/sshd_config
echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config 

sed -e '/PermitEmptyPasswords/d' /etc/ssh/sshd_config > /tmp/tmp_hard
cp -f /tmp/tmp_hard /etc/ssh/sshd_config
echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config

sed -e '/Banner/d' /etc/ssh/sshd_config > /tmp/tmp_hard
cp -f /tmp/tmp_hard /etc/ssh/sshd_config
echo "Banner /etc/issue" >> /etc/ssh/sshd_config

sed -e '/LogLevel/d' /etc/ssh/sshd_config > /tmp/tmp_hard
cp -f /tmp/tmp_hard /etc/ssh/sshd_config
echo "LogLevel info" >> /etc/ssh/sshd_config

sed -e '/HostbasedAuthentication/d' /etc/ssh/sshd_config > /tmp/tmp_hard
cp -f /tmp/tmp_hard /etc/ssh/sshd_config
echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config

sed -e '/GatewayPorts/d' /etc/ssh/sshd_config > /tmp/tmp_hard
cp -f /tmp/tmp_hard /etc/ssh/sshd_config
echo "GatewayPorts no" >> /etc/ssh/sshd_config

sed -e '/PrintLastLog/d' /etc/ssh/sshd_config > /tmp/tmp_hard
cp -f /tmp/tmp_hard /etc/ssh/sshd_config
echo "PrintLastLog yes" >> /etc/ssh/sshd_config

sed -e '/PermitUserEnvironment/d' /etc/ssh/sshd_config > /tmp/tmp_hard
cp -f /tmp/tmp_hard /etc/ssh/sshd_config
echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config
