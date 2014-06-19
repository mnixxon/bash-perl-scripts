#!/bin/bash
# To resolve SECSCN test L2.17
# Description:
#  Ensure users have more secure umask values by checking values defined 
#  in the following files: /etc/profile, /etc/csh.login, /etc/csh.cshrc, 
#  /etc/bashrc, /root/.bash_profile, /root/.bashrc, /root/.cshrc, /root/.tcshrc.

sed -e 's/umask 002/umask 027/' /etc/csh.login > /tmp/tmp_hard 
cp -f /tmp/tmp_hard /etc/csh.login
sed -e 's/umask 022/umask 027/' /etc/csh.login > /tmp/tmp_hard 
cp -f /tmp/tmp_hard /etc/csh.login
sed -e 's/umask 002/umask 027/' /etc/csh.cshrc > /tmp/tmp_hard 
cp -f /tmp/tmp_hard /etc/csh.cshrc
sed -e 's/umask 022/umask 027/' /etc/csh.cshrc > /tmp/tmp_hard 
cp -f /tmp/tmp_hard /etc/csh.cshrc
sed -e 's/umask 002/umask 027/' /etc/bashrc > /tmp/tmp_hard 
cp -f /tmp/tmp_hard /etc/bashrc
sed -e 's/umask 022/umask 027/' /etc/bashrc > /tmp/tmp_hard 
cp -f /tmp/tmp_hard /etc/bashrc
echo "umask 027" >> /etc/profile
sed -e 's/umask 002/umask 027/' /etc/profile > /tmp/tmp_hard 
cp -f /tmp/tmp_hard /etc/profile
sed -e 's/umask 022/umask 027/' /etc/profile > /tmp/tmp_hard 
cp -f /tmp/tmp_hard /etc/profile

