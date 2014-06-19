#!/bin/bash
# To resolve SECSCN test L2.21
# Description:
#   Verify single user mode is password protected.

sed -e '\,:S:wait:/sbin/sulogin,d' /etc/inittab > /tmp/tmp_hard
cp -f /tmp/tmp_hard /etc/inittab 
echo "~~:S:wait:/sbin/sulogin" >> /etc/inittab
