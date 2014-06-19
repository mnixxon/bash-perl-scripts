#!/bin/bash
# To resolve SECSCN test L1.14	
# Description: 
# 	Ensure that the system is configured to set the auditable flag during boot for processes that start prior to the audit daemon	
#	
#	Appends "audit=1" to all lines with "kernel" in the grub.conf file

cp /etc/grub.conf /etc/grub.conf.hardened.`date +'%Y%m%d%H%M%S'`
TEST=`grep "audit=1" /etc/grub.conf`
if [ "$TEST" == "" ]; then
	sed -e '/kernel/s/$/ audit=1/' /etc/grub.conf > /tmp/tmp_hard
	cp -f /tmp/tmp_hard /etc/grub.conf
fi

