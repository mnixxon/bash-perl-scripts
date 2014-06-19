#!/bin/bash
#  Resolve tests L1.15 through L1.28 
#  Description:
#  	Adds audit log required by SECSCN and corrects the architcutre for the
#	the system.

ARCH=`uname -a | grep x86_64`
if [ $? = '0' ]; then
	sed -e 's/ARCH/b64/' auditd/audit.rules > /etc/audit/audit.rules
else
	sed -e 's/ARCH/b32/' auditd/audit.rules > /etc/audit/audit.rules
fi

echo "L1.25" >> /etc/audit/audit.rules
echo "Ensure that the system is configured to record execution of privileged commands." >> /etc/audit/audit.rules
find / -xdev  -perm -4000 -o -perm -2000  -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged" }' >> /etc/audit/audit.rules
