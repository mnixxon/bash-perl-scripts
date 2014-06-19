#!/bin/bash
# To resolve SECSCN test L1.11
# Description: 
# 	Check that administrators are notified on disk space low.
#

sed -e 's/space_left_action = SYSLOG/space_left_action = email/' /etc/audit/auditd.conf > /tmp/tmp_hard
cp -f /tmp/tmp_hard /etc/audit/auditd.conf 
