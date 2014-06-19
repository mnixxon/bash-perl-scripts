#!/bin/bash
# To resolve SECSCN test L1.12
# Description: 
# 	Check that administrators are notified on disk space critical
#

sed -e 's/admin_space_left_action = SUSPEND/admin_space_left_action = email/' /etc/audit/auditd.conf > /tmp/tmp_hard
cp -f /tmp/tmp_hard /etc/audit/auditd.conf 
