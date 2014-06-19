#!/bin/bash
# To resolve SECSCN test L1.9
# Description:
#   Check system action on audit disk error
#   Places system in single user mode to resolve

sed -e  's/disk_error_action = SUSPEND/disk_error_action = SINGLE/' /etc/audit/auditd.conf > /tmp/tmp_hard
cp -f /tmp/tmp_hard /etc/audit/auditd.conf
