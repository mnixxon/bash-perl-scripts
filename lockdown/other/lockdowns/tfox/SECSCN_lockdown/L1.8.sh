#!/bin/bash
# To resolve SECSCN test L1.8
# Description:
#   Verify that the system is configured to halt on audit failure using the disk_full_action settings in /etc/audit/auditd.conf
#   Places system in single user mode to resolve

sed -e 's/disk_full_action = SUSPEND/disk_full_action = SINGLE/' /etc/audit/auditd.conf > /tmp/tmp_hard
cp -f /tmp/tmp_hard /etc/audit/auditd.conf
