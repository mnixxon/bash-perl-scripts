#!/bin/bash
# To resolve SECSCN test L1.13
# Description: 
# 	Check that administrators are notified on disk full
#
# MANUAL REVIEW	

sed -e 's/action_mail_acct = root/action_mail_acct = sysadmin/' /etc/audit/auditd.conf > /tmp/tmp_hard
cp -f /tmp/tmp_hard /etc/audit/auditd.conf 
