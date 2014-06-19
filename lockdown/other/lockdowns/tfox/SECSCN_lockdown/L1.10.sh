#!/bin/bash
# To resolve SECSCN test L1.10
# Description:
#   Verify that audit data is synchronously flushed to disk to avoid data loss
#   Keeps data portion of the disk file sync'd at all times.

sed -e 's/flush = INCREMENTAL/flush = DATA/' /etc/audit/auditd.conf > /tmp/tmp_hard
cp -f /tmp/tmp_hard /etc/audit/auditd.conf
