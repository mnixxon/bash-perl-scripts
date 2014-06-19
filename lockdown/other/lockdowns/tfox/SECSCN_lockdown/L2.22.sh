#!/bin/bash
# To resolve SECSCN test L2.22
# Description:
#   Verify interactive boot is disabled.

sed -e 's/PROMPT=yes/PROMPT=no/' /etc/sysconfig/init > /tmp/tmp_hard
cp -f /tmp/tmp_hard /etc/sysconfig/init
