#!/bin/bash
# To resolve SECSCN test L2.16
# Description:
#  Verify umask is set properly for root.

sed -e 's/umask 022/umask 027/' /etc/init.d/functions > /tmp/tmp_hard 
cp -f /tmp/tmp_hard /etc/init.d/functions

