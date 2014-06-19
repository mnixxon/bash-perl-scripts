#!/bin/bash
# To resolve SECSCN test L2.15
# Description:
#  Verify umask is set properly for root.

sed -e '/umask/d' /root/.bashrc > /tmp/tmp_hard 
cp -f /tmp/tmp_hard /root/.bashrc
echo "umask 027" >> /root/.bashrc
