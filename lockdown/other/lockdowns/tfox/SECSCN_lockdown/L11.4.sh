#!/bin/bash
# To resolve SECSCN test L11.4
# Description:
#  Verify core dumps are disabled

TEST=`grep "* soft core 0" /etc/security/limits.conf` 
if [ "$TEST" == "" ]; then
echo "* soft core 0" >> /etc/security/limits.conf
fi

TEST=`grep "* hard core 0" /etc/security/limits.conf`
if [ "$TEST" == "" ]; then
echo "* hard core 0" >> /etc/security/limits.conf 
fi
