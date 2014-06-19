#!/bin/bash
# To resolve SECSCN test L7.13
# Description:
#  Check the send_redirects setting. 

/sbin/sysctl net.ipv4.conf.all.send_redirects=0

