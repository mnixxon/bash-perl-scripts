#!/bin/bash
# To resolve SECSCN test L7.6
# Description:
# 	Check the secure_redirects setting.


/sbin/sysctl net.ipv4.conf.all.secure_redirects=0
