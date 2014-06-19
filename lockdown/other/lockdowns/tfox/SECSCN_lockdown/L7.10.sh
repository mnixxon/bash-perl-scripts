#!/bin/bash
# To resolve SECSCN test L7.10
# Description:
#		Check the secure_redirects setting. 


/sbin/sysctl net.ipv4.conf.default.secure_redirects=0
