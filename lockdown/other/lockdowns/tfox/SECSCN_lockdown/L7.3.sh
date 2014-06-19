#!/bin/bash
# To resolve SECSCN test L7.3
# Description:
#		Check the rp_filter setting. 


/sbin/sysctl net.ipv4.conf.all.rp_filter=1
