#!/bin/bash
# To resolve SECSCN test L7.5
# Description:
#	Check the accept_redirects setting. 		


/sbin/sysctl net.ipv4.conf.all.accept_redirects=0
