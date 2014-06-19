#!/bin/bash
# To resolve SECSCN test L7.9
# Description:
# 	Check the net.ipv4.conf.default.accept_redirects setting. 


/sbin/sysctl net.ipv4.conf.default.accept_redirects=0
