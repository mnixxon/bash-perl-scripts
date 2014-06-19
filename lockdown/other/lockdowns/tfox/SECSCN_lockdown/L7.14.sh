#!/bin/bash
# To resolve SECSCN test L7.14
# Description:
# Check the send_redirects setting.  

/sbin/sysctl net.ipv4.conf.default.send_redirects=0

