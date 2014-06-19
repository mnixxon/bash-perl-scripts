#!/bin/bash
# To resolve SECSCN test L8.1
# Description:
#  Verify appropriate warning banners are in place for xterm launch and login. Also, telnet and ftp banners. 

cp -f security_blurb.txt /etc/motd
cp -f security_blurb.txt /etc/issue
cp -f security_blurb.txt /etc/issue.net
