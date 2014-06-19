#!/bin/bash
# To resolve SECSCN test L1.2 
# Description:
#   Verify audit daemon runs on boot 

/sbin/chkconfig --level 12345 auditd on
